/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package shieldstral

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	chatCompletionsPath = "/v1/chat/completions"
	// maxResponseBytes bounds how much of the classifier reply is read. With max_tokens=1
	// and 20 top logprobs the reply is a few kilobytes.
	maxResponseBytes = 1 << 20
	maxAttempts      = 2
	baseBackoff      = 200 * time.Millisecond
	maxBackoff       = 2 * time.Second

	// systemPrompt is the fixed system message Shieldstral was trained with, copied from
	// Mistral's reference cookbook. It must not be reworded.
	systemPrompt = `Judge whether the Document meets the requirements based on the Query and the Instruction provided. Note that the answer can only be "yes" or "no".`

	// missingLogprob is the value the reference implementation assigns a yes/no token that
	// is absent from the top logprobs.
	missingLogprob = -10.0
)

var (
	yesTokens = map[string]struct{}{"yes": {}, "yes.": {}, `"yes"`: {}, "'yes'": {}}
	noTokens  = map[string]struct{}{"no": {}, "no.": {}, `"no"`: {}, "'no'": {}}
)

// classifierClient calls a self-hosted Shieldstral model behind an OpenAI-compatible
// /v1/chat/completions endpoint (vLLM). The process-wide HTTP client is fetched on every
// call so the operator's pooling, timeout and SSRF settings apply.
type classifierClient struct {
	endpoint string
	apiKey   string // optional; empty means no Authorization header
	model    string
	timeout  time.Duration
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
	Logprobs    bool          `json:"logprobs"`
	TopLogprobs int           `json:"top_logprobs"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Logprobs *struct {
			Content []struct {
				TopLogprobs []struct {
					Token   string  `json:"token"`
					Logprob float64 `json:"logprob"`
				} `json:"top_logprobs"`
			} `json:"content"`
		} `json:"logprobs"`
	} `json:"choices"`
}

// buildMessages assembles the exact message layout Shieldstral expects.
func buildMessages(instruct, query, document string) []chatMessage {
	user := "<Instruct>: " + instruct + "\n\n<Query>: " + query + "\n\n<Document>: " + document
	return []chatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: user},
	}
}

// score asks the model whether document violates the rule and returns the probability of
// "yes" (a violation), in [0,1].
func (c *classifierClient) score(ctx context.Context, instruct, query, document string) (float64, error) {
	client := utils.SharedHTTPClient()
	if client == nil {
		return 0, errors.New("shared HTTP client is not available")
	}
	payload, err := json.Marshal(chatRequest{
		Model:       c.model,
		Messages:    buildMessages(instruct, query, document),
		MaxTokens:   1,
		Temperature: 0,
		Logprobs:    true,
		TopLogprobs: 20,
	})
	if err != nil {
		return 0, fmt.Errorf("marshal request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, backoffFor(attempt, lastErr)); err != nil {
				break
			}
		}
		var s float64
		s, lastErr = c.attempt(ctx, client, payload)
		if lastErr == nil {
			return s, nil
		}
		if !retryable(lastErr) {
			break
		}
	}
	return 0, lastErr
}

func (c *classifierClient) attempt(ctx context.Context, client *http.Client, payload []byte) (float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+chatCompletionsPath, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, &transportError{err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, &transportError{err}
	}
	if resp.StatusCode != http.StatusOK {
		return 0, &retryAfterError{httpStatusError{resp.StatusCode}, parseRetryAfter(resp.Header.Get("Retry-After"))}
	}
	if len(body) > maxResponseBytes {
		return 0, errors.New("Shieldstral response exceeds size limit")
	}
	return parseScore(body)
}

// parseScore turns a chat-completions reply into P(yes), following the reference
// implementation: take the best logprob among the yes variants and among the no variants
// in the first generated token's top logprobs, then normalise. A side that is absent counts
// as -10. If neither side appears the model did not answer yes/no, which is an error and
// not a verdict.
func parseScore(body []byte) (float64, error) {
	var parsed chatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, fmt.Errorf("decode Shieldstral response: %w", err)
	}
	if len(parsed.Choices) == 0 || parsed.Choices[0].Logprobs == nil || len(parsed.Choices[0].Logprobs.Content) == 0 {
		return 0, errors.New("Shieldstral response carries no logprobs (is the server ignoring logprobs?)")
	}
	top := parsed.Choices[0].Logprobs.Content[0].TopLogprobs

	zYes, zNo := math.Inf(-1), math.Inf(-1)
	for _, t := range top {
		tok := strings.ToLower(strings.TrimSpace(t.Token))
		if _, ok := yesTokens[tok]; ok {
			zYes = math.Max(zYes, t.Logprob)
		} else if _, ok := noTokens[tok]; ok {
			zNo = math.Max(zNo, t.Logprob)
		}
	}
	foundYes, foundNo := !math.IsInf(zYes, -1), !math.IsInf(zNo, -1)
	if !foundYes && !foundNo {
		return 0, errors.New("Shieldstral did not answer yes or no")
	}
	// Unlike the reference implementation, which floors both sides at -10 and so reports
	// exactly 0.5 whenever both logprobs are below -10, a side that is present keeps its
	// real value; only an absent side takes the -10 placeholder.
	if !foundYes {
		zYes = missingLogprob
	}
	if !foundNo {
		zNo = missingLogprob
	}
	// Subtract the larger logprob before exponentiating so very negative values cannot
	// underflow both terms to zero.
	m := math.Max(zYes, zNo)
	eYes, eNo := math.Exp(zYes-m), math.Exp(zNo-m)
	return eYes / (eYes + eNo), nil
}

// httpStatusError reports a non-200 reply. The body is deliberately not included: it can
// echo infrastructure details and is not needed to act on the status.
type httpStatusError struct{ status int }

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("Shieldstral endpoint returned HTTP %d", e.status)
}

// retryAfterError is an httpStatusError that also carries the server's Retry-After hint.
type retryAfterError struct {
	httpStatusError
	after time.Duration
}

func (e *retryAfterError) Unwrap() error { return &e.httpStatusError }

// transportError marks a failure to complete the HTTP exchange. Malformed replies are not
// transport errors and are not retried.
type transportError struct{ err error }

func (e *transportError) Error() string { return "call Shieldstral endpoint: " + e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// retryable reports whether a failed attempt is worth repeating: overload, server errors
// and transport errors are; a rejected key, a bad request or a malformed reply are not.
func retryable(err error) bool {
	var se *httpStatusError
	if errors.As(err, &se) {
		return se.status == http.StatusTooManyRequests || se.status >= 500
	}
	var te *transportError
	return errors.As(err, &te) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// backoffFor returns the wait before retry number attempt (1-based), honouring Retry-After
// but never exceeding maxBackoff.
func backoffFor(attempt int, last error) time.Duration {
	d := baseBackoff << (attempt - 1)
	var ra *retryAfterError
	if errors.As(last, &ra) && ra.after > d {
		d = ra.after
	}
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

func parseRetryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
