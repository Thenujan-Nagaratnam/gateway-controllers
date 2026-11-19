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

package mistralmoderation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	moderationPath = "/v1/moderations"
	// maxResponseBytes bounds how much of the API response is read. A moderation result is
	// a few hundred bytes; the ceiling only protects the policy engine from a misbehaving
	// endpoint.
	maxResponseBytes = 1 << 20
	maxAttempts      = 3
	baseBackoff      = 250 * time.Millisecond
	maxBackoff       = 2 * time.Second
)

// moderationClient calls the Mistral Moderation API. It holds no HTTP client of its own:
// the process-wide client built from [policy_engine.http_client] is fetched on every call so
// the operator's pooling, timeout and SSRF settings apply, and so a policy built before the
// engine finishes start-up still works once it has.
type moderationClient struct {
	endpoint string
	apiKey   string
	model    string
	timeout  time.Duration
}

// moderationResult is the part of an API result the policy uses: per-category scores and
// per-category flags (Mistral's own calibrated decision).
type moderationResult struct {
	Scores map[string]float64
	Flags  map[string]bool
}

type moderationRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type moderationResponse struct {
	Results []struct {
		Categories     map[string]bool    `json:"categories"`
		CategoryScores map[string]float64 `json:"category_scores"`
	} `json:"results"`
}

// httpStatusError reports a non-200 API reply. The body is deliberately not included: it
// can echo account details and is not needed to act on the status.
type httpStatusError struct{ status int }

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("Mistral Moderation API returned HTTP %d", e.status)
}

// retryable reports whether a failed attempt is worth repeating: rate limiting, server
// errors and transport errors are; a rejected key or malformed request is not.
func retryable(err error) bool {
	var se *httpStatusError
	if errors.As(err, &se) {
		return se.status == http.StatusTooManyRequests || se.status >= 500
	}
	var te *transportError
	return errors.As(err, &te) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// transportError marks a failure to complete the HTTP exchange (connection reset, DNS,
// timeout of one attempt). Malformed replies are not transport errors and are not retried.
type transportError struct{ err error }

func (e *transportError) Error() string { return "call Mistral Moderation API: " + e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// moderate sends texts to the API in one call and returns one result per text, in order.
// The whole call, retries included, is bounded by the configured timeout.
func (c *moderationClient) moderate(ctx context.Context, texts []string) ([]*moderationResult, error) {
	client := utils.SharedHTTPClient()
	if client == nil {
		return nil, errors.New("shared HTTP client is not available")
	}

	payload, err := json.Marshal(moderationRequest{Model: c.model, Input: texts})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
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
		var results []*moderationResult
		results, lastErr = c.attempt(ctx, client, payload, len(texts))
		if lastErr == nil {
			return results, nil
		}
		if !retryable(lastErr) {
			break
		}
	}
	return nil, lastErr
}

func (c *moderationClient) attempt(ctx context.Context, client *http.Client, payload []byte, want int) ([]*moderationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+moderationPath, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, &transportError{err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Mistral Moderation API response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &retryAfterError{httpStatusError{resp.StatusCode}, parseRetryAfter(resp.Header.Get("Retry-After"))}
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("Mistral Moderation API response exceeds size limit")
	}

	var parsed moderationResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode Mistral Moderation API response: %w", err)
	}
	if len(parsed.Results) != want {
		return nil, fmt.Errorf("Mistral Moderation API returned %d results, expected %d", len(parsed.Results), want)
	}
	out := make([]*moderationResult, len(parsed.Results))
	for i, r := range parsed.Results {
		if r.CategoryScores == nil && r.Categories == nil {
			return nil, errors.New("Mistral Moderation API result has no categories")
		}
		out[i] = &moderationResult{Scores: nonNilScores(r.CategoryScores), Flags: nonNilFlags(r.Categories)}
	}
	return out, nil
}

// retryAfterError is an httpStatusError that also carries the server's Retry-After hint.
type retryAfterError struct {
	httpStatusError
	after time.Duration
}

func (e *retryAfterError) Unwrap() error { return &e.httpStatusError }

// backoffFor returns the wait before retry number attempt (1-based), honouring a
// Retry-After hint but never exceeding maxBackoff so a hostile value cannot stall a request.
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

// parseRetryAfter reads the delta-seconds form of Retry-After; any other form yields 0.
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

func nonNilScores(m map[string]float64) map[string]float64 {
	if m == nil {
		return map[string]float64{}
	}
	return m
}

func nonNilFlags(m map[string]bool) map[string]bool {
	if m == nil {
		return map[string]bool{}
	}
	return m
}
