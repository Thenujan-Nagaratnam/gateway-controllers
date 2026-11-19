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

// Package shieldstral is a guardrail policy that checks request and/or response text
// against rules you write in plain language, using a self-hosted Mistral Shieldstral
// safety classifier.
package shieldstral

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	guardrailName         = "shieldstral"
	envelopeType          = "SHIELDSTRAL"
	envelopeGuardrailName = "Shieldstral"

	defaultModel   = "mistralai/Shieldstral-1.0-3B"
	defaultTimeout = 10 * time.Second
	maxTimeout     = 120 * time.Second

	defaultBlockStatusCode = 422
	unavailableStatusCode  = 503

	requestDefaultJSONPath  = "$.messages[-1].content"
	responseDefaultJSONPath = "$.choices[0].message.content"
	// streamingDefaultJSONPath locates the text inside one SSE data frame of an
	// OpenAI-style stream. The non-streaming path addresses a different shape.
	streamingDefaultJSONPath = "$.choices[0].delta.content"

	// defaultStreamingTextUnitChars is how much streamed text is gathered before each
	// check. Smaller means earlier cut-off and more classifier calls (rules x batches).
	defaultStreamingTextUnitChars = 1000
	minStreamingTextUnitChars     = 100
	// textSeparator joins the separate texts one payload yields into a single document.
	textSeparator = "\n"

	// defaultInstruction is the example instruction from Mistral's reference cookbook.
	defaultInstruction = "You are a strict safety moderator reviewing potentially harmful content. Apply a low tolerance threshold."
	defaultThreshold   = 0.5

	// maxRules bounds the fan-out: every rule is one classifier call per moderated payload.
	maxRules = 10
	// defaultMaxContentChars keeps a payload well inside the model's 32k-token window
	// (the cookbook serves with --max-model-len 32768) with room for the prompt.
	defaultMaxContentChars = 40000
)

var ruleNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// promptTagPattern matches the section markers of the classifier prompt. Moderated content
// is attacker-controlled and is placed inside that prompt, so a literal "<Query>:" in it
// could pose as a new section.
var promptTagPattern = regexp.MustCompile(`(?i)<\s*(instruct|query|document)\s*>\s*:`)

type rule struct {
	name        string
	query       string
	instruction string
	threshold   float64
}

type phaseParams struct {
	jsonPath           string
	path               *jsonPath // jsonPath, compiled when the policy is built
	streamingJSONPath  string
	streamPath         *jsonPath // streamingJSONPath, compiled; nil on the request phase
	streamingUnitChars int       // 0 = check a stream only once, at its end
	instruction        string
	rules              []rule
	maxContentChars    int
	passthroughOnError bool
	showAssessment     bool
	blockStatusCode    int
}

// ShieldstralPolicy implements the Shieldstral guardrail. It is immutable after GetPolicy
// returns, so one instance is safe to share across concurrent requests.
type ShieldstralPolicy struct {
	client   *classifierClient
	request  *phaseParams // nil when the request phase is not configured
	response *phaseParams // nil when the response phase is not configured
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	rawEndpoint := stringParam(params, "endpoint", "")
	if rawEndpoint == "" {
		return nil, fmt.Errorf("invalid params: 'endpoint' is required (set shieldstral_endpoint in the gateway config)")
	}
	endpoint, err := parseEndpoint(rawEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	timeout, err := parseTimeout(params["timeout"])
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	p := &ShieldstralPolicy{
		client: &classifierClient{
			endpoint: endpoint,
			apiKey:   stringParam(params, "apiKey", ""),
			model:    stringParam(params, "model", defaultModel),
			timeout:  timeout,
		},
	}

	if raw, ok := params["request"]; ok && raw != nil {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid request parameters: 'request' must be an object")
		}
		if p.request, err = parsePhaseParams(m, false); err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
	}
	if raw, ok := params["response"]; ok && raw != nil {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid response parameters: 'response' must be an object")
		}
		if p.response, err = parsePhaseParams(m, true); err != nil {
			return nil, fmt.Errorf("invalid response parameters: %w", err)
		}
	}
	if p.request == nil && p.response == nil {
		return nil, fmt.Errorf("at least one of 'request' or 'response' parameters must be provided")
	}

	if strings.HasPrefix(endpoint, "http://") && p.client.apiKey != "" {
		slog.Warn("Shieldstral: endpoint is plain HTTP; the API key is sent unencrypted", "endpoint", endpoint)
	}
	slog.Debug("Shieldstral: policy initialized", "endpoint", endpoint, "model", p.client.model,
		"request", p.request != nil, "response", p.response != nil)
	return p, nil
}

// Mode buffers the request body and streams the response body, each only when its phase is
// configured.
func (p *ShieldstralPolicy) Mode() policy.ProcessingMode {
	mode := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if p.request != nil {
		mode.RequestBodyMode = policy.BodyModeBuffer
	}
	if p.response != nil {
		// STREAM is not a decision to stream: the engine upgrades a route only when the
		// upstream reply is actually chunked or text/event-stream, and calls the buffered
		// OnResponseBody for everything else.
		mode.ResponseBodyMode = policy.BodyModeStream
	}
	return mode
}

// OnRequestBody classifies the text found at the request jsonPath.
func (p *ShieldstralPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if p.request == nil {
		return policy.UpstreamRequestModifications{}
	}
	var content []byte
	if reqCtx != nil && reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	if v := p.moderate(ctx, content, p.request, false); v != nil {
		status, body, fault := v.render()
		return policy.ImmediateResponse{
			StatusCode:        status,
			Headers:           map[string]string{"Content-Type": "application/json"},
			Body:              body,
			IsFault:           true,
			Fault:             fault,
			AnalyticsMetadata: analyticsMetadata(v),
		}
	}
	return policy.UpstreamRequestModifications{}
}

// OnResponseBody classifies the text found at the response jsonPath. Non-2xx upstream
// responses are passed through: an upstream error body is not model output.
func (p *ShieldstralPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if p.response == nil {
		return policy.DownstreamResponseModifications{}
	}
	if respCtx != nil && (respCtx.ResponseStatus < 200 || respCtx.ResponseStatus > 299) {
		return policy.DownstreamResponseModifications{}
	}
	var content []byte
	if respCtx != nil && respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	if v := p.moderate(ctx, content, p.response, true); v != nil {
		status, body, fault := v.render()
		return policy.DownstreamResponseModifications{
			StatusCode:        &status,
			Body:              body,
			HeadersToSet:      map[string]string{"Content-Type": "application/json"},
			IsFault:           true,
			Fault:             fault,
			AnalyticsMetadata: analyticsMetadata(v),
		}
	}
	return policy.DownstreamResponseModifications{}
}

// ─── Verdict ────────────────────────────────────────────────────────────────

type verdictKind int

const (
	verdictViolation  verdictKind = iota // at least one rule crossed its threshold
	verdictBadPayload                    // jsonPath could not be read
	verdictCheckError                    // the classifier could not give an answer
)

// ruleResult is one rule's outcome, as reported in the assessment.
type ruleResult struct {
	Rule      string  `json:"rule"`
	Score     float64 `json:"score"`
	Threshold float64 `json:"threshold"`
	Violated  bool    `json:"violated"`
}

type verdict struct {
	kind       verdictKind
	isResponse bool
	params     *phaseParams
	results    []ruleResult // verdictViolation: every rule that answered, in configured order
	err        error
}

func (v *verdict) violated() []ruleResult {
	var out []ruleResult
	for _, r := range v.results {
		if r.Violated {
			out = append(out, r)
		}
	}
	return out
}

// moderate returns nil to allow the payload, or the verdict to reject it with.
func (p *ShieldstralPolicy) moderate(ctx context.Context, payload []byte, params *phaseParams, isResponse bool) *verdict {
	if len(payload) == 0 {
		return nil
	}

	var texts []string
	if isResponse && params.streamPath != nil && looksLikeSSE(string(payload)) {
		// A streamed reply that reached the buffered hook (the engine fell back to buffering
		// the whole body). Frames are token deltas of one reply, so they are joined.
		texts = []string{strings.Join(sseFrameTexts(string(payload), params.streamPath), "")}
	} else {
		var err error
		texts, err = extractTexts(payload, params.path, params.jsonPath)
		if err != nil {
			if params.passthroughOnError {
				slog.Debug("Shieldstral: jsonPath extraction failed, passing through", "jsonPath", params.jsonPath, "isResponse", isResponse)
				return nil
			}
			return &verdict{kind: verdictBadPayload, isResponse: isResponse, params: params, err: err}
		}
	}
	return p.checkTexts(ctx, texts, params, isResponse)
}

// checkTexts classifies the given texts, joined into one document, against every rule and
// returns nil to allow them or the verdict to reject them with.
func (p *ShieldstralPolicy) checkTexts(ctx context.Context, texts []string, params *phaseParams, isResponse bool) *verdict {
	var kept []string
	for _, t := range texts {
		if strings.TrimSpace(t) != "" {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	text := strings.Join(kept, textSeparator)

	if utf8.RuneCountInString(text) > params.maxContentChars {
		slog.Warn("Shieldstral: content exceeds maxContentChars", "limit", params.maxContentChars, "isResponse", isResponse)
		if params.passthroughOnError {
			return nil
		}
		return &verdict{kind: verdictCheckError, isResponse: isResponse, params: params,
			err: fmt.Errorf("content exceeds maxContentChars (%d)", params.maxContentChars)}
	}
	document := promptTagPattern.ReplaceAllString(text, "[$1]:")

	results, errs := p.runRules(ctx, document, params)
	anyViolated := false
	for _, r := range results {
		if r.Violated {
			anyViolated = true
		}
	}
	// A violation blocks even if another rule's call failed: the content is already known
	// to be unacceptable.
	if anyViolated {
		slog.Debug("Shieldstral: violation detected", "isResponse", isResponse)
		return &verdict{kind: verdictViolation, isResponse: isResponse, params: params, results: results}
	}
	if len(errs) > 0 {
		slog.Warn("Shieldstral: classifier call failed", "error", errs[0], "failedRules", len(errs), "isResponse", isResponse)
		if params.passthroughOnError {
			return nil
		}
		return &verdict{kind: verdictCheckError, isResponse: isResponse, params: params, err: errs[0]}
	}
	slog.Debug("Shieldstral: content passed", "rules", len(results), "isResponse", isResponse)
	return nil
}

// runRules classifies the document against every rule concurrently. It returns the results
// of the rules that answered, in configured order, and the errors of those that did not.
func (p *ShieldstralPolicy) runRules(ctx context.Context, document string, params *phaseParams) ([]ruleResult, []error) {
	type outcome struct {
		res ruleResult
		err error
	}
	outcomes := make([]outcome, len(params.rules))

	var wg sync.WaitGroup
	for i := range params.rules {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := params.rules[i]
			score, err := p.client.score(ctx, r.instruction, r.query, document)
			if err != nil {
				outcomes[i].err = err
				return
			}
			// The decision uses the exact score; only the reported value is rounded.
			outcomes[i].res = ruleResult{Rule: r.name, Score: math.Round(score*1e4) / 1e4, Threshold: r.threshold, Violated: score > r.threshold}
		}(i)
	}
	wg.Wait()

	var results []ruleResult
	var errs []error
	for _, o := range outcomes {
		if o.err != nil {
			errs = append(errs, o.err)
			continue
		}
		results = append(results, o.res)
	}
	return results, errs
}

func analyticsMetadata(v *verdict) map[string]interface{} {
	return map[string]interface{}{
		"isGuardrailHit": v.kind == verdictViolation,
		"guardrailName":  envelopeGuardrailName,
	}
}

func (v *verdict) direction() string {
	if v.isResponse {
		return policy.DirectionResponse
	}
	return policy.DirectionRequest
}

// render builds the HTTP status, JSON body and fault details for the verdict.
func (v *verdict) render() (int, []byte, *policy.FaultDetails) {
	message := map[string]interface{}{
		"interveningGuardrail": envelopeGuardrailName,
		"direction":            strings.ToUpper(v.direction()),
	}

	var (
		status int
		fault  *policy.FaultDetails
	)
	switch v.kind {
	case verdictViolation:
		status = v.params.blockStatusCode
		message["action"] = "GUARDRAIL_INTERVENED"
		message["actionReason"] = "Violation of Shieldstral safety policy detected."
		if v.params.showAssessment {
			message["assessments"] = map[string]interface{}{"rules": v.results}
		}
		names := make([]string, 0)
		for _, r := range v.violated() {
			names = append(names, r.Rule)
		}
		guardrail := &policy.GuardrailDetails{
			InterveningGuardrail: guardrailName,
			Action:               policy.GuardrailActionIntervened,
			ActionReason:         "Violation of Shieldstral safety policy detected.",
		}
		if v.params.showAssessment {
			guardrail.Assessments = map[string]any{"rules": v.results}
		}
		fault = &policy.FaultDetails{
			Code:      policy.GuardrailCodeUnsafeContent,
			Type:      policy.FaultTypeGuardrail,
			Direction: v.direction(),
			Message:   "Content moderation guardrail intervened",
			// Names the rules only; the moderated text is never copied into a fault.
			Description: "Shieldstral rules violated: " + strings.Join(names, ", "),
			Guardrail:   guardrail,
		}
	case verdictBadPayload:
		status = v.params.blockStatusCode
		message["action"] = "GUARDRAIL_INTERVENED"
		message["actionReason"] = "Error extracting value from JSONPath"
		if v.params.showAssessment && v.err != nil {
			message["assessments"] = []string{v.err.Error()}
		}
		fault = &policy.FaultDetails{Direction: v.direction(), Description: "Error extracting value from JSONPath: " + v.err.Error()}
		if v.isResponse {
			fault.Code, fault.Type = policy.FaultCodeMediationFailed, policy.FaultTypeMediation
			fault.Message = "The response body could not be read for the guardrail check"
		} else {
			fault.Code, fault.Type = policy.FaultCodeInvalidRequestBody, policy.FaultTypeValidation
			fault.Message = "The request body could not be read for the guardrail check"
		}
	default: // verdictCheckError
		status = unavailableStatusCode
		message["action"] = "SERVICE_UNAVAILABLE"
		message["actionReason"] = "Content safety service unavailable."
		// The classifier's error text can name infrastructure, so it stays in the log only.
		fault = &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeMediation,
			Direction:   v.direction(),
			Message:     "The guardrail check could not be completed",
			Description: "Shieldstral classification failed",
		}
	}

	body, err := json.Marshal(map[string]interface{}{"type": envelopeType, "message": message})
	if err != nil {
		body = []byte(`{"type":"` + envelopeType + `","message":"Internal error"}`)
	}
	return status, body, fault
}

// ─── Parameter parsing ──────────────────────────────────────────────────────

func parsePhaseParams(raw map[string]interface{}, isResponse bool) (*phaseParams, error) {
	pp := &phaseParams{
		jsonPath:           requestDefaultJSONPath,
		streamingUnitChars: defaultStreamingTextUnitChars,
		instruction:        defaultInstruction,
		maxContentChars:    defaultMaxContentChars,
		blockStatusCode:    defaultBlockStatusCode,
	}
	if isResponse {
		pp.jsonPath = responseDefaultJSONPath
		pp.streamingJSONPath = streamingDefaultJSONPath
	}

	if v, ok := raw["jsonPath"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("'jsonPath' must be a string")
		}
		pp.jsonPath = s
	}
	if v, ok := raw["streamingJsonPath"]; ok {
		if !isResponse {
			return nil, fmt.Errorf("'streamingJsonPath' applies to the response phase only")
		}
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("'streamingJsonPath' must be a non-empty string")
		}
		pp.streamingJSONPath = s
	}
	if v, ok := raw["streamingTextUnitChars"]; ok {
		if !isResponse {
			return nil, fmt.Errorf("'streamingTextUnitChars' applies to the response phase only")
		}
		n, err := toFloat(v)
		if err != nil || n != float64(int(n)) || (n != 0 && n < minStreamingTextUnitChars) {
			return nil, fmt.Errorf("'streamingTextUnitChars' must be 0 (check the whole stream at its end) or an integer of at least %d", minStreamingTextUnitChars)
		}
		pp.streamingUnitChars = int(n)
	}
	if pp.jsonPath != "" {
		jp, err := compileJSONPath(pp.jsonPath)
		if err != nil {
			return nil, err
		}
		pp.path = jp
	}
	if isResponse {
		sp, err := compileJSONPath(pp.streamingJSONPath)
		if err != nil {
			return nil, err
		}
		pp.streamPath = sp
	}
	if v, ok := raw["instruction"]; ok {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("'instruction' must be a non-empty string")
		}
		pp.instruction = s
	}
	var err error
	if pp.passthroughOnError, err = boolParam(raw, "passthroughOnError"); err != nil {
		return nil, err
	}
	if pp.showAssessment, err = boolParam(raw, "showAssessment"); err != nil {
		return nil, err
	}
	if v, ok := raw["blockStatusCode"]; ok {
		n, err := toFloat(v)
		if err != nil || n != float64(int(n)) || n < 400 || n > 599 {
			return nil, fmt.Errorf("'blockStatusCode' must be an integer between 400 and 599")
		}
		pp.blockStatusCode = int(n)
	}
	if v, ok := raw["maxContentChars"]; ok {
		n, err := toFloat(v)
		if err != nil || n != float64(int(n)) || n < 1 {
			return nil, fmt.Errorf("'maxContentChars' must be a positive integer")
		}
		pp.maxContentChars = int(n)
	}

	rulesRaw, ok := raw["rules"].([]interface{})
	if !ok || len(rulesRaw) == 0 {
		return nil, fmt.Errorf("'rules' must be a non-empty array")
	}
	if len(rulesRaw) > maxRules {
		return nil, fmt.Errorf("'rules' may hold at most %d entries, got %d", maxRules, len(rulesRaw))
	}
	seen := map[string]struct{}{}
	for i, item := range rulesRaw {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("'rules[%d]' must be an object", i)
		}
		r := rule{instruction: pp.instruction, threshold: defaultThreshold}
		if r.name, _ = m["name"].(string); !ruleNamePattern.MatchString(r.name) {
			return nil, fmt.Errorf("'rules[%d].name' must match %s", i, ruleNamePattern)
		}
		if _, dup := seen[r.name]; dup {
			return nil, fmt.Errorf("'rules[%d].name' %q is duplicated", i, r.name)
		}
		seen[r.name] = struct{}{}
		if r.query, _ = m["query"].(string); strings.TrimSpace(r.query) == "" {
			return nil, fmt.Errorf("'rules[%d].query' must be a non-empty string", i)
		}
		if v, ok := m["instruction"]; ok {
			s, ok := v.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return nil, fmt.Errorf("'rules[%d].instruction' must be a non-empty string", i)
			}
			r.instruction = s
		}
		if v, ok := m["threshold"]; ok {
			t, err := toFloat(v)
			if err != nil || t < 0 || t > 1 {
				return nil, fmt.Errorf("'rules[%d].threshold' must be a number between 0 and 1", i)
			}
			r.threshold = t
		}
		pp.rules = append(pp.rules, r)
	}
	return pp, nil
}

func parseEndpoint(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("'endpoint' must be an http(s) URL, got %q", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("'endpoint' must not contain credentials")
	}
	return raw, nil
}

func parseTimeout(v interface{}) (time.Duration, error) {
	if v == nil {
		return defaultTimeout, nil
	}
	n, err := toFloat(v)
	if err != nil || n < 1 || n > maxTimeout.Seconds() {
		return 0, fmt.Errorf("'timeout' must be a number of seconds between 1 and %d", int(maxTimeout.Seconds()))
	}
	return time.Duration(n * float64(time.Second)), nil
}

func stringParam(params map[string]interface{}, key, fallback string) string {
	if s, ok := params[key].(string); ok && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	return fallback
}

func boolParam(m map[string]interface{}, key string) (bool, error) {
	v, ok := m[key]
	if !ok {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("'%s' must be a boolean", key)
	}
	return b, nil
}

func toFloat(v interface{}) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case json.Number:
		return n.Float64()
	default:
		return 0, fmt.Errorf("cannot convert %T to a number", v)
	}
}

// The response phase is streamed when the upstream reply is (see stream.go).
var _ policy.StreamingResponsePolicy = (*ShieldstralPolicy)(nil)
