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

// Package mistralmoderation is a guardrail policy that checks request and/or response
// text against the Mistral Moderation API (POST /v1/moderations).
package mistralmoderation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// guardrailName identifies this guardrail in GuardrailDetails.InterveningGuardrail.
	guardrailName = "mistral-moderation"
	// envelopeType is the "type" of the JSON error body the policy returns.
	envelopeType = "MISTRAL_MODERATION"
	// envelopeGuardrailName is the interveningGuardrail value in the JSON error body.
	envelopeGuardrailName = "MistralModeration"

	defaultEndpoint = "https://api.mistral.ai"
	defaultModel    = "mistral-moderation-latest"
	defaultTimeout  = 10 * time.Second
	maxTimeout      = 120 * time.Second

	defaultBlockStatusCode = 422
	unavailableStatusCode  = 503

	requestDefaultJSONPath  = "$.messages[-1].content"
	responseDefaultJSONPath = "$.choices[0].message.content"
	// streamingDefaultJSONPath locates the text inside one SSE data frame of an
	// OpenAI-style stream. The non-streaming path addresses a different shape.
	streamingDefaultJSONPath = "$.choices[0].delta.content"

	// defaultStreamingTextUnitChars is how much streamed text is gathered before each
	// moderation call. Smaller means earlier cut-off and more calls.
	defaultStreamingTextUnitChars = 1000
	minStreamingTextUnitChars     = 100

	// defaultMaxContentChars bounds the text sent to the API for one payload.
	defaultMaxContentChars = 100000
	// maxTexts bounds how many separate texts one payload may yield (a wildcard path over
	// a long conversation), and textsPerCall how many go in one API call.
	maxTexts     = 100
	textsPerCall = 20
)

// defaultIgnoredCategories are the Mistral categories that describe subject matter rather
// than harm (medical, financial and legal advice, personal data). Blocking them by default
// would reject ordinary, legitimate prompts, so they are enforced only when the API author
// names them in categoryThresholds.
var defaultIgnoredCategories = []string{"health", "financial", "law", "pii"}

// phaseParams is the parsed, validated configuration of one phase (request or response).
type phaseParams struct {
	jsonPath            string
	path                *jsonPath // jsonPath, compiled when the policy is built
	streamingJSONPath   string
	streamPath          *jsonPath // streamingJSONPath, compiled; nil on the request phase
	streamingUnitChars  int       // 0 = moderate a stream only once, at its end
	maxContentChars     int
	passthroughOnError  bool
	showAssessment      bool
	blockStatusCode     int
	categoryThresholds  map[string]float64
	ignoredCategories   map[string]struct{}
	ignoreOtherCategory bool
}

// MistralModerationPolicy implements the Mistral Moderation guardrail.
//
// The struct is immutable after GetPolicy returns, so one instance is safe to share across
// concurrent requests.
type MistralModerationPolicy struct {
	client   *moderationClient
	request  *phaseParams // nil when the request phase is not configured
	response *phaseParams // nil when the response phase is not configured
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	endpoint, err := parseEndpoint(stringParam(params, "endpoint", defaultEndpoint))
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	apiKey := strings.TrimSpace(stringParam(params, "apiKey", ""))
	if apiKey == "" {
		return nil, fmt.Errorf("invalid params: 'apiKey' is required (set mistral_moderation_api_key in the gateway config)")
	}
	timeout, err := parseTimeout(params["timeout"])
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	p := &MistralModerationPolicy{
		client: &moderationClient{
			endpoint: endpoint,
			apiKey:   apiKey,
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

	if strings.HasPrefix(endpoint, "http://") {
		slog.Warn("MistralModeration: endpoint is plain HTTP; the API key is sent unencrypted", "endpoint", endpoint)
	}
	slog.Debug("MistralModeration: policy initialized",
		"endpoint", endpoint, "model", p.client.model,
		"request", p.request != nil, "response", p.response != nil)
	return p, nil
}

// Mode buffers the request body and streams the response body, each only when its phase is
// configured, so an API that only moderates requests never pays for holding responses.
func (p *MistralModerationPolicy) Mode() policy.ProcessingMode {
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

// OnRequestBody moderates the text found at the request jsonPath.
func (p *MistralModerationPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if p.request == nil {
		return policy.UpstreamRequestModifications{}
	}
	var content []byte
	if reqCtx != nil && reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	if v := p.moderate(ctx, content, p.request, false); v != nil {
		return p.rejectRequest(v)
	}
	return policy.UpstreamRequestModifications{}
}

// OnResponseBody moderates the text found at the response jsonPath. Non-2xx upstream
// responses are passed through: an upstream error body is not model output, and the
// jsonPath would not resolve against it.
func (p *MistralModerationPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
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
		return p.rejectResponse(v)
	}
	return policy.DownstreamResponseModifications{}
}

// ─── Verdict ────────────────────────────────────────────────────────────────

type verdictKind int

const (
	verdictViolation  verdictKind = iota // content crossed a threshold
	verdictBadPayload                    // jsonPath could not be read
	verdictCheckError                    // the moderation call failed
)

// categoryResult is one category's outcome, as reported in the assessment.
type categoryResult struct {
	Name    string  `json:"category"`
	Score   float64 `json:"score"`
	Flagged bool    `json:"flagged"`
}

// verdict describes why a payload is being rejected. A nil *verdict means "let it through".
type verdict struct {
	kind       verdictKind
	isResponse bool
	params     *phaseParams
	violated   []categoryResult // verdictViolation only, highest score first
	err        error            // verdictBadPayload / verdictCheckError
}

// moderate returns nil to allow the payload, or the verdict to reject it with.
func (p *MistralModerationPolicy) moderate(ctx context.Context, payload []byte, params *phaseParams, isResponse bool) *verdict {
	if len(payload) == 0 {
		return nil
	}

	var texts []string
	if isResponse && params.streamPath != nil && looksLikeSSE(string(payload)) {
		// A streamed reply that reached the buffered hook (the engine fell back to buffering
		// the whole body). Read it frame by frame instead of as one JSON document.
		// Frames are token deltas of one reply, so they are joined into a single text.
		texts = []string{strings.Join(sseFrameTexts(string(payload), params.streamPath), "")}
	} else {
		var err error
		texts, err = extractTexts(payload, params.path, params.jsonPath)
		if err != nil {
			if params.passthroughOnError {
				slog.Debug("MistralModeration: jsonPath extraction failed, passing through", "jsonPath", params.jsonPath, "isResponse", isResponse)
				return nil
			}
			return &verdict{kind: verdictBadPayload, isResponse: isResponse, params: params, err: err}
		}
	}
	return p.checkTexts(ctx, texts, params, isResponse)
}

// checkTexts moderates the given texts and returns nil to allow them or the verdict to
// reject them with.
func (p *MistralModerationPolicy) checkTexts(ctx context.Context, texts []string, params *phaseParams, isResponse bool) *verdict {
	texts = nonBlank(texts)
	if len(texts) == 0 {
		return nil
	}
	if err := checkLimits(texts, params.maxContentChars); err != nil {
		slog.Warn("MistralModeration: content over limits", "error", err, "isResponse", isResponse)
		if params.passthroughOnError {
			return nil
		}
		return &verdict{kind: verdictCheckError, isResponse: isResponse, params: params, err: err}
	}

	results, err := p.moderateAll(ctx, texts)
	if err != nil {
		// Only the class of failure is logged; the text being moderated and the API key
		// never appear in logs.
		slog.Warn("MistralModeration: moderation call failed", "error", err, "isResponse", isResponse)
		if params.passthroughOnError {
			return nil
		}
		return &verdict{kind: verdictCheckError, isResponse: isResponse, params: params, err: err}
	}

	violated := mergeViolations(results, params)
	if len(violated) == 0 {
		slog.Debug("MistralModeration: content passed", "texts", len(texts), "isResponse", isResponse)
		return nil
	}
	slog.Debug("MistralModeration: violation detected", "violations", len(violated), "isResponse", isResponse)
	return &verdict{kind: verdictViolation, isResponse: isResponse, params: params, violated: violated}
}

// moderateAll sends the texts to the API in calls of at most textsPerCall, concurrently,
// and returns one result per text in order.
func (p *MistralModerationPolicy) moderateAll(ctx context.Context, texts []string) ([]*moderationResult, error) {
	results := make([]*moderationResult, len(texts))
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	for lo := 0; lo < len(texts); lo += textsPerCall {
		hi := lo + textsPerCall
		if hi > len(texts) {
			hi = len(texts)
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			rs, err := p.client.moderate(ctx, texts[lo:hi])
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			copy(results[lo:hi], rs)
		}(lo, hi)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return results, nil
}

// mergeViolations evaluates every result and keeps, per category, the highest-scoring
// violation, ordered highest score first.
func mergeViolations(results []*moderationResult, params *phaseParams) []categoryResult {
	best := map[string]categoryResult{}
	for _, r := range results {
		for _, v := range evaluate(r, params) {
			if cur, ok := best[v.Name]; !ok || v.Score > cur.Score {
				best[v.Name] = v
			}
		}
	}
	out := make([]categoryResult, 0, len(best))
	for _, v := range best {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func nonBlank(texts []string) []string {
	out := texts[:0:0]
	for _, t := range texts {
		if strings.TrimSpace(t) != "" {
			out = append(out, t)
		}
	}
	return out
}

func checkLimits(texts []string, maxChars int) error {
	if len(texts) > maxTexts {
		return fmt.Errorf("jsonPath yielded %d texts, more than the limit of %d", len(texts), maxTexts)
	}
	total := 0
	for _, t := range texts {
		total += utf8.RuneCountInString(t)
	}
	if total > maxChars {
		return fmt.Errorf("content is %d characters, more than maxContentChars (%d)", total, maxChars)
	}
	return nil
}

// evaluate applies the phase's category rules to an API result and returns the categories
// that should block, highest score first.
//
// Per category, in order:
//  1. an explicit categoryThresholds entry decides: block when score >= threshold, and a
//     threshold of 1 disables the category;
//  2. otherwise the category is skipped when ignoreOtherCategories is set, or when it is in
//     ignoredCategories;
//  3. otherwise Mistral's own calibrated flag decides.
func evaluate(result *moderationResult, params *phaseParams) []categoryResult {
	var violated []categoryResult
	for name, score := range result.Scores {
		key := normalizeCategory(name)
		flagged := result.Flags[name]

		if threshold, ok := params.categoryThresholds[key]; ok {
			if threshold < 1 && score >= threshold {
				violated = append(violated, categoryResult{Name: key, Score: score, Flagged: flagged})
			}
			continue
		}
		if params.ignoreOtherCategory {
			continue
		}
		if _, ignored := params.ignoredCategories[key]; ignored {
			continue
		}
		if flagged {
			violated = append(violated, categoryResult{Name: key, Score: score, Flagged: true})
		}
	}
	// A category reported only as a flag (no score) must still be honoured.
	for name, flagged := range result.Flags {
		if _, hasScore := result.Scores[name]; hasScore || !flagged {
			continue
		}
		key := normalizeCategory(name)
		if _, explicit := params.categoryThresholds[key]; explicit || params.ignoreOtherCategory {
			continue
		}
		if _, ignored := params.ignoredCategories[key]; ignored {
			continue
		}
		violated = append(violated, categoryResult{Name: key, Flagged: true})
	}
	sort.Slice(violated, func(i, j int) bool {
		if violated[i].Score != violated[j].Score {
			return violated[i].Score > violated[j].Score
		}
		return violated[i].Name < violated[j].Name
	})
	return violated
}

// normalizeCategory lower-cases a category name so configuration matches regardless of the
// spelling the API uses.
func normalizeCategory(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ─── Rejections ─────────────────────────────────────────────────────────────

func (p *MistralModerationPolicy) rejectRequest(v *verdict) policy.RequestAction {
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

func (p *MistralModerationPolicy) rejectResponse(v *verdict) policy.ResponseAction {
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
		message["actionReason"] = "Violation of Mistral moderation policy detected."
		if v.params.showAssessment {
			message["assessments"] = map[string]interface{}{"categories": v.violated}
		}
		top := ""
		if len(v.violated) > 0 {
			top = v.violated[0].Name
		}
		guardrail := &policy.GuardrailDetails{
			InterveningGuardrail: guardrailName,
			Action:               policy.GuardrailActionIntervened,
			ActionReason:         "Violation of Mistral moderation policy detected.",
		}
		if v.params.showAssessment {
			guardrail.Assessments = map[string]any{"categories": v.violated}
		}
		fault = &policy.FaultDetails{
			Code:      guardrailCodeFor(top),
			Type:      policy.FaultTypeGuardrail,
			Direction: v.direction(),
			Message:   "Content moderation guardrail intervened",
			// Names the categories only; the moderated text is never copied into a fault.
			Description: "Mistral moderation flagged: " + joinNames(v.violated),
			Guardrail:   guardrail,
		}
	case verdictBadPayload:
		status = v.params.blockStatusCode
		message["action"] = "GUARDRAIL_INTERVENED"
		message["actionReason"] = "Error extracting value from JSONPath"
		if v.params.showAssessment && v.err != nil {
			message["assessments"] = []string{v.err.Error()}
		}
		fault = &policy.FaultDetails{Direction: v.direction(), Description: "Error extracting value from JSONPath: " + errString(v.err)}
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
		message["actionReason"] = "Content moderation service unavailable."
		// The service's error text can name account resources, so it stays in the log only.
		fault = &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeMediation,
			Direction:   v.direction(),
			Message:     "The guardrail check could not be completed",
			Description: "Mistral moderation call failed",
		}
	}

	body, err := json.Marshal(map[string]interface{}{"type": envelopeType, "message": message})
	if err != nil {
		body = []byte(`{"type":"` + envelopeType + `","message":"Internal error"}`)
	}
	return status, body, fault
}

// guardrailCodeFor maps a Mistral category onto the specific guardrail code for it, so a
// caller can branch on the code instead of parsing a message. Matching is by substring
// because 2411 and 2603 name the dangerous/criminal categories differently; anything
// unrecognised reports the content-safety group's generic code.
func guardrailCodeFor(category string) string {
	c := normalizeCategory(category)
	switch {
	case strings.Contains(c, "sexual"):
		return policy.GuardrailCodeSexual
	case strings.Contains(c, "hate"):
		return policy.GuardrailCodeHate
	case strings.Contains(c, "violence"):
		return policy.GuardrailCodeViolence
	case strings.Contains(c, "selfharm"), strings.Contains(c, "self_harm"), strings.Contains(c, "self-harm"):
		return policy.GuardrailCodeSelfHarm
	case strings.Contains(c, "dangerous"), strings.Contains(c, "criminal"):
		return policy.GuardrailCodeDangerousActivity
	case strings.Contains(c, "jailbreak"):
		return policy.GuardrailCodePromptInjection
	case c == "pii":
		return policy.GuardrailCodePII
	default:
		return policy.GuardrailCodeUnsafeContent
	}
}

func joinNames(cs []categoryResult) string {
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, c.Name)
	}
	return strings.Join(names, ", ")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ─── Parameter parsing ──────────────────────────────────────────────────────

func parsePhaseParams(raw map[string]interface{}, isResponse bool) (*phaseParams, error) {
	pp := &phaseParams{
		jsonPath:           requestDefaultJSONPath,
		maxContentChars:    defaultMaxContentChars,
		streamingUnitChars: defaultStreamingTextUnitChars,
		blockStatusCode:    defaultBlockStatusCode,
		categoryThresholds: map[string]float64{},
		ignoredCategories:  toSet(defaultIgnoredCategories),
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
			return nil, fmt.Errorf("'streamingTextUnitChars' must be 0 (moderate the whole stream at its end) or an integer of at least %d", minStreamingTextUnitChars)
		}
		pp.streamingUnitChars = int(n)
	}
	if v, ok := raw["maxContentChars"]; ok {
		n, err := toFloat(v)
		if err != nil || n != float64(int(n)) || n < 1 {
			return nil, fmt.Errorf("'maxContentChars' must be a positive integer")
		}
		pp.maxContentChars = int(n)
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
	var err error
	if pp.passthroughOnError, err = boolParam(raw, "passthroughOnError"); err != nil {
		return nil, err
	}
	if pp.showAssessment, err = boolParam(raw, "showAssessment"); err != nil {
		return nil, err
	}
	if pp.ignoreOtherCategory, err = boolParam(raw, "ignoreOtherCategories"); err != nil {
		return nil, err
	}

	if v, ok := raw["blockStatusCode"]; ok {
		n, err := toFloat(v)
		if err != nil || n != float64(int(n)) || n < 400 || n > 599 {
			return nil, fmt.Errorf("'blockStatusCode' must be an integer between 400 and 599")
		}
		pp.blockStatusCode = int(n)
	}

	if v, ok := raw["categoryThresholds"]; ok && v != nil {
		m, ok := v.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("'categoryThresholds' must be an object")
		}
		for name, tv := range m {
			t, err := toFloat(tv)
			if err != nil || t < 0 || t > 1 {
				return nil, fmt.Errorf("'categoryThresholds.%s' must be a number between 0 and 1", name)
			}
			pp.categoryThresholds[normalizeCategory(name)] = t
		}
	}

	if v, ok := raw["ignoredCategories"]; ok && v != nil {
		list, ok := v.([]interface{})
		if !ok {
			return nil, fmt.Errorf("'ignoredCategories' must be an array of strings")
		}
		pp.ignoredCategories = map[string]struct{}{}
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("'ignoredCategories' must be an array of strings")
			}
			pp.ignoredCategories[normalizeCategory(s)] = struct{}{}
		}
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

func toSet(items []string) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, i := range items {
		s[i] = struct{}{}
	}
	return s
}

// The response phase is streamed when the upstream reply is (see stream.go).
var _ policy.StreamingResponsePolicy = (*MistralModerationPolicy)(nil)
