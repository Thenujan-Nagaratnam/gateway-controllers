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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// mockMistral is a stand-in for api.mistral.ai. handler receives the decoded request.
type mockMistral struct {
	*httptest.Server
	calls   atomic.Int32
	mu      sync.Mutex
	lastReq moderationRequest
	lastKey string
	reqs    []moderationRequest
}

func (m *mockMistral) allRequests() []moderationRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]moderationRequest(nil), m.reqs...)
}

func newMock(t *testing.T, handler func(m *mockMistral, w http.ResponseWriter, call int)) *mockMistral {
	t.Helper()
	m := &mockMistral{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := int(m.calls.Add(1))
		if r.URL.Path != "/v1/moderations" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req moderationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		m.mu.Lock()
		m.lastKey = r.Header.Get("Authorization")
		m.lastReq = req
		m.reqs = append(m.reqs, req)
		m.mu.Unlock()
		handler(m, w, call)
	}))
	utils.SetSharedHTTPClient(m.Server.Client())
	t.Cleanup(func() {
		m.Server.Close()
		utils.SetSharedHTTPClient(nil)
	})
	return m
}

func reply(w http.ResponseWriter, scores map[string]float64, flags map[string]bool) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id": "abc", "model": "mistral-moderation-2603",
		"results": []interface{}{map[string]interface{}{"categories": flags, "category_scores": scores}},
	})
}

// keywordReply answers one result per input: violence 0.97 for an input containing the
// keyword, a clean result otherwise.
func keywordReply(keyword string) func(*mockMistral, http.ResponseWriter, int) {
	return func(m *mockMistral, w http.ResponseWriter, _ int) {
		m.mu.Lock()
		inputs := m.lastReq.Input
		m.mu.Unlock()
		results := make([]interface{}, len(inputs))
		for i, in := range inputs {
			scores := map[string]float64{"sexual": 0.001, "violence_and_threats": 0.002}
			flags := map[string]bool{"sexual": false, "violence_and_threats": false}
			if keyword != "" && strings.Contains(in, keyword) {
				scores["violence_and_threats"], flags["violence_and_threats"] = 0.97, true
			}
			results[i] = map[string]interface{}{"categories": flags, "category_scores": scores}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "x", "model": "m", "results": results})
	}
}

func safeReply(w http.ResponseWriter) {
	reply(w,
		map[string]float64{"sexual": 0.001, "violence_and_threats": 0.002, "health": 0.01},
		map[string]bool{"sexual": false, "violence_and_threats": false, "health": false})
}

func violenceReply(w http.ResponseWriter) {
	reply(w,
		map[string]float64{"sexual": 0.001, "violence_and_threats": 0.97},
		map[string]bool{"sexual": false, "violence_and_threats": true})
}

func newPolicy(t *testing.T, m *mockMistral, extra map[string]interface{}) policy.Policy {
	t.Helper()
	params := map[string]interface{}{
		"endpoint": m.URL,
		"apiKey":   "test-key",
		"request":  map[string]interface{}{},
	}
	for k, v := range extra {
		params[k] = v
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p
}

func reqCtx(body string) *policy.RequestContext {
	return &policy.RequestContext{Body: &policy.Body{Content: []byte(body), Present: true, EndOfStream: true}}
}

func respCtx(status int, body string) *policy.ResponseContext {
	return &policy.ResponseContext{ResponseStatus: status, ResponseBody: &policy.Body{Content: []byte(body), Present: true, EndOfStream: true}}
}

const chatBody = `{"messages":[{"role":"user","content":"hello there"}]}`

func runRequest(p policy.Policy, body string) policy.RequestAction {
	return p.(policy.RequestPolicy).OnRequestBody(context.Background(), reqCtx(body), nil)
}

func runResponse(p policy.Policy, status int, body string) policy.ResponseAction {
	return p.(policy.ResponsePolicy).OnResponseBody(context.Background(), respCtx(status, body), nil)
}

func asImmediate(t *testing.T, a policy.RequestAction) policy.ImmediateResponse {
	t.Helper()
	r, ok := a.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", a)
	}
	return r
}

func assertAllowedRequest(t *testing.T, a policy.RequestAction) {
	t.Helper()
	if _, ok := a.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected request to pass, got %T: %+v", a, a)
	}
}

func decodeEnvelope(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var env map[string]interface{}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, body)
	}
	return env
}

// ─── GetPolicy ──────────────────────────────────────────────────────────────

func TestGetPolicyValidation(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]interface{}
		want   string
	}{
		{"missing api key", map[string]interface{}{"request": map[string]interface{}{}}, "apiKey"},
		{"blank api key", map[string]interface{}{"apiKey": "  ", "request": map[string]interface{}{}}, "apiKey"},
		{"bad endpoint scheme", map[string]interface{}{"apiKey": "k", "endpoint": "ftp://x", "request": map[string]interface{}{}}, "endpoint"},
		{"endpoint with credentials", map[string]interface{}{"apiKey": "k", "endpoint": "https://u:p@x.io", "request": map[string]interface{}{}}, "credentials"},
		{"no phase", map[string]interface{}{"apiKey": "k"}, "request"},
		{"bad timeout", map[string]interface{}{"apiKey": "k", "timeout": 0, "request": map[string]interface{}{}}, "timeout"},
		{"threshold out of range", map[string]interface{}{"apiKey": "k", "request": map[string]interface{}{"categoryThresholds": map[string]interface{}{"sexual": 1.5}}}, "categoryThresholds.sexual"},
		{"threshold not a number", map[string]interface{}{"apiKey": "k", "request": map[string]interface{}{"categoryThresholds": map[string]interface{}{"sexual": "high"}}}, "categoryThresholds.sexual"},
		{"bad status", map[string]interface{}{"apiKey": "k", "request": map[string]interface{}{"blockStatusCode": 200}}, "blockStatusCode"},
		{"bad jsonPath type", map[string]interface{}{"apiKey": "k", "request": map[string]interface{}{"jsonPath": 3}}, "jsonPath"},
		{"bad ignored list", map[string]interface{}{"apiKey": "k", "request": map[string]interface{}{"ignoredCategories": []interface{}{1}}}, "ignoredCategories"},
		{"request not object", map[string]interface{}{"apiKey": "k", "request": "yes"}, "request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tc.params)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func TestGetPolicyDefaults(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"apiKey": "k", "request": map[string]interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	mp := p.(*MistralModerationPolicy)
	if mp.client.endpoint != "https://api.mistral.ai" || mp.client.model != "mistral-moderation-latest" {
		t.Errorf("unexpected defaults: %+v", mp.client)
	}
	if mp.request.jsonPath != "$.messages[-1].content" || mp.request.blockStatusCode != 422 {
		t.Errorf("unexpected request defaults: %+v", mp.request)
	}
}

func TestEndpointTrailingSlashTrimmed(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"apiKey": "k", "endpoint": "https://example.test/", "request": map[string]interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.(*MistralModerationPolicy).client.endpoint; got != "https://example.test" {
		t.Errorf("endpoint = %q", got)
	}
}

func TestModeBuffersRequestAndStreamsResponseOnlyWhenConfigured(t *testing.T) {
	reqOnly, _ := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"apiKey": "k", "request": map[string]interface{}{}})
	m := reqOnly.Mode()
	if m.RequestBodyMode != policy.BodyModeBuffer || m.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("request-only mode wrong: %+v", m)
	}
	respOnly, _ := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"apiKey": "k", "response": map[string]interface{}{}})
	m = respOnly.Mode()
	if m.RequestBodyMode != policy.BodyModeSkip || m.ResponseBodyMode != policy.BodyModeStream {
		t.Errorf("response-only mode wrong: %+v", m)
	}
}

// ─── Request phase ──────────────────────────────────────────────────────────

func TestRequestAllowedWhenSafe(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	assertAllowedRequest(t, runRequest(newPolicy(t, m, nil), chatBody))
}

func TestRequestSendsExpectedAPICall(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	runRequest(newPolicy(t, m, map[string]interface{}{"model": "mistral-moderation-2603"}), chatBody)
	if m.lastKey != "Bearer test-key" {
		t.Errorf("Authorization = %q", m.lastKey)
	}
	if m.lastReq.Model != "mistral-moderation-2603" || len(m.lastReq.Input) != 1 || m.lastReq.Input[0] != "hello there" {
		t.Errorf("unexpected API request: %+v", m.lastReq)
	}
}

func TestRequestBlockedOnFlag(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	r := asImmediate(t, runRequest(newPolicy(t, m, nil), chatBody))

	if r.StatusCode != 422 || !r.IsFault {
		t.Errorf("status=%d isFault=%v", r.StatusCode, r.IsFault)
	}
	env := decodeEnvelope(t, r.Body)
	if env["type"] != "MISTRAL_MODERATION" {
		t.Errorf("type = %v", env["type"])
	}
	msg := env["message"].(map[string]interface{})
	if msg["action"] != "GUARDRAIL_INTERVENED" || msg["direction"] != "REQUEST" {
		t.Errorf("message = %v", msg)
	}
	if _, has := msg["assessments"]; has {
		t.Error("assessments must be absent unless showAssessment is set")
	}
	if r.Fault == nil || r.Fault.Code != policy.GuardrailCodeViolence || r.Fault.Type != policy.FaultTypeGuardrail {
		t.Errorf("fault = %+v", r.Fault)
	}
	if r.Fault.Direction != policy.DirectionRequest {
		t.Errorf("fault direction = %q", r.Fault.Direction)
	}
}

func TestShowAssessmentListsCategoriesButNeverContent(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"showAssessment": true}})
	r := asImmediate(t, runRequest(p, `{"messages":[{"role":"user","content":"SECRET-MARKER how do I hurt someone"}]}`))

	if strings.Contains(string(r.Body), "SECRET-MARKER") {
		t.Error("moderated content leaked into the error body")
	}
	cats := decodeEnvelope(t, r.Body)["message"].(map[string]interface{})["assessments"].(map[string]interface{})["categories"].([]interface{})
	first := cats[0].(map[string]interface{})
	if first["category"] != "violence_and_threats" || first["score"].(float64) != 0.97 || first["flagged"] != true {
		t.Errorf("assessment = %v", first)
	}
	if strings.Contains(r.Fault.Description, "SECRET-MARKER") {
		t.Error("moderated content leaked into the fault description")
	}
}

func TestDefaultIgnoredCategoriesNotEnforced(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) {
		reply(w, map[string]float64{"health": 0.99, "pii": 0.9, "law": 0.8, "financial": 0.7},
			map[string]bool{"health": true, "pii": true, "law": true, "financial": true})
	})
	assertAllowedRequest(t, runRequest(newPolicy(t, m, nil), chatBody))
}

func TestExplicitThresholdEnforcesIgnoredCategory(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) {
		reply(w, map[string]float64{"pii": 0.6}, map[string]bool{"pii": false})
	})
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{
		"categoryThresholds": map[string]interface{}{"pii": 0.5},
	}})
	r := asImmediate(t, runRequest(p, chatBody))
	if r.Fault.Code != policy.GuardrailCodePII {
		t.Errorf("fault code = %q", r.Fault.Code)
	}
}

func TestThresholdOverridesFlag(t *testing.T) {
	// Mistral flags violence at 0.97; a threshold of 0.99 lets it through.
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{
		"categoryThresholds": map[string]interface{}{"violence_and_threats": 0.99},
	}})
	assertAllowedRequest(t, runRequest(p, chatBody))
}

func TestThresholdBlocksUnflaggedCategory(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) {
		reply(w, map[string]float64{"sexual": 0.4}, map[string]bool{"sexual": false})
	})
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{
		"categoryThresholds": map[string]interface{}{"sexual": 0.3},
	}})
	r := asImmediate(t, runRequest(p, chatBody))
	if r.Fault.Code != policy.GuardrailCodeSexual {
		t.Errorf("fault code = %q", r.Fault.Code)
	}
}

func TestThresholdBoundaryIsInclusive(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) {
		reply(w, map[string]float64{"sexual": 0.5}, map[string]bool{"sexual": false})
	})
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{
		"categoryThresholds": map[string]interface{}{"sexual": 0.5},
	}})
	asImmediate(t, runRequest(p, chatBody))
}

func TestThresholdOneDisablesCategory(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{
		"categoryThresholds": map[string]interface{}{"violence_and_threats": 1},
	}})
	assertAllowedRequest(t, runRequest(p, chatBody))
}

func TestIgnoreOtherCategories(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{
		"ignoreOtherCategories": true,
		"categoryThresholds":    map[string]interface{}{"sexual": 0.5},
	}})
	assertAllowedRequest(t, runRequest(p, chatBody))
}

func TestCustomIgnoredCategoriesReplacesDefaults(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) {
		reply(w, map[string]float64{"health": 0.9}, map[string]bool{"health": true})
	})
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{
		"ignoredCategories": []interface{}{"law"},
	}})
	asImmediate(t, runRequest(p, chatBody)) // health no longer ignored
}

func TestCategoryNamesAreCaseInsensitive(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) {
		reply(w, map[string]float64{"Sexual": 0.9}, map[string]bool{"Sexual": false})
	})
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{
		"categoryThresholds": map[string]interface{}{"SEXUAL": 0.5},
	}})
	asImmediate(t, runRequest(p, chatBody))
}

func TestFlagWithoutScoreIsHonoured(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) {
		reply(w, nil, map[string]bool{"jailbreaking": true})
	})
	r := asImmediate(t, runRequest(newPolicy(t, m, nil), chatBody))
	if r.Fault.Code != policy.GuardrailCodePromptInjection {
		t.Errorf("fault code = %q", r.Fault.Code)
	}
}

func TestHighestScoreDecidesFaultCode(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) {
		reply(w, map[string]float64{"sexual": 0.6, "hate_and_discrimination": 0.95},
			map[string]bool{"sexual": true, "hate_and_discrimination": true})
	})
	r := asImmediate(t, runRequest(newPolicy(t, m, nil), chatBody))
	if r.Fault.Code != policy.GuardrailCodeHate {
		t.Errorf("fault code = %q, want hate", r.Fault.Code)
	}
	if !strings.Contains(r.Fault.Description, "hate_and_discrimination, sexual") {
		t.Errorf("description = %q", r.Fault.Description)
	}
}

func TestCustomBlockStatusCode(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"blockStatusCode": 400}})
	if r := asImmediate(t, runRequest(p, chatBody)); r.StatusCode != 400 {
		t.Errorf("status = %d", r.StatusCode)
	}
}

func TestCustomJSONPath(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"jsonPath": "$.prompt"}})
	runRequest(p, `{"prompt":"from prompt"}`)
	if len(m.lastReq.Input) != 1 || m.lastReq.Input[0] != "from prompt" {
		t.Errorf("input = %v", m.lastReq.Input)
	}
}

func TestNoAPICallForEmptyInput(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	p := newPolicy(t, m, nil)
	assertAllowedRequest(t, runRequest(p, ""))
	assertAllowedRequest(t, runRequest(p, `{"messages":[{"role":"user","content":"   "}]}`))
	if m.calls.Load() != 0 {
		t.Errorf("API was called %d times for empty input", m.calls.Load())
	}
}

func TestNilBodyAllowed(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	a := newPolicy(t, m, nil).(policy.RequestPolicy).OnRequestBody(context.Background(), &policy.RequestContext{}, nil)
	assertAllowedRequest(t, a)
}

func TestPathThatMatchesNothingPasses(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	assertAllowedRequest(t, runRequest(newPolicy(t, m, nil), `{"nothing":"here"}`))
	p := newPolicy(t, m, map[string]interface{}{"request": nil, "response": map[string]interface{}{}})
	for _, body := range []string{`{"error":{"message":"rate limited","type":"x"}}`, `{"choices":[]}`, `{"unexpected":true}`, `[]`, `{}`} {
		if a := runResponse(p, 200, body).(policy.DownstreamResponseModifications); a.IsFault || a.Body != nil {
			t.Errorf("%s: a response with nothing at the path must pass, got %+v", body, a)
		}
	}
	if m.calls.Load() != 0 {
		t.Errorf("nothing to check, nothing to call; got %d calls", m.calls.Load())
	}
}

func TestNonJSONBodyBlocksAsInvalidBody(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	r := asImmediate(t, runRequest(newPolicy(t, m, nil), `not json`))
	if r.StatusCode != 422 || r.Fault.Code != policy.FaultCodeInvalidRequestBody || r.Fault.Type != policy.FaultTypeValidation {
		t.Errorf("status=%d fault=%+v", r.StatusCode, r.Fault)
	}
	if m.calls.Load() != 0 {
		t.Error("API must not be called when the text cannot be extracted")
	}
}

func TestJSONPathFailurePassthrough(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"passthroughOnError": true}})
	assertAllowedRequest(t, runRequest(p, `not json`))
}

// ─── Failures of the moderation call ────────────────────────────────────────

func TestAPIFailureFailsClosed(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { http.Error(w, "nope", http.StatusUnauthorized) })
	r := asImmediate(t, runRequest(newPolicy(t, m, nil), chatBody))
	if r.StatusCode != 503 {
		t.Errorf("status = %d, want 503", r.StatusCode)
	}
	if r.Fault.Code != policy.FaultCodeMediationFailed || r.Fault.Type != policy.FaultTypeMediation {
		t.Errorf("fault = %+v", r.Fault)
	}
	if strings.Contains(string(r.Body), "nope") || strings.Contains(r.Fault.Description, "nope") {
		t.Error("upstream error text leaked")
	}
	if got := decodeEnvelope(t, r.Body)["message"].(map[string]interface{})["action"]; got != "SERVICE_UNAVAILABLE" {
		t.Errorf("action = %v", got)
	}
	if m.calls.Load() != 1 {
		t.Errorf("a 401 must not be retried, got %d calls", m.calls.Load())
	}
}

func TestAPIFailurePassthrough(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { http.Error(w, "boom", 500) })
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"passthroughOnError": true}})
	assertAllowedRequest(t, runRequest(p, chatBody))
}

func TestRetriesServerErrorThenSucceeds(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, call int) {
		if call < 3 {
			http.Error(w, "busy", http.StatusBadGateway)
			return
		}
		safeReply(w)
	})
	assertAllowedRequest(t, runRequest(newPolicy(t, m, nil), chatBody))
	if m.calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", m.calls.Load())
	}
}

func TestRetriesRateLimit(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, call int) {
		if call == 1 {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		safeReply(w)
	})
	assertAllowedRequest(t, runRequest(newPolicy(t, m, nil), chatBody))
	if m.calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", m.calls.Load())
	}
}

func TestGivesUpAfterMaxAttempts(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { http.Error(w, "down", 503) })
	r := asImmediate(t, runRequest(newPolicy(t, m, nil), chatBody))
	if r.StatusCode != 503 || m.calls.Load() != maxAttempts {
		t.Errorf("status=%d calls=%d", r.StatusCode, m.calls.Load())
	}
}

func TestMalformedAPIResponsesFailClosedWithoutRetry(t *testing.T) {
	bodies := map[string]string{
		"not json":      `<html>`,
		"no results":    `{"results":[]}`,
		"two results":   `{"results":[{"categories":{"a":false},"category_scores":{"a":0}},{"categories":{"a":false},"category_scores":{"a":0}}]}`,
		"no categories": `{"results":[{}]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { _, _ = w.Write([]byte(body)) })
			r := asImmediate(t, runRequest(newPolicy(t, m, nil), chatBody))
			if r.StatusCode != 503 || m.calls.Load() != 1 {
				t.Errorf("status=%d calls=%d", r.StatusCode, m.calls.Load())
			}
		})
	}
}

func TestOversizedAPIResponseFailsClosed(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) {
		_, _ = w.Write([]byte(`{"results":[{"categories":{"a":false},"category_scores":{"a":0}}],"pad":"` + strings.Repeat("x", maxResponseBytes) + `"}`))
	})
	if r := asImmediate(t, runRequest(newPolicy(t, m, nil), chatBody)); r.StatusCode != 503 {
		t.Errorf("status = %d", r.StatusCode)
	}
}

func TestMissingSharedClientFailsClosed(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	p := newPolicy(t, m, nil)
	utils.SetSharedHTTPClient(nil)
	if r := asImmediate(t, runRequest(p, chatBody)); r.StatusCode != 503 {
		t.Errorf("status = %d", r.StatusCode)
	}
}

func TestUnreachableEndpointFailsClosed(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	p := newPolicy(t, m, map[string]interface{}{"endpoint": "http://127.0.0.1:1", "timeout": 2})
	utils.SetSharedHTTPClient(&http.Client{})
	if r := asImmediate(t, runRequest(p, chatBody)); r.StatusCode != 503 {
		t.Errorf("status = %d", r.StatusCode)
	}
}

func TestBackoffHonoursRetryAfterWithCap(t *testing.T) {
	if d := backoffFor(1, nil); d != baseBackoff {
		t.Errorf("attempt 1 = %v", d)
	}
	if d := backoffFor(2, nil); d != 2*baseBackoff {
		t.Errorf("attempt 2 = %v", d)
	}
	hint := &retryAfterError{httpStatusError{429}, 1_000_000_000}
	if d := backoffFor(1, hint); d != 1_000_000_000 {
		t.Errorf("1s hint = %v", d)
	}
	huge := &retryAfterError{httpStatusError{429}, 3600 * 1_000_000_000}
	if d := backoffFor(1, huge); d != maxBackoff {
		t.Errorf("huge hint not capped: %v", d)
	}
	if parseRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT") != 0 || parseRetryAfter("-5") != 0 || parseRetryAfter("3") != 3_000_000_000 {
		t.Error("parseRetryAfter wrong")
	}
}

// ─── Response phase ─────────────────────────────────────────────────────────

const completionBody = `{"choices":[{"message":{"role":"assistant","content":"some model output"}}]}`

func respPolicy(t *testing.T, m *mockMistral, phase map[string]interface{}) policy.Policy {
	t.Helper()
	return newPolicy(t, m, map[string]interface{}{"request": nil, "response": phase})
}

func TestResponseAllowedWhenSafe(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	a := runResponse(respPolicy(t, m, map[string]interface{}{}), 200, completionBody)
	if _, ok := a.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("got %T", a)
	}
	if mods := a.(policy.DownstreamResponseModifications); mods.IsFault || mods.Body != nil {
		t.Errorf("safe response was modified: %+v", mods)
	}
	if len(m.lastReq.Input) != 1 || m.lastReq.Input[0] != "some model output" {
		t.Errorf("input = %v", m.lastReq.Input)
	}
}

func TestResponseBlocked(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	a := runResponse(respPolicy(t, m, map[string]interface{}{}), 200, completionBody).(policy.DownstreamResponseModifications)
	if a.StatusCode == nil || *a.StatusCode != 422 || !a.IsFault {
		t.Fatalf("mods = %+v", a)
	}
	if a.HeadersToSet["Content-Type"] != "application/json" {
		t.Errorf("headers = %v", a.HeadersToSet)
	}
	if got := decodeEnvelope(t, a.Body)["message"].(map[string]interface{})["direction"]; got != "RESPONSE" {
		t.Errorf("direction = %v", got)
	}
	if a.Fault.Direction != policy.DirectionResponse || a.Fault.Code != policy.GuardrailCodeViolence {
		t.Errorf("fault = %+v", a.Fault)
	}
	if strings.Contains(string(a.Body), "some model output") {
		t.Error("blocked response content leaked into the error body")
	}
}

func TestResponseNon2xxPassesThroughWithoutAPICall(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	p := respPolicy(t, m, map[string]interface{}{})
	for _, status := range []int{400, 404, 500, 301} {
		a := runResponse(p, status, `{"error":"upstream error"}`).(policy.DownstreamResponseModifications)
		if a.IsFault || a.Body != nil {
			t.Errorf("status %d was modified", status)
		}
	}
	if m.calls.Load() != 0 {
		t.Errorf("API called %d times for non-2xx responses", m.calls.Load())
	}
}

func TestResponseAPIFailureReplacesResponseWith503(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { http.Error(w, "x", 401) })
	a := runResponse(respPolicy(t, m, map[string]interface{}{}), 200, completionBody).(policy.DownstreamResponseModifications)
	if a.StatusCode == nil || *a.StatusCode != 503 || a.Fault.Direction != policy.DirectionResponse {
		t.Errorf("mods = %+v", a)
	}
}

func TestResponseNonJSONBodyIsMediationFault(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) })
	a := runResponse(respPolicy(t, m, map[string]interface{}{}), 200, `<html>oops</html>`).(policy.DownstreamResponseModifications)
	if a.Fault == nil || a.Fault.Code != policy.FaultCodeMediationFailed || a.Fault.Type != policy.FaultTypeMediation {
		t.Errorf("fault = %+v", a.Fault)
	}
}

func TestPhasesAreIndependent(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	p := newPolicy(t, m, map[string]interface{}{
		"request":  map[string]interface{}{"categoryThresholds": map[string]interface{}{"violence_and_threats": 1}},
		"response": map[string]interface{}{},
	})
	assertAllowedRequest(t, runRequest(p, chatBody))                                                   // violence disabled on the request side
	if a := runResponse(p, 200, completionBody).(policy.DownstreamResponseModifications); !a.IsFault { // but enforced on the response
		t.Error("response phase should still block")
	}
}

func TestUnconfiguredPhaseIsNoOp(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { violenceReply(w) })
	p := newPolicy(t, m, nil) // request only
	if a := runResponse(p, 200, completionBody).(policy.DownstreamResponseModifications); a.IsFault {
		t.Error("response must not be moderated when only request is configured")
	}
	if m.calls.Load() != 0 {
		t.Error("API called")
	}
}

// ─── guardrailCodeFor ───────────────────────────────────────────────────────

func TestGuardrailCodeFor(t *testing.T) {
	cases := map[string]string{
		"sexual":                         policy.GuardrailCodeSexual,
		"hate_and_discrimination":        policy.GuardrailCodeHate,
		"violence_and_threats":           policy.GuardrailCodeViolence,
		"selfharm":                       policy.GuardrailCodeSelfHarm,
		"self_harm":                      policy.GuardrailCodeSelfHarm,
		"dangerous_and_criminal_content": policy.GuardrailCodeDangerousActivity,
		"dangerous":                      policy.GuardrailCodeDangerousActivity,
		"criminal":                       policy.GuardrailCodeDangerousActivity,
		"jailbreaking":                   policy.GuardrailCodePromptInjection,
		"pii":                            policy.GuardrailCodePII,
		"something_new":                  policy.GuardrailCodeUnsafeContent,
		"":                               policy.GuardrailCodeUnsafeContent,
	}
	for in, want := range cases {
		if got := guardrailCodeFor(in); got != want {
			t.Errorf("guardrailCodeFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func jsonEncode(w http.ResponseWriter, v interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}
