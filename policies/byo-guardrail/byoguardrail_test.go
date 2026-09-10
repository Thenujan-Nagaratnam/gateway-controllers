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

package byoguardrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// --- Helpers ---

func mustGetPolicy(t *testing.T, params map[string]interface{}) *BYOGuardrailPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	gp, ok := p.(*BYOGuardrailPolicy)
	if !ok {
		t.Fatalf("expected *BYOGuardrailPolicy, got %T", p)
	}
	return gp
}

func reqCtx(body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{RequestID: "req-id", Metadata: map[string]interface{}{}},
		Body:          &policy.Body{Content: []byte(body), Present: body != ""},
	}
}

func respCtx(body string) *policy.ResponseContext {
	return &policy.ResponseContext{
		SharedContext: &policy.SharedContext{RequestID: "req-id", Metadata: map[string]interface{}{}},
		ResponseBody:  &policy.Body{Content: []byte(body), Present: body != ""},
	}
}

func mockGuardrailServer(t *testing.T, decision guardrailDecision) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decision)
	}))
}

func baseParams(endpoint string) map[string]interface{} {
	return map[string]interface{}{"endpoint": endpoint}
}

func decodeJSON(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	return m
}

func assertRequestBlocked(t *testing.T, action policy.RequestAction) map[string]interface{} {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != blockStatusCode {
		t.Fatalf("unexpected status code: got %d, want %d", resp.StatusCode, blockStatusCode)
	}
	return decodeJSON(t, resp.Body)
}

func assertResponseBlocked(t *testing.T, action policy.ResponseAction) map[string]interface{} {
	t.Helper()
	resp, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	if resp.StatusCode == nil || *resp.StatusCode != blockStatusCode {
		t.Fatalf("unexpected status code: %v", resp.StatusCode)
	}
	return decodeJSON(t, resp.Body)
}

func extractMessage(t *testing.T, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	msg, ok := body["message"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected body.message object, got %T", body["message"])
	}
	return msg
}

// --- Config validation ---

func TestGetPolicy_MissingEndpoint(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"request": map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "'endpoint'") {
		t.Fatalf("expected missing endpoint error, got %v", err)
	}
}

func TestGetPolicy_EndpointNotAbsolute(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"endpoint": "not-a-url",
		"request":  map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "http or https scheme") {
		t.Fatalf("expected scheme error, got %v", err)
	}
}

func TestGetPolicy_EndpointWrongScheme(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"endpoint": "ftp://example.com/evaluate",
		"request":  map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "http or https scheme") {
		t.Fatalf("expected scheme error, got %v", err)
	}
}

func TestGetPolicy_EndpointWithUserinfo(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"endpoint": "https://user:pass@example.com/evaluate",
		"request":  map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "userinfo") {
		t.Fatalf("expected userinfo rejection, got %v", err)
	}
}

func TestGetPolicy_MissingRequestAndResponse(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"endpoint": "https://example.com/evaluate",
	})
	if err == nil || !strings.Contains(err.Error(), "at least one of 'request' or 'response'") {
		t.Fatalf("expected missing request/response error, got %v", err)
	}
}

func TestGetPolicy_APIKeyAuthMissingValue(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"endpoint": "https://example.com/evaluate",
		"request":  map[string]interface{}{},
		"auth":     map[string]interface{}{"type": "apiKey"},
	})
	if err == nil || !strings.Contains(err.Error(), "'apiKeyValue' is required") {
		t.Fatalf("expected apiKeyValue required error, got %v", err)
	}
}

func TestGetPolicy_InvalidAuthType(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"endpoint": "https://example.com/evaluate",
		"request":  map[string]interface{}{},
		"auth":     map[string]interface{}{"type": "hmac"},
	})
	if err == nil || !strings.Contains(err.Error(), "'type' must be one of") {
		t.Fatalf("expected invalid auth type error, got %v", err)
	}
}

func TestGetPolicy_InvalidRequestTimeout(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"endpoint":       "https://example.com/evaluate",
		"request":        map[string]interface{}{},
		"requestTimeout": "soon",
	})
	if err == nil || !strings.Contains(err.Error(), "'requestTimeout'") {
		t.Fatalf("expected requestTimeout error, got %v", err)
	}
}

func TestGetPolicy_InvalidMaxResponseBytes(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"endpoint":         "https://example.com/evaluate",
		"request":          map[string]interface{}{},
		"maxResponseBytes": float64(-5),
	})
	if err == nil || !strings.Contains(err.Error(), "'maxResponseBytes'") {
		t.Fatalf("expected maxResponseBytes error, got %v", err)
	}
}

// --- ALLOW / pass-through ---

func TestOnRequestBody_AllowVerdict_PassThrough(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "ALLOW"})
	defer srv.Close()

	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL,
		"request":  map[string]interface{}{},
	})
	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"hello"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on ALLOW, got %T", action)
	}
}

func TestOnRequestBody_NoRequestConfig_PassThrough(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": "https://example.com/evaluate",
		"response": map[string]interface{}{"enabled": true},
	})
	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"content":"hi"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestOnResponseBody_NoResponseConfig_PassThrough(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": "https://example.com/evaluate",
		"request":  map[string]interface{}{},
	})
	action := p.OnResponseBody(context.Background(), respCtx(`{"choices":[{"message":{"content":"hi"}}]}`), nil)
	if _, ok := action.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
}

// --- BLOCK ---

func TestOnRequestBody_BlockVerdict_Returns422(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "BLOCK", Reason: "banned phrase detected"})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"bad stuff"}]}`), nil)
	body := assertRequestBlocked(t, action)
	if body["type"] != "BYO_GUARDRAIL" {
		t.Fatalf("unexpected type: %v", body["type"])
	}
	msg := extractMessage(t, body)
	if msg["direction"] != "REQUEST" {
		t.Fatalf("expected REQUEST direction, got %v", msg["direction"])
	}
	if msg["actionReason"] != "banned phrase detected" {
		t.Fatalf("expected reason to be surfaced, got %v", msg["actionReason"])
	}
	if msg["interveningGuardrail"] != defaultGuardrailName {
		t.Fatalf("expected default guardrailName, got %v", msg["interveningGuardrail"])
	}
}

func TestOnResponseBody_BlockVerdict_Returns422(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "BLOCK"})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{}
	params["response"] = map[string]interface{}{"enabled": true}
	p := mustGetPolicy(t, params)

	action := p.OnResponseBody(context.Background(), respCtx(`{"choices":[{"message":{"content":"bad"}}]}`), nil)
	body := assertResponseBlocked(t, action)
	msg := extractMessage(t, body)
	if msg["direction"] != "RESPONSE" {
		t.Fatalf("expected RESPONSE direction, got %v", msg["direction"])
	}
}

func TestOnRequestBody_BlockVerdict_InterveningGuardrailOverride(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "BLOCK", InterveningGuardrail: "ToxicityGuard"})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["guardrailName"] = "DefaultName"
	params["request"] = map[string]interface{}{}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"x"}]}`), nil)
	body := assertRequestBlocked(t, action)
	msg := extractMessage(t, body)
	if msg["interveningGuardrail"] != "ToxicityGuard" {
		t.Fatalf("expected override guardrail name, got %v", msg["interveningGuardrail"])
	}
}

// --- showAssessment ---

func TestOnRequestBody_BlockVerdict_ShowAssessment(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "BLOCK", Assessment: map[string]string{"category": "toxicity", "score": "0.9"}})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"showAssessment": true}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"x"}]}`), nil)
	body := assertRequestBlocked(t, action)
	msg := extractMessage(t, body)
	assessments, ok := msg["assessments"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected assessments map, got %T", msg["assessments"])
	}
	if assessments["category"] != "toxicity" {
		t.Fatalf("expected category in assessments, got %v", assessments)
	}
}

func TestOnRequestBody_BlockVerdict_ShowAssessmentFalse(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "BLOCK", Assessment: map[string]string{"category": "toxicity"}})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"showAssessment": false}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"x"}]}`), nil)
	body := assertRequestBlocked(t, action)
	msg := extractMessage(t, body)
	if _, ok := msg["assessments"]; ok {
		t.Fatalf("expected no assessments when showAssessment=false")
	}
}

// --- MODIFY ---

func TestOnRequestBody_ModifyVerdict_RewritesContent(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "MODIFY", ModifiedContent: "REDACTED"})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"jsonPath": "$.prompt"}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"prompt":"my ssn is 123-45-6789"}`), nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications on MODIFY, got %T", action)
	}
	body := decodeJSON(t, mods.Body)
	if body["prompt"] != "REDACTED" {
		t.Fatalf("expected rewritten prompt, got %v", body["prompt"])
	}
}

// A MODIFY verdict with an empty modifiedContent is a protocol error, not "replace
// with blank text" - the guardrail service is either misbehaving or the field was
// omitted from its response. Silently rewriting the field to "" and forwarding a 200
// would mask that failure behind a confusing, silently-emptied response.
func TestOnRequestBody_ModifyVerdict_EmptyModifiedContent_PassthroughDisabled(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "MODIFY", ModifiedContent: ""})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"passthroughOnError": false}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"hi"}]}`), nil)
	assertRequestBlocked(t, action)
}

func TestOnRequestBody_ModifyVerdict_EmptyModifiedContent_PassthroughEnabled(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "MODIFY", ModifiedContent: "   "})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"passthroughOnError": true}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"hi"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications (unmodified passthrough) on whitespace-only modifiedContent with passthroughOnError=true, got %T", action)
	}
}

func TestOnResponseBody_ModifyVerdict_RewritesContent(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "MODIFY", ModifiedContent: "safe reply"})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{}
	params["response"] = map[string]interface{}{"enabled": true}
	p := mustGetPolicy(t, params)

	action := p.OnResponseBody(context.Background(), respCtx(`{"choices":[{"message":{"content":"unsafe reply"}}]}`), nil)
	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications on MODIFY, got %T", action)
	}
	if mods.StatusCode != nil {
		t.Fatalf("MODIFY must not override the status code, got %v", *mods.StatusCode)
	}
	body := decodeJSON(t, mods.Body)
	choices := body["choices"].([]interface{})
	msg := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if msg["content"] != "safe reply" {
		t.Fatalf("expected rewritten content, got %v", msg["content"])
	}
}

// --- Unknown verdict ---

func TestOnRequestBody_UnknownVerdict_TreatedAsError(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "MAYBE"})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"passthroughOnError": false}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"x"}]}`), nil)
	assertRequestBlocked(t, action)
}

func TestOnRequestBody_UnknownVerdict_PassthroughEnabled(t *testing.T) {
	srv := mockGuardrailServer(t, guardrailDecision{Verdict: "MAYBE"})
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"passthroughOnError": true}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"x"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through on unknown verdict with passthroughOnError, got %T", action)
	}
}

// --- Transport / API errors ---

func TestOnRequestBody_APIError_PassthroughDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"passthroughOnError": false}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"x"}]}`), nil)
	assertRequestBlocked(t, action)
}

func TestOnRequestBody_APIError_PassthroughEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"passthroughOnError": true}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"x"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through on API error, got %T", action)
	}
}

func TestOnRequestBody_APIError_ReasonIsSterile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"some very specific internal backend detail"}`))
	}))
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"passthroughOnError": false, "showAssessment": true}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"x"}]}`), nil)
	body := assertRequestBlocked(t, action)
	msg := extractMessage(t, body)
	reason, _ := msg["actionReason"].(string)
	if strings.Contains(reason, "internal") || strings.Contains(reason, srv.URL) {
		t.Fatalf("expected sterile actionReason, got %q", reason)
	}
	if _, ok := msg["assessments"]; ok {
		t.Fatalf("expected no assessments for a transport error even with showAssessment=true")
	}
}

// --- Response size limit ---

func TestOnRequestBody_OversizedResponse_Blocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":"ALLOW","padding":"` + strings.Repeat("a", 200) + `"}`))
	}))
	defer srv.Close()

	params := baseParams(srv.URL)
	params["maxResponseBytes"] = float64(32)
	params["request"] = map[string]interface{}{"passthroughOnError": false}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"x"}]}`), nil)
	assertRequestBlocked(t, action)
}

// --- Auth header ---

func TestOnRequestBody_APIKeyAuthHeaderSent(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(guardrailDecision{Verdict: "ALLOW"})
	}))
	defer srv.Close()

	params := baseParams(srv.URL)
	params["auth"] = map[string]interface{}{"type": "apiKey", "apiKeyValue": "secret-token"}
	params["request"] = map[string]interface{}{}
	p := mustGetPolicy(t, params)

	p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"hi"}]}`), nil)
	if capturedAuth != "Bearer secret-token" {
		t.Fatalf("expected Authorization header 'Bearer secret-token', got %q", capturedAuth)
	}
}

func TestOnRequestBody_APIKeyAuthCustomHeader(t *testing.T) {
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(guardrailDecision{Verdict: "ALLOW"})
	}))
	defer srv.Close()

	params := baseParams(srv.URL)
	params["auth"] = map[string]interface{}{
		"type":        "apiKey",
		"headerName":  "X-Api-Key",
		"valuePrefix": "",
		"apiKeyValue": "raw-value",
	}
	params["request"] = map[string]interface{}{}
	p := mustGetPolicy(t, params)

	p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"hi"}]}`), nil)
	if captured != "raw-value" {
		t.Fatalf("expected X-Api-Key 'raw-value', got %q", captured)
	}
}

func TestOnRequestBody_NoAuth_NoHeaderSent(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization") != ""
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(guardrailDecision{Verdict: "ALLOW"})
	}))
	defer srv.Close()

	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": srv.URL,
		"request":  map[string]interface{}{},
	})
	p.OnRequestBody(context.Background(), reqCtx(`{"messages":[{"role":"user","content":"hi"}]}`), nil)
	if sawAuth {
		t.Fatalf("expected no Authorization header when auth.type is unset (none)")
	}
}

// --- Request payload shape sent to the guardrail endpoint ---

func TestCallGuardrailEndpoint_SendsExpectedPayload(t *testing.T) {
	var captured guardrailEvaluateRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(guardrailDecision{Verdict: "ALLOW"})
	}))
	defer srv.Close()

	params := baseParams(srv.URL)
	params["request"] = map[string]interface{}{"jsonPath": "$.prompt"}
	p := mustGetPolicy(t, params)

	p.OnRequestBody(context.Background(), reqCtx(`{"prompt":"extracted text"}`), nil)
	if captured.Content != "extracted text" {
		t.Fatalf("expected content 'extracted text', got %q", captured.Content)
	}
	if captured.Direction != "REQUEST" {
		t.Fatalf("expected direction REQUEST, got %q", captured.Direction)
	}
	if captured.RequestID != "req-id" {
		t.Fatalf("expected requestId 'req-id', got %q", captured.RequestID)
	}
}

// --- Nil body / JSONPath errors ---

func TestOnRequestBody_NilBody_PassThrough(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": "https://example.com/evaluate",
		"request":  map[string]interface{}{},
	})
	action := p.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: &policy.SharedContext{RequestID: "req-id"},
		Body:          nil,
	}, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications for nil body, got %T", action)
	}
}

func TestOnRequestBody_JSONPathError_PassthroughDisabled(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": "https://example.com/evaluate",
		"request":  map[string]interface{}{"jsonPath": "$.missing", "passthroughOnError": false},
	})
	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":"hello"}`), nil)
	assertRequestBlocked(t, action)
}

func TestOnRequestBody_JSONPathError_PassthroughEnabled(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"endpoint": "https://example.com/evaluate",
		"request":  map[string]interface{}{"jsonPath": "$.missing", "passthroughOnError": true},
	})
	action := p.OnRequestBody(context.Background(), reqCtx(`{"messages":"hello"}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through on JSONPath error, got %T", action)
	}
}

// --- Parse flow / auth params directly ---

func TestParseFlowParams_Defaults(t *testing.T) {
	got, err := parseFlowParams(map[string]interface{}{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.JsonPath != requestDefaultJSONPath || !got.Enabled {
		t.Fatalf("unexpected request defaults: %+v", got)
	}

	gotResp, err := parseFlowParams(map[string]interface{}{}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotResp.JsonPath != responseDefaultJSONPath || gotResp.Enabled {
		t.Fatalf("unexpected response defaults: %+v", gotResp)
	}
}

func TestParseAuthConfig_Defaults(t *testing.T) {
	got, err := parseAuthConfig(map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.authType != authTypeNone {
		t.Fatalf("expected default auth type none, got %q", got.authType)
	}
}
