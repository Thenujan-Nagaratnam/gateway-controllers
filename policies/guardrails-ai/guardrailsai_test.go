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

package guardrailsai

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

func mustGetPolicy(t *testing.T, params map[string]interface{}) *GuardrailsAIPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}
	gp, ok := p.(*GuardrailsAIPolicy)
	if !ok {
		t.Fatalf("expected *GuardrailsAIPolicy, got %T", p)
	}
	return gp
}

func guardRequestContext(body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		Body: &policy.Body{
			Content: []byte(body),
			Present: body != "",
		},
	}
}

func guardResponseContext(body string) *policy.ResponseContext {
	return &policy.ResponseContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		ResponseBody: &policy.Body{
			Content: []byte(body),
			Present: body != "",
		},
	}
}

func mockValidateServer(t *testing.T, status string, failedValidators []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/validate") {
			t.Errorf("expected /validate path suffix, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"callId":       "test-call-id",
			"rawLlmOutput": "test-text",
			"status":       status,
		}
		if len(failedValidators) > 0 {
			resp["failedValidators"] = failedValidators
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func baseParams(serverURL, guardName string) map[string]interface{} {
	return map[string]interface{}{
		"guardrailsApiEndpoint": serverURL,
		"apiKey":                "test-key",
		"guardName":             guardName,
	}
}

func decodeJSON(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	return m
}

func assertRequestError(t *testing.T, action policy.RequestAction) map[string]interface{} {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != GuardrailErrorCode {
		t.Fatalf("unexpected status code: got %d, want %d", resp.StatusCode, GuardrailErrorCode)
	}
	return decodeJSON(t, resp.Body)
}

func assertResponseError(t *testing.T, action policy.ResponseAction) map[string]interface{} {
	t.Helper()
	resp, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	if resp.StatusCode == nil || *resp.StatusCode != GuardrailErrorCode {
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

// --- Config validation tests ---

func TestGetPolicy_MissingEndpoint(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"guardName": "my-guard",
		"request":   map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "'guardrailsApiEndpoint' parameter is required") {
		t.Fatalf("expected missing endpoint error, got %v", err)
	}
}

func TestGetPolicy_EndpointWrongType(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"guardrailsApiEndpoint": 123,
		"guardName":             "my-guard",
		"request":               map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "'guardrailsApiEndpoint' must be a string") {
		t.Fatalf("expected endpoint type error, got %v", err)
	}
}

func TestGetPolicy_MissingGuardName(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"request":               map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "'guardName' parameter is required") {
		t.Fatalf("expected missing guardName error, got %v", err)
	}
}

func TestGetPolicy_MissingRequestAndResponse(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
	})
	if err == nil || !strings.Contains(err.Error(), "at least one of 'request' or 'response' parameters must be provided") {
		t.Fatalf("expected missing request/response error, got %v", err)
	}
}

func TestGetPolicy_InvalidRequestParams(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"request": map[string]interface{}{
			"enabled": "not-a-bool",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid request parameters") {
		t.Fatalf("expected invalid request params error, got %v", err)
	}
}

func TestGetPolicy_InvalidResponseParams(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"response": map[string]interface{}{
			"jsonPath": 42,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid response parameters") {
		t.Fatalf("expected invalid response params error, got %v", err)
	}
}

func TestGetPolicy_InvalidRequestTimeout(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"requestTimeout":        "not-a-number",
		"request":               map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "'requestTimeout'") {
		t.Fatalf("expected requestTimeout type error, got %v", err)
	}
}

func TestGetPolicy_NonPositiveRequestTimeout(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"requestTimeout":        float64(0),
		"request":               map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "'requestTimeout'") {
		t.Fatalf("expected requestTimeout positivity error, got %v", err)
	}
}

func TestGetPolicy_InvalidMaxResponseBytes(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"maxResponseBytes":      "lots",
		"request":               map[string]interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "'maxResponseBytes'") {
		t.Fatalf("expected maxResponseBytes type error, got %v", err)
	}
}

// --- Request disabled / no config ---

func TestOnRequestBody_NoRequestConfig_PassThrough(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"response": map[string]interface{}{
			"enabled": true,
		},
	})
	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"content":"hello"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

func TestOnRequestBody_RequestDisabled_PassThrough(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"request": map[string]interface{}{
			"enabled": false,
		},
		"response": map[string]interface{}{
			"enabled": true,
		},
	})
	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"content":"hello"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications when request disabled, got %T", action)
	}
}

func TestOnResponseBody_NoResponseConfig_PassThrough(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"request":               map[string]interface{}{},
	})
	action := p.OnResponseBody(context.Background(), guardResponseContext(`{"choices":[{"message":{"content":"hi"}}]}`), nil)
	if _, ok := action.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
}

func TestOnResponseBody_ResponseDisabled_PassThrough(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"request":               map[string]interface{}{},
		"response": map[string]interface{}{
			"enabled": false,
		},
	})
	action := p.OnResponseBody(context.Background(), guardResponseContext(`{"choices":[{"message":{"content":"hi"}}]}`), nil)
	if _, ok := action.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications when response disabled, got %T", action)
	}
}

// --- Pass validation ---

func TestOnRequestBody_PassValidation(t *testing.T) {
	srv := mockValidateServer(t, "pass", nil)
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{
		"jsonPath": "$.messages[-1].content",
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"hello world"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on pass, got %T", action)
	}
}

func TestOnResponseBody_PassValidation(t *testing.T) {
	srv := mockValidateServer(t, "pass", nil)
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{}
	params["response"] = map[string]interface{}{
		"enabled":  true,
		"jsonPath": "$.choices[0].message.content",
	}
	p := mustGetPolicy(t, params)

	action := p.OnResponseBody(context.Background(), guardResponseContext(`{"choices":[{"message":{"content":"hello"}}]}`), nil)
	if _, ok := action.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications on pass, got %T", action)
	}
}

// --- Fail validation ---

func TestOnRequestBody_FailValidation_Returns422(t *testing.T) {
	srv := mockValidateServer(t, "fail", []string{"ToxicLanguage"})
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{
		"jsonPath": "$.messages[-1].content",
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"toxic message"}]}`), nil)
	body := assertRequestError(t, action)
	if body["type"] != "GUARDRAILS_AI_GUARDRAIL" {
		t.Fatalf("unexpected error type: %v", body["type"])
	}
	msg := extractMessage(t, body)
	if msg["direction"] != "REQUEST" {
		t.Fatalf("expected REQUEST direction, got %v", msg["direction"])
	}
	if msg["action"] != "GUARDRAIL_INTERVENED" {
		t.Fatalf("expected GUARDRAIL_INTERVENED action, got %v", msg["action"])
	}
}

func TestOnResponseBody_FailValidation_Returns422(t *testing.T) {
	srv := mockValidateServer(t, "fail", nil)
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{}
	params["response"] = map[string]interface{}{
		"enabled": true,
	}
	p := mustGetPolicy(t, params)

	action := p.OnResponseBody(context.Background(), guardResponseContext(`{"choices":[{"message":{"content":"bad content"}}]}`), nil)
	body := assertResponseError(t, action)
	if body["type"] != "GUARDRAILS_AI_GUARDRAIL" {
		t.Fatalf("unexpected error type: %v", body["type"])
	}
	msg := extractMessage(t, body)
	if msg["direction"] != "RESPONSE" {
		t.Fatalf("expected RESPONSE direction, got %v", msg["direction"])
	}
}

// --- ShowAssessment ---

func TestOnRequestBody_FailValidation_ShowAssessment(t *testing.T) {
	srv := mockValidateServer(t, "fail", []string{"ToxicLanguage", "Jailbreak"})
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{
		"showAssessment": true,
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"bad prompt"}]}`), nil)
	body := assertRequestError(t, action)
	msg := extractMessage(t, body)
	if _, ok := msg["assessments"]; !ok {
		t.Fatalf("expected assessments in error response when showAssessment=true")
	}
	assessment, ok := msg["assessments"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected assessments to be a map, got %T", msg["assessments"])
	}
	if _, ok := assessment["failedValidators"]; !ok {
		t.Fatalf("expected failedValidators in assessments")
	}
}

func TestOnRequestBody_FailValidation_ShowAssessment_False(t *testing.T) {
	srv := mockValidateServer(t, "fail", []string{"ToxicLanguage"})
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{
		"showAssessment": false,
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"bad prompt"}]}`), nil)
	body := assertRequestError(t, action)
	msg := extractMessage(t, body)
	if _, ok := msg["assessments"]; ok {
		t.Fatalf("expected no assessments when showAssessment=false")
	}
}

// --- API errors with passthrough ---

func TestOnRequestBody_APIError_PassthroughEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{
		"passthroughOnError": true,
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"test"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on API error with passthrough, got %T", action)
	}
}

func TestOnRequestBody_APIError_PassthroughDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{
		"passthroughOnError": false,
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"test"}]}`), nil)
	assertRequestError(t, action)
}

// buildErrorResponse must never leak the underlying transport/API error text to the
// client (error-handling.md) - only a fixed, sterile reason.
func TestOnRequestBody_APIError_ReasonIsSterile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"some very specific internal backend detail"}`))
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{
		"passthroughOnError": false,
		"showAssessment":     true,
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"test"}]}`), nil)
	body := assertRequestError(t, action)
	msg := extractMessage(t, body)
	reason, _ := msg["actionReason"].(string)
	if strings.Contains(reason, "internal") || strings.Contains(reason, srv.URL) {
		t.Fatalf("expected sterile actionReason, got %q which leaks internal detail", reason)
	}
	if _, ok := msg["assessments"]; ok {
		t.Fatalf("expected no assessments field for a transport/API error even with showAssessment=true, got %v", msg["assessments"])
	}
}

func TestOnResponseBody_APIError_PassthroughEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{}
	params["response"] = map[string]interface{}{
		"enabled":            true,
		"passthroughOnError": true,
	}
	p := mustGetPolicy(t, params)

	action := p.OnResponseBody(context.Background(), guardResponseContext(`{"choices":[{"message":{"content":"hi"}}]}`), nil)
	if _, ok := action.(policy.DownstreamResponseModifications); !ok {
		t.Fatalf("expected DownstreamResponseModifications on API error with passthrough, got %T", action)
	}
	// Must be a pass-through (no status code override)
	mods := action.(policy.DownstreamResponseModifications)
	if mods.StatusCode != nil {
		t.Fatalf("expected no status code override on passthrough, got %d", *mods.StatusCode)
	}
}

func TestOnResponseBody_APIError_PassthroughDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{}
	params["response"] = map[string]interface{}{
		"enabled":            true,
		"passthroughOnError": false,
	}
	p := mustGetPolicy(t, params)

	action := p.OnResponseBody(context.Background(), guardResponseContext(`{"choices":[{"message":{"content":"hi"}}]}`), nil)
	assertResponseError(t, action)
}

// --- Response size limit ---

func TestOnRequestBody_OversizedResponse_PassthroughDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Pad well past the configured maxResponseBytes.
		_, _ = w.Write([]byte(`{"status":"pass","padding":"` + strings.Repeat("a", 200) + `"}`))
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["maxResponseBytes"] = float64(32)
	params["request"] = map[string]interface{}{
		"passthroughOnError": false,
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"test"}]}`), nil)
	assertRequestError(t, action)
}

func TestOnRequestBody_OversizedResponse_PassthroughEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"pass","padding":"` + strings.Repeat("a", 200) + `"}`))
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["maxResponseBytes"] = float64(32)
	params["request"] = map[string]interface{}{
		"passthroughOnError": true,
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"test"}]}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications on oversized response with passthrough, got %T", action)
	}
}

// --- JSONPath errors ---

func TestOnRequestBody_JSONPathError_PassthroughEnabled(t *testing.T) {
	params := map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"request": map[string]interface{}{
			"jsonPath":           "$.missing.deep.path",
			"passthroughOnError": true,
		},
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":"hello"}`), nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected pass-through on JSONPath error, got %T", action)
	}
}

func TestOnRequestBody_JSONPathError_PassthroughDisabled(t *testing.T) {
	params := map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"request": map[string]interface{}{
			"jsonPath":           "$.missing.deep.path",
			"passthroughOnError": false,
		},
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":"hello"}`), nil)
	assertRequestError(t, action)
}

// --- Custom JSONPath ---

func TestOnRequestBody_CustomJSONPath_CorrectTextSent(t *testing.T) {
	var capturedBody guardrailsValidateRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&capturedBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "pass"})
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{
		"jsonPath": "$.prompt",
	}
	p := mustGetPolicy(t, params)

	p.OnRequestBody(context.Background(), guardRequestContext(`{"prompt":"custom extracted text"}`), nil)
	if capturedBody.LLMOutput != "custom extracted text" {
		t.Fatalf("expected llmOutput 'custom extracted text', got %q", capturedBody.LLMOutput)
	}
}

// --- Guard name in error response ---

func TestOnRequestBody_FailValidation_GuardNameInResponse(t *testing.T) {
	srv := mockValidateServer(t, "fail", nil)
	defer srv.Close()

	params := baseParams(srv.URL, "toxicity-guard")
	params["request"] = map[string]interface{}{}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"test"}]}`), nil)
	body := assertRequestError(t, action)
	msg := extractMessage(t, body)
	if msg["guardName"] != "toxicity-guard" {
		t.Fatalf("expected guardName 'toxicity-guard' in error response, got %v", msg["guardName"])
	}
}

// --- Auth header ---

func TestOnRequestBody_AuthHeaderSent(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "pass"})
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["apiKey"] = "my-secret-token"
	params["request"] = map[string]interface{}{}
	p := mustGetPolicy(t, params)

	p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"hello"}]}`), nil)
	if capturedAuth != "Bearer my-secret-token" {
		t.Fatalf("expected Authorization header 'Bearer my-secret-token', got %q", capturedAuth)
	}
}

// --- Parse flow params ---

func TestParseFlowParams_Defaults(t *testing.T) {
	got, err := parseFlowParams(map[string]interface{}{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.JsonPath != requestDefaultJSONPath {
		t.Fatalf("expected default request jsonPath, got %q", got.JsonPath)
	}
	if !got.Enabled {
		t.Fatalf("expected request to be enabled by default")
	}

	gotResp, err := parseFlowParams(map[string]interface{}{}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotResp.JsonPath != responseDefaultJSONPath {
		t.Fatalf("expected default response jsonPath, got %q", gotResp.JsonPath)
	}
	if gotResp.Enabled {
		t.Fatalf("expected response to be disabled by default")
	}
}

func TestParseFlowParams_InvalidTypes(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]interface{}
		want   string
	}{
		{"enabled wrong type", map[string]interface{}{"enabled": "true"}, "'enabled' must be a boolean"},
		{"jsonPath wrong type", map[string]interface{}{"jsonPath": 42}, "'jsonPath' must be a string"},
		{"passthroughOnError wrong type", map[string]interface{}{"passthroughOnError": "yes"}, "'passthroughOnError' must be a boolean"},
		{"showAssessment wrong type", map[string]interface{}{"showAssessment": 1}, "'showAssessment' must be a boolean"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFlowParams(tt.params, false)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

// --- Validate endpoint path ---

func TestCallValidateAPI_CorrectEndpointPath(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "pass"})
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "pii-guard")
	params["request"] = map[string]interface{}{}
	p := mustGetPolicy(t, params)

	p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"test"}]}`), nil)
	if capturedPath != "/guards/pii-guard/validate" {
		t.Fatalf("expected path /guards/pii-guard/validate, got %q", capturedPath)
	}
}

// --- Nil body ---

func TestOnRequestBody_NilBody_PassThrough(t *testing.T) {
	p := mustGetPolicy(t, map[string]interface{}{
		"guardrailsApiEndpoint": "http://localhost:8000",
		"guardName":             "my-guard",
		"request":               map[string]interface{}{},
	})
	reqCtx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "req-id",
			Metadata:  map[string]interface{}{},
		},
		Body: nil,
	}
	action := p.OnRequestBody(context.Background(), reqCtx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications for nil body, got %T", action)
	}
}

// --- Invalid JSON response from server ---

func TestOnRequestBody_InvalidJSONFromServer_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer srv.Close()

	params := baseParams(srv.URL, "my-guard")
	params["request"] = map[string]interface{}{
		"passthroughOnError": false,
	}
	p := mustGetPolicy(t, params)

	action := p.OnRequestBody(context.Background(), guardRequestContext(`{"messages":[{"role":"user","content":"test"}]}`), nil)
	assertRequestError(t, action)
}
