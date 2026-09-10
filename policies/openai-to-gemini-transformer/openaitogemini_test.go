/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package openaitogemini

import (
	"context"
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestGetPolicy_ModelIsOptionalAtConfigTime(t *testing.T) {
	// Unlike before payload-fallback support, an absent 'model' param is not
	// a config-time error - resolveModel enforces "payload or config, at
	// least one" per request instead (see TestOnRequestBody_RejectsMissingFallbackModel).
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{}); err != nil {
		t.Fatalf("model override should be optional: %v", err)
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"model": "gemini-2.5-flash", "providerId": "gemini-provider",
	}); err != nil {
		t.Fatalf("unexpected error for valid params: %v", err)
	}
}

func TestGetPolicy_ParsesRequestModel(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tp := p.(*TranslatorPolicy)
	if tp.params.RequestModel.Location != "payload" || tp.params.RequestModel.Identifier != "$.model" {
		t.Fatalf("requestModel not parsed into params: %#v", tp.params.RequestModel)
	}

	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{}); err != nil {
		t.Fatalf("requestModel should be optional: %v", err)
	}

	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"requestModel": map[string]interface{}{"location": "header", "identifier": "x-model"},
	}); err == nil {
		t.Fatal("expected an error for a non-payload requestModel.location")
	}
}

// TestOnRequestBody_UsesInjectedRequestModelJsonPath proves resolveModel
// actually follows the PROXY's own template's requestModel identifier (here
// deliberately NOT the default "$.model", so a pass can't be a coincidence of
// a hardcoded lookup) rather than always reading a fixed top-level field.
func TestOnRequestBody_UsesInjectedRequestModelJsonPath(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{
		APIVersion:   DefaultAPIVersion,
		RequestModel: requestModelConfig{Location: "payload", Identifier: "$.routing.modelName"},
	}}
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	req := &policy.RequestContext{
		SharedContext: shared,
		Body: &policy.Body{Present: true, Content: []byte(
			`{"routing":{"modelName":"gemini-2.5-pro-via-custom-path"},"messages":[{"role":"user","content":"hi"}]}`)},
	}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	want := "/v1beta/models/gemini-2.5-pro-via-custom-path:generateContent"
	if mods.Path == nil || *mods.Path != want {
		t.Fatalf("expected the model read via requestModel's JSONPath, path %q, got %v", want, mods.Path)
	}
	if got := shared.Metadata[MetadataKeyEffectiveModel]; got != "gemini-2.5-pro-via-custom-path" {
		t.Fatalf("effective model was not stored in request metadata: %v", got)
	}
}

func TestOnRequestBody_FallsBackToRequestModel(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{APIVersion: DefaultAPIVersion}}
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	req := &policy.RequestContext{
		SharedContext: shared,
		Body: &policy.Body{Present: true, Content: []byte(
			`{"model":"gemini-2.5-pro-from-payload","messages":[{"role":"user","content":"hi"}]}`)},
	}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	want := "/v1beta/models/gemini-2.5-pro-from-payload:generateContent"
	if mods.Path == nil || *mods.Path != want {
		t.Fatalf("expected fallback path %q, got %v", want, mods.Path)
	}
	if got := shared.Metadata[MetadataKeyEffectiveModel]; got != "gemini-2.5-pro-from-payload" {
		t.Fatalf("effective model was not stored in request metadata: %v", got)
	}
}

func TestOnRequestBody_PayloadModelWinsOverConfiguredModel(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{APIVersion: DefaultAPIVersion, Model: "gemini-2.5-flash-configured"}}
	req := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Body: &policy.Body{Present: true, Content: []byte(
			`{"model":"gemini-2.5-pro-should-win","messages":[{"role":"user","content":"hi"}]}`)},
	}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	want := "/v1beta/models/gemini-2.5-pro-should-win:generateContent"
	if mods.Path == nil || *mods.Path != want {
		t.Fatalf("expected the payload's model to win, path %q, got %v", want, mods.Path)
	}
}

func TestOnRequestBody_RejectsMissingFallbackModel(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{APIVersion: DefaultAPIVersion}}
	for _, body := range []string{
		`{"messages":[]}`,
		`{"model":"","messages":[]}`,
		`{"model":42,"messages":[]}`,
	} {
		action := p.OnRequestBody(context.Background(), &policy.RequestContext{
			SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
			Body:          &policy.Body{Present: true, Content: []byte(body)},
		}, nil)
		if response, ok := action.(policy.ImmediateResponse); !ok || response.StatusCode != 400 {
			t.Errorf("expected a 400 response for body %s, got %#v", body, action)
		}
	}
}

func TestBuildGeminiPath(t *testing.T) {
	if got := buildGeminiPath("v1beta", "gemini-2.5-flash", false); got != "/v1beta/models/gemini-2.5-flash:generateContent" {
		t.Errorf("non-streaming path wrong: %s", got)
	}
	got := buildGeminiPath("v1beta", "gemini-2.5-flash", true)
	if got != "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse" {
		t.Errorf("streaming path wrong: %s", got)
	}
}

func TestTranslateBody_ContentsAndSystem(t *testing.T) {
	payload := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "be brief"},
			map[string]interface{}{"role": "user", "content": "hi"},
		},
	}
	mods, err := translateBody(payload, "gemini-2.5-flash", PolicyParams{Model: "gemini-2.5-flash", APIVersion: "v1beta"}, false)
	if err != nil {
		t.Fatalf("translateBody failed: %v", err)
	}

	if mods.Path == nil || *mods.Path != "/v1beta/models/gemini-2.5-flash:generateContent" {
		t.Fatalf("unexpected path: %v", mods.Path)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	// System message must map to Gemini's systemInstruction, not contents.
	if body["systemInstruction"] == nil {
		t.Error("expected systemInstruction to be set from the system message")
	}
	contents, ok := body["contents"].([]interface{})
	if !ok || len(contents) == 0 {
		t.Fatalf("expected non-empty contents, got %v", body["contents"])
	}
	// OpenAI 'messages' must not leak through to the Gemini body.
	if _, leaked := body["messages"]; leaked {
		t.Error("OpenAI 'messages' must not appear in the Gemini body")
	}
}

func TestTranslateResponse_JSONShape(t *testing.T) {
	gemini := `{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi there"}]},` +
		`"finishReason":"STOP","index":0}],` +
		`"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":3,"totalTokenCount":8}}`
	action := translateResponse([]byte(gemini), 200, "gemini-2.5-flash")

	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(mods.Body, &out); err != nil {
		t.Fatalf("translated body not JSON: %v", err)
	}
	choices, _ := out["choices"].([]interface{})
	if len(choices) != 1 {
		t.Fatalf("expected 1 choice, got %v", out["choices"])
	}
	choice := choices[0].(map[string]interface{})
	msg := choice["message"].(map[string]interface{})
	if msg["content"] != "Hi there" {
		t.Errorf("unexpected content: %v", msg["content"])
	}
	if choice["finish_reason"] != "stop" {
		t.Errorf("expected finish_reason=stop, got %v", choice["finish_reason"])
	}
}
