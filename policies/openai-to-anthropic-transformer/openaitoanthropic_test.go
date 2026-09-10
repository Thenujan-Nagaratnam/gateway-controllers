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

package openaitoanthropic

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
		"model": "claude", "providerId": "anthropic-provider",
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

	// Absent entirely is valid - resolveModel falls back to its own default.
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{}); err != nil {
		t.Fatalf("requestModel should be optional: %v", err)
	}

	// A location this transformer can't act on (it only ever reads the JSON
	// body it's translating) is a config error, not silently ignored.
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
		AnthropicVersion: DefaultAnthropicVersion,
		RequestModel:     requestModelConfig{Location: "payload", Identifier: "$.routing.modelName"},
	}}
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	req := &policy.RequestContext{
		SharedContext: shared,
		Body: &policy.Body{Present: true, Content: []byte(
			`{"routing":{"modelName":"claude-3-opus-via-custom-path"},"messages":[{"role":"user","content":"hi"}]}`)},
	}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	var sentBody map[string]interface{}
	if err := json.Unmarshal(mods.Body, &sentBody); err != nil {
		t.Fatalf("translated body is not valid JSON: %v", err)
	}
	if sentBody["model"] != "claude-3-opus-via-custom-path" {
		t.Fatalf("expected the model read via requestModel's JSONPath, got %v", sentBody["model"])
	}
	if got := shared.Metadata[MetadataKeyEffectiveModel]; got != "claude-3-opus-via-custom-path" {
		t.Fatalf("effective model was not stored in request metadata: %v", got)
	}
}

func TestOnRequestBody_FallsBackToRequestModel(t *testing.T) {
	// No configured model at all - the request body's own "model" field must
	// carry it through translation and back out into the OpenAI-shaped
	// response, via the per-request SharedContext (never p.params.Model,
	// which stays empty for the life of this shared policy instance).
	p := &TranslatorPolicy{params: PolicyParams{AnthropicVersion: DefaultAnthropicVersion}}
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	req := &policy.RequestContext{
		SharedContext: shared,
		Body: &policy.Body{Present: true, Content: []byte(
			`{"model":"claude-3-opus-from-payload","messages":[{"role":"user","content":"hi"}]}`)},
	}

	action := p.OnRequestBody(context.Background(), req, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	var sentBody map[string]interface{}
	if err := json.Unmarshal(mods.Body, &sentBody); err != nil {
		t.Fatalf("translated body is not valid JSON: %v", err)
	}
	if sentBody["model"] != "claude-3-opus-from-payload" {
		t.Fatalf("expected the payload's own model, got %v", sentBody["model"])
	}
	if got := shared.Metadata[MetadataKeyEffectiveModel]; got != "claude-3-opus-from-payload" {
		t.Fatalf("effective model was not stored in request metadata: %v", got)
	}

	response := &policy.ResponseContext{
		SharedContext:  shared,
		ResponseStatus: 200,
		// Deliberately omits its own "model" field - forces translateResponse
		// to fall back to the resolved effective model, not p.params.Model.
		ResponseBody: &policy.Body{Present: true, Content: []byte(
			`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)},
	}
	responseAction := p.OnResponseBody(context.Background(), response, nil)
	responseMods, ok := responseAction.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", responseAction)
	}
	var translated map[string]interface{}
	if err := json.Unmarshal(responseMods.Body, &translated); err != nil {
		t.Fatalf("translated response is not valid JSON: %v", err)
	}
	if translated["model"] != "claude-3-opus-from-payload" {
		t.Fatalf("response did not use the effective request model: %v", translated["model"])
	}
}

func TestOnRequestBody_PayloadModelWinsOverConfiguredModel(t *testing.T) {
	// A statically configured model is now only a fallback default - a
	// request-supplied model must override it, e.g. so model-failover's own
	// per-fallback model reaches Anthropic instead of being silently ignored.
	p := &TranslatorPolicy{params: PolicyParams{AnthropicVersion: DefaultAnthropicVersion, Model: "claude-sonnet-4-5-20250929"}}
	req := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Body: &policy.Body{Present: true, Content: []byte(
			`{"model":"claude-3-opus-should-win","messages":[{"role":"user","content":"hi"}]}`)},
	}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	var sentBody map[string]interface{}
	if err := json.Unmarshal(mods.Body, &sentBody); err != nil {
		t.Fatalf("translated body is not valid JSON: %v", err)
	}
	if sentBody["model"] != "claude-3-opus-should-win" {
		t.Fatalf("expected the payload's model to win over the configured one, got %v", sentBody["model"])
	}
}

func TestOnRequestBody_RejectsMissingFallbackModel(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{AnthropicVersion: DefaultAnthropicVersion}}
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

func TestTranslateBody_MessagesShape(t *testing.T) {
	payload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "be brief"},
			map[string]interface{}{"role": "user", "content": "hi"},
		},
		"temperature": 0.5,
	}
	mods, err := translateBody(payload, "claude", PolicyParams{Model: "claude", AnthropicVersion: DefaultAnthropicVersion})
	if err != nil {
		t.Fatalf("translateBody failed: %v", err)
	}

	if mods.Path == nil || *mods.Path != AnthropicMessagesPath {
		t.Fatalf("expected path %q, got %v", AnthropicMessagesPath, mods.Path)
	}
	if mods.HeadersToSet["anthropic-version"] != DefaultAnthropicVersion {
		t.Errorf("expected anthropic-version header, got %v", mods.HeadersToSet)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if body["model"] != "claude" {
		t.Errorf("expected model=claude, got %v", body["model"])
	}
	if body["system"] != "be brief" {
		t.Errorf("expected system text extracted, got %v", body["system"])
	}
	// Anthropic requires max_tokens — the translator must inject the default.
	if body["max_tokens"] == nil {
		t.Error("expected max_tokens to be set (Anthropic requires it)")
	}
	msgs, ok := body["messages"].([]interface{})
	if !ok || len(msgs) != 1 {
		t.Fatalf("expected 1 non-system message, got %v", body["messages"])
	}
	if first := msgs[0].(map[string]interface{}); first["role"] != "user" {
		t.Errorf("expected first message role=user, got %v", first["role"])
	}
}

func TestTranslateBody_ToolsConverted(t *testing.T) {
	payload := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "weather?"},
		},
		"tools": []interface{}{
			map[string]interface{}{
				"type": "function",
				"function": map[string]interface{}{
					"name":        "get_weather",
					"description": "Get weather",
					"parameters":  map[string]interface{}{"type": "object"},
				},
			},
		},
	}
	mods, err := translateBody(payload, "claude", PolicyParams{Model: "claude"})
	if err != nil {
		t.Fatalf("translateBody failed: %v", err)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	tools, ok := body["tools"].([]interface{})
	if !ok || len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %v", body["tools"])
	}
	tool := tools[0].(map[string]interface{})
	if tool["name"] != "get_weather" {
		t.Errorf("expected tool name=get_weather, got %v", tool["name"])
	}
	// OpenAI's "parameters" must be remapped to Anthropic's "input_schema".
	if tool["input_schema"] == nil {
		t.Errorf("expected input_schema on the converted tool, got %v", tool)
	}
}

func TestTranslateBody_ToolChoiceNoneDropsTools(t *testing.T) {
	payload := map[string]interface{}{
		"messages": []interface{}{map[string]interface{}{"role": "user", "content": "hi"}},
		"tools": []interface{}{
			map[string]interface{}{"type": "function", "function": map[string]interface{}{"name": "f"}},
		},
		"tool_choice": "none",
	}
	mods, err := translateBody(payload, "claude", PolicyParams{Model: "claude"})
	if err != nil {
		t.Fatalf("translateBody failed: %v", err)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if _, hasTools := body["tools"]; hasTools {
		t.Error("tool_choice=none must drop tools entirely (no Anthropic negative form)")
	}
}

func TestTranslateResponse_JSONShape(t *testing.T) {
	anthropic := `{"id":"msg_1","type":"message","role":"assistant",` +
		`"content":[{"type":"text","text":"Hi there"}],` +
		`"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":3}}`
	action := translateResponse([]byte(anthropic), 200, "claude")

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

// TestConvertUserContent_MalformedBlocks ensures content blocks with a missing
// or non-string "type" are skipped rather than panicking — the block list comes
// straight from an untrusted request body.
func TestConvertUserContent_MalformedBlocks(t *testing.T) {
	content := []interface{}{
		map[string]interface{}{"text": "no type field"},
		map[string]interface{}{"type": 42, "text": "non-string type"},
		"not an object",
		map[string]interface{}{"type": "text", "text": "valid"},
	}
	result := convertUserContent(content)

	blocks, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", result)
	}
	if len(blocks) != 1 {
		t.Fatalf("expected only the 1 valid block to survive, got %d: %v", len(blocks), blocks)
	}
	if block := blocks[0].(map[string]interface{}); block["text"] != "valid" {
		t.Errorf("unexpected surviving block: %v", block)
	}
}

// TestLooksLikeSSE distinguishes streaming SSE bodies (passed through
// untouched, since translating SSE needs a stateful chunk-level policy) from
// JSON bodies (translated to OpenAI shape).
func TestLooksLikeSSE(t *testing.T) {
	sse := []byte("event: message_start\ndata: {\"type\":\"message_start\"}\n\n")
	if !looksLikeSSE(sse) {
		t.Error("expected an event-stream body to be detected as SSE")
	}
	jsonBody := []byte(`{"id":"msg_1","content":[{"type":"text","text":"hi"}]}`)
	if looksLikeSSE(jsonBody) {
		t.Error("expected a JSON body not to be detected as SSE")
	}
}
