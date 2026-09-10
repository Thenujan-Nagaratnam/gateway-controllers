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

package openaitobedrock

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestGetPolicy_ValidatesParams(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{}); err != nil {
		t.Fatalf("model override should be optional: %v", err)
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"model":      "us.amazon.nova-lite-v1:0",
		"providerId": "bedrock-provider",
	}); err != nil {
		t.Fatalf("unexpected error for valid params: %v", err)
	}
	for _, params := range []map[string]interface{}{
		{"model": 42},
		{"model": "nova", "providerId": true},
	} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Errorf("expected invalid params to fail: %#v", params)
		}
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
		RequestModel: requestModelConfig{Location: "payload", Identifier: "$.routing.modelName"},
	}}
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	req := &policy.RequestContext{
		SharedContext: shared,
		Body: &policy.Body{Present: true, Content: []byte(
			`{"routing":{"modelName":"anthropic.claude-via-custom-path"},"messages":[{"role":"user","content":"hello"}]}`)},
	}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	want := "/model/anthropic.claude-via-custom-path/converse"
	if mods.Path == nil || *mods.Path != want {
		t.Fatalf("expected the model read via requestModel's JSONPath, path %q, got %v", want, mods.Path)
	}
	if got := shared.Metadata[MetadataKeyEffectiveModel]; got != "anthropic.claude-via-custom-path" {
		t.Fatalf("effective model was not stored in request metadata: %v", got)
	}
}

func TestOnRequestBody_FallsBackToRequestModel(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{}}
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	req := &policy.RequestContext{
		SharedContext: shared,
		Body: &policy.Body{Present: true, Content: []byte(
			`{"model":"us.amazon.nova-lite-v1:0","messages":[{"role":"user","content":"hello"}]}`)},
	}

	action := p.OnRequestBody(context.Background(), req, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.Path == nil || *mods.Path != "/model/us.amazon.nova-lite-v1:0/converse" {
		t.Fatalf("unexpected fallback path: %v", mods.Path)
	}
	if got := shared.Metadata[MetadataKeyEffectiveModel]; got != "us.amazon.nova-lite-v1:0" {
		t.Fatalf("effective model was not stored in request metadata: %v", got)
	}

	response := &policy.ResponseContext{
		SharedContext:  shared,
		ResponseStatus: 200,
		ResponseBody: &policy.Body{Present: true, Content: []byte(
			`{"output":{"message":{"role":"assistant","content":[{"text":"hello"}]}},"stopReason":"end_turn"}`)},
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
	if translated["model"] != "us.amazon.nova-lite-v1:0" {
		t.Fatalf("response did not use the effective request model: %v", translated["model"])
	}
}

func TestOnRequestBody_PayloadModelWinsOverConfiguredModel(t *testing.T) {
	// Both a static model and the request body's own "model" are present -
	// the request-supplied one must win (e.g. so model-failover's own
	// per-fallback model reaches Bedrock instead of being silently ignored).
	p := &TranslatorPolicy{params: PolicyParams{Model: "us.amazon.nova-lite-v1:0"}}
	req := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Body: &policy.Body{Present: true, Content: []byte(
			`{"model":"anthropic.claude-3-5-sonnet-20241022-v2:0","messages":[{"role":"user","content":"hello"}]}`)},
	}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	want := "/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse"
	if mods.Path == nil || *mods.Path != want {
		t.Fatalf("expected the payload's model to win, path %q, got %v", want, mods.Path)
	}
}

func TestOnRequestBody_RejectsMissingFallbackModel(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{}}
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

func TestOnRequestBody_RewritesAndRoutes(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{
		Model:      "us.amazon.nova-lite-v1:0",
		ProviderID: "bedrock-provider",
	}}
	req := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Body: &policy.Body{Present: true, Content: []byte(
			`{"messages":[{"role":"user","content":"hello"}],"stream":true}`)},
	}
	action := p.OnRequestBody(context.Background(), req, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.Path == nil || *mods.Path != "/model/us.amazon.nova-lite-v1:0/converse-stream" {
		t.Fatalf("unexpected path: %v", mods.Path)
	}
	if mods.UpstreamName == nil || *mods.UpstreamName != "bedrock-provider" {
		t.Fatalf("unexpected upstream: %v", mods.UpstreamName)
	}

	req.SharedContext.Metadata[MetadataKeySelectedProvider] = "gemini-provider"
	action = p.OnRequestBody(context.Background(), req, nil)
	if skipped, ok := action.(policy.UpstreamRequestModifications); !ok || skipped.Body != nil {
		t.Fatalf("non-matching provider should be skipped, got %#v", action)
	}

	req.SharedContext.Metadata[MetadataKeySelectedProvider] = "BEDROCK-PROVIDER"
	if _, ok := p.OnRequestBody(context.Background(), req, nil).(policy.UpstreamRequestModifications); !ok {
		t.Fatal("provider selection should be case-insensitive")
	}
}

func TestOnRequestBody_RejectsBadBodies(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "nova"}}
	for _, body := range []*policy.Body{
		nil,
		{Present: true},
		{Present: true, Content: []byte(`{"messages":`)},
	} {
		action := p.OnRequestBody(context.Background(), &policy.RequestContext{
			SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
			Body:          body,
		}, nil)
		resp, ok := action.(policy.ImmediateResponse)
		if !ok || resp.StatusCode != 400 {
			t.Errorf("expected a 400 ImmediateResponse, got %#v", action)
		}
	}
}

func TestPolicyPhases_HandleNilSharedContext(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "nova"}}

	requestAction := p.OnRequestBody(context.Background(), &policy.RequestContext{
		Body: &policy.Body{Present: true, Content: []byte(`{"messages":[]}`)},
	}, nil)
	if _, ok := requestAction.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("request phase with nil SharedContext returned %T", requestAction)
	}

	if _, ok := p.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{}, nil).(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatal("response-header phase must handle nil SharedContext")
	}
	if _, ok := p.OnResponseBody(context.Background(), &policy.ResponseContext{}, nil).(policy.DownstreamResponseModifications); !ok {
		t.Fatal("response phase must handle nil SharedContext")
	}
	if _, ok := p.OnResponseBodyChunk(context.Background(), &policy.ResponseStreamContext{},
		&policy.StreamBody{EndOfStream: true}, nil).(policy.ForwardResponseChunk); !ok {
		t.Fatal("streaming response phase must handle nil SharedContext")
	}
}

// encodeFrame builds a synthetic Amazon event-stream frame the way Bedrock does:
// a :message-type=event and :event-type=<eventType> string header pair followed
// by the JSON payload. CRCs are zeroed — the decoder does not validate them.
func encodeFrame(eventType string, payload string) []byte {
	headers := encodeStringHeader(":event-type", eventType)
	headers = append(headers, encodeStringHeader(":message-type", "event")...)

	totalLen := 16 + len(headers) + len(payload)
	frame := make([]byte, 0, totalLen)
	frame = binary.BigEndian.AppendUint32(frame, uint32(totalLen))
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(headers)))
	frame = binary.BigEndian.AppendUint32(frame, 0) // prelude CRC (ignored)
	frame = append(frame, headers...)
	frame = append(frame, payload...)
	frame = binary.BigEndian.AppendUint32(frame, 0) // message CRC (ignored)
	return frame
}

func encodeStringHeader(name, value string) []byte {
	out := []byte{byte(len(name))}
	out = append(out, name...)
	out = append(out, headerTypeString)
	out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
	out = append(out, value...)
	return out
}

func encodeTypedHeader(name string, valueType byte, encodedValue []byte) []byte {
	out := []byte{byte(len(name))}
	out = append(out, name...)
	out = append(out, valueType)
	out = append(out, encodedValue...)
	return out
}

func TestParseHeaders_SkipsNonStringHeaders(t *testing.T) {
	byteArrayValue := binary.BigEndian.AppendUint16(nil, 2)
	byteArrayValue = append(byteArrayValue, 0xaa, 0xbb)

	tests := []struct {
		name         string
		valueType    byte
		encodedValue []byte
	}{
		{"true", headerTypeTrue, nil},
		{"false", headerTypeFalse, nil},
		{"byte", headerTypeByte, make([]byte, 1)},
		{"short", headerTypeShort, make([]byte, 2)},
		{"integer", headerTypeInteger, make([]byte, 4)},
		{"long", headerTypeLong, make([]byte, 8)},
		{"byte array", headerTypeByteArray, byteArrayValue},
		{"timestamp", headerTypeTimestamp, make([]byte, 8)},
		{"UUID", headerTypeUUID, make([]byte, 16)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headerBytes := encodeTypedHeader("ignored", tt.valueType, tt.encodedValue)
			headerBytes = append(headerBytes, encodeStringHeader(":event-type", "messageStart")...)

			if got := parseHeaders(headerBytes)[":event-type"]; got != "messageStart" {
				t.Fatalf("event type after %s header = %q, want messageStart", tt.name, got)
			}
		})
	}
}

func bedrockStream() []byte {
	var stream []byte
	stream = append(stream, encodeFrame("messageStart", `{"role":"assistant"}`)...)
	stream = append(stream, encodeFrame("contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"Hello"}}`)...)
	stream = append(stream, encodeFrame("contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":" world"}}`)...)
	stream = append(stream, encodeFrame("messageStop", `{"stopReason":"end_turn"}`)...)
	stream = append(stream, encodeFrame("metadata", `{"usage":{"inputTokens":10,"outputTokens":2,"totalTokens":12,"cacheReadInputTokens":4,"cacheWriteInputTokens":6,"cacheDetails":[{"ttl":"1h","inputTokens":4},{"ttl":"5m","inputTokens":2}]}}`)...)
	return stream
}

func TestEventStreamToSSE_TextStream(t *testing.T) {
	out := string(eventStreamToSSE(bedrockStream(), true, "chatcmpl-test", "claude"))

	for _, want := range []string{
		`"delta":{"role":"assistant"}`,
		`"content":"Hello"`,
		`"content":" world"`,
		`"finish_reason":"stop"`,
		`"prompt_tokens":20`,
		`"total_tokens":22`,
		`"cached_tokens":4`,
		`"cache_write_tokens":6`,
		`"cache_write_5m_tokens":2`,
		`"cache_write_1h_tokens":4`,
		"data: [DONE]\n\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("SSE output missing %q\n---\n%s", want, out)
		}
	}
	// Every non-terminal event must be framed as an SSE data line.
	if !strings.HasPrefix(out, "data: ") {
		t.Errorf("SSE output must start with a data line, got:\n%s", out)
	}
}

func TestEventStreamToSSE_PreservesNonEventStreamData(t *testing.T) {
	data := []byte(`{"message":"upstream error"}`)

	if got := eventStreamToSSE(data, false, "id", "claude"); string(got) != string(data) {
		t.Fatalf("non-event-stream data = %q, want %q", got, data)
	}

	wantAtEnd := append(append([]byte{}, data...), sseDonePayload...)
	if got := eventStreamToSSE(data, true, "id", "claude"); string(got) != string(wantAtEnd) {
		t.Fatalf("final non-event-stream data = %q, want %q", got, wantAtEnd)
	}
}

// TestEventStreamToSSE_SplitFrames verifies that feeding the stream in
// arbitrarily split pieces, using eventStreamBoundary to only decode whole
// frames per flush (as the kernel does), reproduces the same SSE stream.
func TestEventStreamToSSE_SplitFrames(t *testing.T) {
	full := bedrockStream()
	whole := string(eventStreamToSSE(full, true, "id", "claude"))

	var assembled strings.Builder
	var acc []byte
	for i := 0; i < len(full); i++ {
		acc = append(acc, full[i])
		completeLen, hasPartial, ok := eventStreamBoundary(acc)
		if !ok {
			t.Fatalf("boundary check reported non-event-stream data at byte %d", i)
		}
		last := i == len(full)-1
		// Flush only on a clean boundary (mirrors NeedsMoreResponseData==false)
		// or at end of stream.
		if (!hasPartial && completeLen == len(acc) && completeLen > 0) || last {
			assembled.Write(eventStreamToSSE(acc, last, "id", "claude"))
			acc = nil
		}
	}

	if assembled.String() != whole {
		t.Errorf("split-frame SSE differs from whole-stream SSE\nsplit:\n%s\nwhole:\n%s", assembled.String(), whole)
	}
}

func TestNeedsMoreResponseData_Boundaries(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{Model: "claude"}}
	frame := encodeFrame("messageStop", `{"stopReason":"end_turn"}`)

	if p.NeedsMoreResponseData(frame) {
		t.Error("a complete frame should not request more data")
	}
	if !p.NeedsMoreResponseData(frame[:len(frame)-3]) {
		t.Error("a truncated frame should request more data")
	}
	if p.NeedsMoreResponseData(nil) {
		t.Error("empty accumulator should not request more data")
	}
}

func TestTranslateRequest_ConverseShape(t *testing.T) {
	payload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "be brief"},
			map[string]interface{}{"role": "user", "content": "hi"},
		},
		"max_tokens":  100,
		"temperature": 0.5,
	}
	mods := translateRequest(payload)

	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if _, hasModel := body["model"]; hasModel {
		t.Error("Converse body must not contain 'model' (it lives in the path)")
	}
	system, ok := body["system"].([]interface{})
	if !ok || len(system) != 1 {
		t.Fatalf("expected 1 system block, got %v", body["system"])
	}
	inference, ok := body["inferenceConfig"].(map[string]interface{})
	if !ok || inference["maxTokens"] == nil {
		t.Fatalf("expected inferenceConfig.maxTokens, got %v", body["inferenceConfig"])
	}
	if p := bedrockConversePath("claude", true); p != "/model/claude/converse-stream" {
		t.Errorf("unexpected streaming path: %s", p)
	}
}

func TestTranslateRequest_OmitsMaxTokensWhenNotSupplied(t *testing.T) {
	payload := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "hi"},
		},
	}
	mods := translateRequest(payload)

	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if _, ok := body["inferenceConfig"]; ok {
		t.Fatalf("inferenceConfig must be omitted when the OpenAI payload has no inference settings: %v", body)
	}
}

func TestTranslateRequest_ToolsImagesAndResults(t *testing.T) {
	payload := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": []interface{}{
				map[string]interface{}{"type": "text", "text": "describe"},
				map[string]interface{}{"type": "image_url", "image_url": map[string]interface{}{
					"url": "data:image/png;base64,aGVsbG8=",
				}},
			}},
			map[string]interface{}{"role": "assistant", "tool_calls": []interface{}{
				map[string]interface{}{"id": "call-1", "function": map[string]interface{}{
					"name": "weather", "arguments": `{"city":"Colombo"}`,
				}},
			}},
			map[string]interface{}{"role": "tool", "tool_call_id": "call-1", "content": "sunny"},
		},
		"tools": []interface{}{map[string]interface{}{
			"type": "function",
			"function": map[string]interface{}{
				"name": "weather", "parameters": map[string]interface{}{"type": "object"},
			},
		}},
		"tool_choice": map[string]interface{}{
			"type": "function", "function": map[string]interface{}{"name": "weather"},
		},
	}
	mods := translateRequest(payload)
	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatalf("translated body is invalid: %v", err)
	}
	messages, _ := body["messages"].([]interface{})
	if len(messages) != 3 {
		t.Fatalf("expected user, assistant, and grouped tool-result messages, got %v", body["messages"])
	}
	toolConfig, _ := body["toolConfig"].(map[string]interface{})
	if toolConfig == nil || toolConfig["toolChoice"] == nil {
		t.Fatalf("expected translated tool configuration, got %v", body["toolConfig"])
	}
}

func TestTranslateRequest_ToolChoiceNoneDropsTools(t *testing.T) {
	payload := map[string]interface{}{
		"tools": []interface{}{map[string]interface{}{
			"function": map[string]interface{}{"name": "weather"},
		}},
		"tool_choice": "none",
	}
	mods := translateRequest(payload)
	var body map[string]interface{}
	if err := json.Unmarshal(mods.Body, &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["toolConfig"]; ok {
		t.Fatalf("tool_choice=none must omit toolConfig: %v", body)
	}
}

func TestTranslateConverseResponse_JSON(t *testing.T) {
	converse := `{"output":{"message":{"role":"assistant","content":[{"text":"Hi there"}]}},` +
		`"stopReason":"end_turn","usage":{"inputTokens":5,"outputTokens":3,"totalTokens":8,` +
		`"cacheReadInputTokens":4,"cacheWriteInputTokens":6,"cacheDetails":[` +
		`{"ttl":"1h","inputTokens":4},{"ttl":"5m","inputTokens":2}]}}`
	action := translateConverseResponse([]byte(converse), 200, "claude", "chatcmpl-x")

	mods, ok := action.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %T", action)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(mods.Body, &out); err != nil {
		t.Fatalf("translated body not JSON: %v", err)
	}
	if out["object"] != objectChatCompletion {
		t.Errorf("expected object=chat.completion, got %v", out["object"])
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
		t.Errorf("unexpected finish_reason: %v", choice["finish_reason"])
	}
	usage := out["usage"].(map[string]interface{})
	if usage["prompt_tokens"] != float64(15) || usage["total_tokens"] != float64(18) {
		t.Fatalf("translated usage does not include cache tokens: %v", usage)
	}
	details := usage["prompt_tokens_details"].(map[string]interface{})
	if details["cached_tokens"] != float64(4) || details["cache_write_tokens"] != float64(6) ||
		details["cache_write_5m_tokens"] != float64(2) ||
		details["cache_write_1h_tokens"] != float64(4) {
		t.Fatalf("translated cache token details are incomplete: %v", details)
	}
}

func TestTranslateConverseResponse_ToolCallAndError(t *testing.T) {
	converse := `{"output":{"message":{"role":"assistant","content":[` +
		`{"toolUse":{"toolUseId":"call-1","name":"weather","input":{"city":"Colombo"}}}` +
		`]}},"stopReason":"tool_use","usage":{"inputTokens":5,"outputTokens":3}}`
	action := translateConverseResponse([]byte(converse), 200, "nova", "chatcmpl-x")
	mods := action.(policy.DownstreamResponseModifications)
	var out map[string]interface{}
	if err := json.Unmarshal(mods.Body, &out); err != nil {
		t.Fatal(err)
	}
	choice := out["choices"].([]interface{})[0].(map[string]interface{})
	if choice["finish_reason"] != "tool_calls" {
		t.Fatalf("unexpected finish reason: %v", choice["finish_reason"])
	}
	message := choice["message"].(map[string]interface{})
	if len(message["tool_calls"].([]interface{})) != 1 {
		t.Fatalf("expected one tool call: %v", message)
	}
	usage := out["usage"].(map[string]interface{})
	if usage["total_tokens"] != float64(8) {
		t.Fatalf("expected computed total tokens, got %v", usage)
	}

	errorAction := translateConverseResponse([]byte(`{"message":"quota exceeded"}`), 429, "nova", "id")
	errorMods := errorAction.(policy.DownstreamResponseModifications)
	var errorBody map[string]interface{}
	if err := json.Unmarshal(errorMods.Body, &errorBody); err != nil {
		t.Fatal(err)
	}
	errValue := errorBody["error"].(map[string]interface{})
	if errValue["type"] != "rate_limit_error" || errValue["message"] != "quota exceeded" {
		t.Fatalf("unexpected translated error: %v", errValue)
	}
}

func TestStopReasonToFinish_KnownReasonsPrecedeToolFallback(t *testing.T) {
	tests := []struct {
		name         string
		stopReason   string
		hasToolCalls bool
		want         string
	}{
		{name: "truncated tool call", stopReason: "max_tokens", hasToolCalls: true, want: "length"},
		{name: "filtered tool call", stopReason: "content_filtered", hasToolCalls: true, want: "content_filter"},
		{name: "guardrail tool call", stopReason: "guardrail_intervened", hasToolCalls: true, want: "content_filter"},
		{name: "explicit tool use", stopReason: "tool_use", hasToolCalls: true, want: "tool_calls"},
		{name: "unknown reason with tools", stopReason: "", hasToolCalls: true, want: "tool_calls"},
		{name: "unknown reason without tools", stopReason: "", hasToolCalls: false, want: "stop"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stopReasonToFinish(tt.stopReason, tt.hasToolCalls); got != tt.want {
				t.Fatalf("stopReasonToFinish(%q, %v) = %q, want %q",
					tt.stopReason, tt.hasToolCalls, got, tt.want)
			}
		})
	}
}

func TestEventStreamToSSE_ToolCall(t *testing.T) {
	stream := encodeFrame("contentBlockStart", `{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"call-1","name":"weather"}}}`)
	stream = append(stream, encodeFrame("contentBlockDelta", `{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"city\":\"Colombo\"}"}}}`)...)
	out := string(eventStreamToSSE(stream, true, "chatcmpl-x", "nova"))
	for _, want := range []string{`"id":"call-1"`, `"name":"weather"`, `"arguments":"{\"city\":\"Colombo\"}"`, "data: [DONE]"} {
		if !strings.Contains(out, want) {
			t.Errorf("tool-call stream missing %q: %s", want, out)
		}
	}
}

func TestDecodeEventStreamFrames_MalformedInput(t *testing.T) {
	if _, _, ok := decodeEventStreamFrames([]byte("not an event stream")); ok {
		t.Fatal("plain text must not be accepted as event-stream framing")
	}
	malformed := make([]byte, preludeWithCRCLen)
	binary.BigEndian.PutUint32(malformed[:4], uint32(maxFrameLen+1))
	if _, _, ok := decodeEventStreamFrames(malformed); ok {
		t.Fatal("oversized frames must be rejected")
	}
}
