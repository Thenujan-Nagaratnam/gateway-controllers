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

// Package openaitobedrock translates OpenAI Chat Completions traffic to and
// from the AWS Bedrock Converse API. Requests are rewritten to the Converse
// wire format (path + body); responses are rewritten back to OpenAI shape.
// Bedrock streams responses with the binary Amazon event-stream framing, which
// this policy decodes and re-emits as OpenAI-style Server-Sent Events.
package openaitobedrock

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	PolicyName                  = "openai-to-bedrock-transformer"
	MetadataKeySelectedProvider = "selected_provider"
	MetadataKeyEffectiveModel   = "openai_to_bedrock_effective_model"
)

// Compile-time proof that this policy participates in every phase it declares
// in Mode(), including chunk-by-chunk response streaming.
var (
	_ policy.Policy                  = (*TranslatorPolicy)(nil)
	_ policy.RequestPolicy           = (*TranslatorPolicy)(nil)
	_ policy.ResponseHeaderPolicy    = (*TranslatorPolicy)(nil)
	_ policy.ResponsePolicy          = (*TranslatorPolicy)(nil)
	_ policy.StreamingResponsePolicy = (*TranslatorPolicy)(nil)
)

type PolicyParams struct {
	Model      string
	ProviderID string
	// RequestModel identifies where the client's own model lives in the
	// request body — a systemParameter gateway-controller injects from the
	// PROXY's OWN (primary provider's) template, never the additional
	// provider's, since that's the one location the client actually sends
	// its model in, regardless of which provider ends up handling the
	// request (see resolveModel). Zero value (Location == "") means it
	// wasn't injected (e.g. this policy attached outside gateway-controller,
	// or an older build) — resolveModel falls back to a plain top-level
	// "model" lookup in that case.
	RequestModel requestModelConfig
}

// requestModelConfig mirrors the convention model-failover/model-round-robin/
// model-weighted-round-robin already use for the same systemParameter — see
// their own requestmodel.go. This transformer only ever reads the client's
// model out of the JSON body it's about to translate (never a header/query/
// path), so only "payload" is a meaningful location here; anything else is a
// config error caught at parse time.
type requestModelConfig struct {
	Location   string
	Identifier string
}

type TranslatorPolicy struct {
	params PolicyParams
}

// GetPolicy is the exported factory the gateway calls to instantiate the policy.
func GetPolicy(_ policy.PolicyMetadata, rawParams map[string]interface{}) (policy.Policy, error) {
	parsed, err := parseParams(rawParams)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid params: %w", PolicyName, err)
	}
	return &TranslatorPolicy{params: parsed}, nil
}

// Mode buffers the (small) request body for translation, processes response
// headers so streaming content-type can be corrected, and asks for STREAM mode
// on the response body so Bedrock's event stream can be decoded chunk-by-chunk.
// The kernel falls back to the buffered OnResponseBody path automatically when
// the upstream response is not a stream.
func (p *TranslatorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// ─── Request phase ────────────────────────────────────────────────────────────

func (p *TranslatorPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if !p.shouldRun(selectedProvider(reqCtx.SharedContext)) {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Body == nil || !reqCtx.Body.Present || len(reqCtx.Body.Content) == 0 {
		return errResponse(400, "Request body is empty.")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		return errResponse(400, fmt.Sprintf("Invalid JSON in request body: %s", err.Error()))
	}

	model, err := p.resolveModel(reqCtx.Body.Content, payload)
	if err != nil {
		return errResponse(400, err.Error())
	}
	storeEffectiveModel(reqCtx.SharedContext, model)

	streaming := boolValue(payload["stream"])
	path := bedrockConversePath(model, streaming)
	slog.Debug(PolicyName+": translating request",
		"providerId", p.params.ProviderID, "model", model, "streaming", streaming, "path", path)

	mods := translateRequest(payload)
	mods.Path = &path
	if p.params.ProviderID != "" && mods.UpstreamName == nil {
		upstream := p.params.ProviderID
		mods.UpstreamName = &upstream
	}
	return mods
}

// bedrockConversePath builds the Converse endpoint path. The model id carries
// the model selection (the awsbedrock provider template extracts it from the
// path), so it is never placed in the body.
func bedrockConversePath(model string, streaming bool) string {
	if streaming {
		return "/model/" + model + "/converse-stream"
	}
	return "/model/" + model + "/converse"
}

// ─── Response phase ───────────────────────────────────────────────────────────

// OnResponseHeaders rewrites the upstream content-type for translated event
// streams (application/vnd.amazon.eventstream) to text/event-stream so
// downstream OpenAI clients recognise the Server-Sent Events we emit. JSON
// responses are left untouched.
func (p *TranslatorPolicy) OnResponseHeaders(
	_ context.Context,
	respCtx *policy.ResponseHeaderContext,
	_ map[string]interface{},
) policy.ResponseHeaderAction {
	if !p.shouldRun(selectedProvider(respCtx.SharedContext)) {
		return policy.DownstreamResponseHeaderModifications{}
	}
	if !isEventStreamContentType(headerValue(respCtx.ResponseHeaders, "content-type")) {
		return policy.DownstreamResponseHeaderModifications{}
	}
	return policy.DownstreamResponseHeaderModifications{
		HeadersToSet:    map[string]string{"content-type": "text/event-stream"},
		HeadersToRemove: []string{"content-length"},
	}
}

// OnResponseBody is the buffered fallback used when the upstream response is not
// detected as a stream (no chunked / text-event-stream headers). It handles both
// a Converse JSON response and a fully buffered Amazon event stream.
func (p *TranslatorPolicy) OnResponseBody(
	_ context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	if !p.shouldRun(selectedProvider(respCtx.SharedContext)) {
		return policy.DownstreamResponseModifications{}
	}
	if respCtx.ResponseBody == nil || !respCtx.ResponseBody.Present || len(respCtx.ResponseBody.Content) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	body := respCtx.ResponseBody.Content
	contentType := headerValue(respCtx.ResponseHeaders, "content-type")
	model := effectiveModel(respCtx.SharedContext, p.params.Model)

	if isEventStreamContentType(contentType) || looksLikeEventStream(body) {
		sse := eventStreamToSSE(body, true, p.completionID(requestID(respCtx.SharedContext)), model)
		return policy.DownstreamResponseModifications{
			Body: sse,
			HeadersToSet: map[string]string{
				"content-type": "text/event-stream",
			},
			HeadersToRemove: []string{"content-length"},
		}
	}

	slog.Debug(PolicyName+": translating buffered JSON response", "status", respCtx.ResponseStatus)
	return translateConverseResponse(body, respCtx.ResponseStatus, model,
		p.completionID(requestID(respCtx.SharedContext)))
}

// ─── Streaming response phase ─────────────────────────────────────────────────

// NeedsMoreResponseData keeps the kernel accumulating until its buffer ends on a
// clean event-stream frame boundary. That guarantees OnResponseBodyChunk always
// receives a whole number of complete frames and never a split one, so no
// cross-chunk carry buffer (which would be unsafe on a shared policy instance)
// is required.
func (p *TranslatorPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if len(accumulated) == 0 {
		return false
	}
	_, hasPartial, ok := eventStreamBoundary(accumulated)
	if !ok {
		// Not event-stream framing (e.g. a JSON error body streamed through) —
		// don't stall the stream waiting for a boundary that will never come.
		return false
	}
	return hasPartial
}

// OnResponseBodyChunk decodes the complete frames delivered in this flush and
// re-emits them as OpenAI SSE events, replacing the raw binary bytes. On the
// final chunk it appends the terminating `data: [DONE]` event.
func (p *TranslatorPolicy) OnResponseBodyChunk(
	_ context.Context,
	respCtx *policy.ResponseStreamContext,
	chunk *policy.StreamBody,
	_ map[string]interface{},
) policy.StreamingResponseAction {
	if !p.shouldRun(selectedProvider(respCtx.SharedContext)) {
		return policy.ForwardResponseChunk{}
	}

	model := effectiveModel(respCtx.SharedContext, p.params.Model)
	sse := eventStreamToSSE(chunk.Chunk, chunk.EndOfStream,
		p.completionID(requestID(respCtx.SharedContext)), model)
	// Always return a non-nil body so the raw Amazon event-stream bytes are
	// replaced (nil would pass them through untranslated). An empty slice emits
	// nothing for this flush, which is correct when a frame carried no delta.
	if sse == nil {
		sse = []byte{}
	}
	return policy.ForwardResponseChunk{Body: sse}
}

// ─── Routing / selection ──────────────────────────────────────────────────────

func (p *TranslatorPolicy) shouldRun(selected string) bool {
	if selected == "" {
		// Single-provider mode: no router selected a provider, so run.
		return true
	}
	return strings.EqualFold(selected, p.params.ProviderID)
}

func selectedProvider(shared *policy.SharedContext) string {
	if shared == nil || shared.Metadata == nil {
		return ""
	}
	raw, ok := shared.Metadata[MetadataKeySelectedProvider]
	if !ok {
		return ""
	}
	value, isString := raw.(string)
	if !isString {
		return ""
	}
	return strings.TrimSpace(value)
}

// resolveModel prefers the request body's own model field — so a caller, or
// an upstream policy rewriting it per attempt (e.g. model-failover's
// per-fallback model on a cross-provider self-redial), always wins — and
// falls back to the operator's statically configured model only when the
// payload doesn't carry one.
//
// When p.params.RequestModel is set (gateway-controller injected it from the
// PROXY's own template), the client's model is read via JSONPath at
// RequestModel.Identifier against the raw body, exactly like the template
// says. Absent that (this policy attached outside gateway-controller, or an
// older build with no such injection), falls back to a plain top-level
// "model" field lookup — every current built-in template resolves to that
// same shape anyway, so this is never a behavior change for the common case,
// only a safety net.
func (p *TranslatorPolicy) resolveModel(bodyBytes []byte, payload map[string]interface{}) (string, error) {
	if p.params.RequestModel.Location == "payload" {
		if val, err := utils.ExtractStringValueFromJsonpath(bodyBytes, p.params.RequestModel.Identifier); err == nil {
			if val = strings.TrimSpace(val); val != "" {
				return val, nil
			}
		}
	} else if raw, ok := payload["model"]; ok && raw != nil {
		if model, ok := raw.(string); ok {
			if model = strings.TrimSpace(model); model != "" {
				return model, nil
			}
		}
		// A present-but-malformed payload "model" (wrong type, blank) falls
		// through to the configured fallback below rather than erroring
		// immediately - consistent with every other transformer's
		// resolveModel-style helper.
	}

	if p.params.Model != "" {
		return p.params.Model, nil
	}

	return "", fmt.Errorf("a Bedrock model must be provided in either the policy configuration or request body")
}

func storeEffectiveModel(shared *policy.SharedContext, model string) {
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = map[string]interface{}{}
	}
	shared.Metadata[MetadataKeyEffectiveModel] = model
}

func effectiveModel(shared *policy.SharedContext, configured string) string {
	if shared != nil && shared.Metadata != nil {
		if model, ok := shared.Metadata[MetadataKeyEffectiveModel].(string); ok && model != "" {
			return model
		}
	}
	return configured
}

func requestID(shared *policy.SharedContext) string {
	if shared == nil {
		return ""
	}
	return shared.RequestID
}

// completionID derives a stable OpenAI completion id from the per-request id so
// every SSE chunk of one response shares it, without holding per-request state
// on the shared policy instance. Falls back to a random id when unavailable.
func (p *TranslatorPolicy) completionID(requestID string) string {
	if requestID != "" {
		return "chatcmpl-" + strings.ReplaceAll(requestID, "-", "")
	}
	return newChatCompletionID()
}

// ─── Param parsing ────────────────────────────────────────────────────────────

func parseParams(params map[string]interface{}) (PolicyParams, error) {
	result := PolicyParams{}

	model, err := optionalString(params, "model")
	if err != nil {
		return result, err
	}
	result.Model = model

	if providerID, err := optionalString(params, "providerId"); err != nil {
		return result, err
	} else {
		result.ProviderID = providerID
	}

	requestModel, err := parseRequestModelConfig(params)
	if err != nil {
		return result, err
	}
	result.RequestModel = requestModel

	return result, nil
}

func optionalString(params map[string]interface{}, key string) (string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return "", nil
	}
	value, isString := raw.(string)
	if !isString {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	return strings.TrimSpace(value), nil
}

// parseRequestModelConfig parses the optional 'requestModel' systemParameter
// (see PolicyParams.RequestModel's own doc). Absent entirely is valid — the
// zero value signals resolveModel to use its own fallback. Present-but-
// malformed is a config error: gateway-controller injecting a location this
// transformer can't act on (i.e. anything but "payload") means something is
// misconfigured upstream, not a case to silently ignore.
func parseRequestModelConfig(params map[string]interface{}) (requestModelConfig, error) {
	raw, ok := params["requestModel"]
	if !ok || raw == nil {
		return requestModelConfig{}, nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return requestModelConfig{}, fmt.Errorf("'requestModel' must be an object")
	}
	location, err := optionalString(m, "location")
	if err != nil {
		return requestModelConfig{}, err
	}
	identifier, err := optionalString(m, "identifier")
	if err != nil {
		return requestModelConfig{}, err
	}
	if location == "" && identifier == "" {
		return requestModelConfig{}, nil
	}
	if location != "payload" {
		return requestModelConfig{}, fmt.Errorf("'requestModel.location' must be \"payload\" for %s (the client's model is always read from the JSON body being translated), got %q", PolicyName, location)
	}
	if identifier == "" {
		return requestModelConfig{}, fmt.Errorf("'requestModel.identifier' is required when requestModel is set")
	}
	return requestModelConfig{Location: location, Identifier: identifier}, nil
}

func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) {
			return 0, false
		}
		return int(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i), true
		}
	}
	return 0, false
}

func boolValue(v interface{}) bool {
	b, ok := v.(bool)
	return ok && b
}

func headerValue(headers *policy.Headers, name string) string {
	if headers == nil {
		return ""
	}
	values := headers.Get(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func isEventStreamContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "vnd.amazon.eventstream") || strings.Contains(ct, "application/octet-stream")
}

// looksLikeEventStream sniffs a buffered body for Amazon event-stream framing:
// binary (not starting with a JSON delimiter) whose leading 4 bytes advertise a
// plausible frame length.
func looksLikeEventStream(body []byte) bool {
	if len(body) < preludeWithCRCLen {
		return false
	}
	trimmed := strings.TrimLeft(string(body[:1]), " \r\n\t")
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return false
	}
	_, _, ok := eventStreamBoundary(body)
	return ok
}

func errResponse(statusCode int, message string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]interface{}{
		"error": map[string]string{"message": message, "type": "invalid_request_error"},
	})
	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}
