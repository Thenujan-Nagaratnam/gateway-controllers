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

// Package openaitomistral translates OpenAI Chat Completions requests for
// Mistral's OpenAI-compatible chat completions endpoint.
package openaitomistral

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	PolicyName                  = "openai-to-mistral-transformer"
	MistralChatCompletionsPath  = "/v1/chat/completions"
	MetadataKeySelectedProvider = "selected_provider"

	// MetadataKeyEffectiveModel carries the model actually resolved for THIS
	// request (see resolveModel) from the request phase into the response
	// phase, so a per-request payload-supplied model isn't lost behind the
	// shared policy instance's own static p.params.Model when building the
	// OpenAI-shaped response.
	MetadataKeyEffectiveModel = "openai_to_mistral_effective_model"
)

// unsupportedRequestFields lists OpenAI fields Mistral's API rejects. Keep in
// sync with https://docs.mistral.ai/api/.
var unsupportedRequestFields = []string{
	"logprobs",
	"top_logprobs",
	"logit_bias",
	"n",
	"service_tier",
	"store",
	"metadata",
	"user",
}

type PolicyParams struct {
	// Model is used only as a fallback: the request body's own "model" field
	// wins when present (see resolveModel).
	Model string
	// ProviderID is the upstream provider this translator targets. It serves two
	// purposes: it is the upstream cluster the request is routed to, and it
	// is the key matched (case-insensitive) against
	// SharedContext.Metadata["selected_provider"] in multi-provider mode.
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

func GetPolicy(_ policy.PolicyMetadata, rawParams map[string]interface{}) (policy.Policy, error) {
	parsed, err := parseParams(rawParams)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid params: %w", PolicyName, err)
	}
	return &TranslatorPolicy{params: parsed}, nil
}

func (p *TranslatorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

func (p *TranslatorPolicy) OnRequestBody(
	_ context.Context,
	reqCtx *policy.RequestContext,
	_ map[string]interface{},
) policy.RequestAction {
	if !p.shouldRun(reqCtx) {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Body == nil || !reqCtx.Body.Present || len(reqCtx.Body.Content) == 0 {
		return errResponse(400, "Request body is empty.")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		return errResponse(400, fmt.Sprintf("Invalid JSON in request body: %s", err.Error()))
	}

	model, err := resolveModel(reqCtx.Body.Content, payload, p.params.Model, p.params.RequestModel)
	if err != nil {
		return errResponse(400, err.Error())
	}
	storeEffectiveModel(reqCtx.SharedContext, model)

	payload["model"] = model
	for _, key := range unsupportedRequestFields {
		delete(payload, key)
	}

	newBody, err := json.Marshal(payload)
	if err != nil {
		return errResponse(500, "failed to marshal Mistral body: "+err.Error())
	}

	newPath := MistralChatCompletionsPath
	slog.Debug(PolicyName+": translating request",
		"providerId", p.params.ProviderID, "model", model, "path", newPath)

	mods := policy.UpstreamRequestModifications{
		Body:         newBody,
		Path:         &newPath,
		HeadersToSet: map[string]string{"content-type": "application/json"},
	}
	if p.params.ProviderID != "" {
		upstream := p.params.ProviderID
		mods.UpstreamName = &upstream
	}
	return mods
}

// OnResponseBody normalises the Mistral response into OpenAI shape. Mistral
// already emits OpenAI-shaped success bodies, so the work here is mostly
// error-envelope translation and ensuring the response model is non-empty.
// SSE streaming bodies pass through untouched.
func (p *TranslatorPolicy) OnResponseBody(
	_ context.Context,
	respCtx *policy.ResponseContext,
	_ map[string]interface{},
) policy.ResponseAction {
	if !p.shouldRunResponse(respCtx) {
		return policy.DownstreamResponseModifications{}
	}

	if respCtx.ResponseBody == nil || !respCtx.ResponseBody.Present || len(respCtx.ResponseBody.Content) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	body := respCtx.ResponseBody.Content
	if looksLikeSSE(body) {
		slog.Debug(PolicyName+": SSE response passthrough", "status", respCtx.ResponseStatus)
		return policy.DownstreamResponseModifications{}
	}

	slog.Debug(PolicyName+": translating response", "status", respCtx.ResponseStatus)
	return translateResponse(body, respCtx.ResponseStatus, effectiveModel(respCtx.SharedContext, p.params.Model))
}

// shouldRun reports whether the request should be translated. When no upstream
// router (e.g. llm-header-router) has published a selected provider into the
// metadata, the proxy is in single-provider mode and the translator always
// runs. When a provider has been selected, the translator runs only if that
// selection matches its own "providerId".
func (p *TranslatorPolicy) shouldRun(reqCtx *policy.RequestContext) bool {
	return p.shouldRunForSelected(selectedProviderFromMetadata(reqCtx.SharedContext, reqCtx.Metadata))
}

func (p *TranslatorPolicy) shouldRunResponse(respCtx *policy.ResponseContext) bool {
	return p.shouldRunForSelected(selectedProviderFromMetadata(respCtx.SharedContext, respCtx.Metadata))
}

func (p *TranslatorPolicy) shouldRunForSelected(selected string) bool {
	if selected == "" {
		// Single-provider mode: no router selected a provider, so run.
		return true
	}
	return strings.EqualFold(selected, p.params.ProviderID)
}

func selectedProviderFromMetadata(shared *policy.SharedContext, metadata map[string]interface{}) string {
	if shared == nil || metadata == nil {
		return ""
	}
	raw, ok := metadata[MetadataKeySelectedProvider]
	if !ok {
		return ""
	}
	v, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

func parseParams(params map[string]interface{}) (PolicyParams, error) {
	result := PolicyParams{}

	// 'model' is optional here (unlike pre-payload-fallback versions of this
	// policy): resolveModel falls back to it only when the request body
	// doesn't carry its own "model" field. Both being absent is a per-request
	// error (resolveModel), not a config-time one.
	model, err := optionalString(params, "model")
	if err != nil {
		return result, err
	}
	result.Model = model

	if v, err := optionalString(params, "providerId"); err != nil {
		return result, err
	} else {
		result.ProviderID = v
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
	v, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	return strings.TrimSpace(v), nil
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

// resolveModel prefers the request body's own model field — so a caller, or
// an upstream policy rewriting it per attempt (e.g. model-failover's
// per-fallback model on a cross-provider self-redial), always wins — and
// falls back to the operator's statically configured model only when the
// payload doesn't carry one. Errors when neither is present.
//
// When reqModel is set (gateway-controller injected it from the PROXY's own
// template — see PolicyParams.RequestModel), the client's model is read via
// JSONPath at reqModel.Identifier against the raw body, exactly like the
// template says. Absent that (this policy attached outside gateway-
// controller, or an older build with no such injection), falls back to a
// plain top-level "model" field lookup — every current built-in template
// resolves to that same shape anyway, so this is never a behavior change for
// the common case, only a safety net.
func resolveModel(bodyBytes []byte, payload map[string]interface{}, configured string, reqModel requestModelConfig) (string, error) {
	if reqModel.Location == "payload" {
		if val, err := utils.ExtractStringValueFromJsonpath(bodyBytes, reqModel.Identifier); err == nil {
			if trimmed := strings.TrimSpace(val); trimmed != "" {
				return trimmed, nil
			}
		}
	} else if raw, ok := payload["model"]; ok && raw != nil {
		if s, ok := raw.(string); ok {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				return trimmed, nil
			}
		}
	}
	if configured != "" {
		return configured, nil
	}
	return "", fmt.Errorf("a model must be provided in either the request body or the 'model' policy parameter")
}

// storeEffectiveModel/effectiveModel carry the model actually resolved for
// THIS request (see resolveModel) from the request phase into the response
// phase via the per-request SharedContext — never via p.params.Model
// directly, which is shared across every request this policy instance
// handles and would silently ignore a payload-supplied model once the
// response is being built.
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

func errResponse(statusCode int, message string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": message})
	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}
