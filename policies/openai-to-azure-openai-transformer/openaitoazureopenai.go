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

// Package openaitoazureopenai rewrites an OpenAI Chat Completions request path
// into the Azure OpenAI form
// /openai/deployments/{deployment}/{pathSuffix}?api-version=<apiVersion>.
// The body passes through unchanged; Azure already emits OpenAI-shaped
// responses, so response translation is intentionally not implemented.
package openaitoazureopenai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	PolicyName                  = "openai-to-azure-openai-transformer"
	DefaultPathSuffix           = "/chat/completions"
	MetadataKeySelectedProvider = "selected_provider"
)

type PolicyParams struct {
	APIVersion string
	Model      string
	PathSuffix string
	// ProviderID is the upstream provider this translator targets. It is both the
	// upstream cluster the request is routed to and the key matched
	// (case-insensitive) against SharedContext.Metadata["selected_provider"]
	// in multi-provider mode.
	ProviderID string
	// RequestModel identifies where the client's own model lives in the
	// request body — a systemParameter gateway-controller injects from the
	// PROXY's OWN (primary provider's) template, never the additional
	// provider's, since that's the one location the client actually sends
	// its model in, regardless of which provider ends up handling the
	// request (see readModelFromBody). Zero value (Location == "") means it
	// wasn't injected (e.g. this policy attached outside gateway-controller,
	// or an older build) — readModelFromBody falls back to a plain top-level
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

// Mode buffers the request body even though we don't modify it — the
// deployment id is read from the body's "model" field first, falling back
// to the operator's configured one only when the request doesn't carry it.
func (p *TranslatorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
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

	// The request body's own model field wins when present (e.g. a
	// per-attempt override from a policy like model-failover); the
	// statically configured deployment is used only as a fallback.
	deployment := readModelFromBody(reqCtx, p.params.RequestModel)
	if deployment == "" {
		deployment = p.params.Model
	}
	if deployment == "" {
		return errResponse(400,
			"'model' is required in the request body (or as a policy parameter) "+
				"to derive the Azure deployment id.")
	}

	newPath := buildAzurePath(deployment, p.params.PathSuffix, p.params.APIVersion)
	slog.Debug(PolicyName+": rewriting request path",
		"providerId", p.params.ProviderID, "deployment", deployment, "path", newPath)

	mods := policy.UpstreamRequestModifications{Path: &newPath}
	if p.params.ProviderID != "" {
		upstream := p.params.ProviderID
		mods.UpstreamName = &upstream
	}
	return mods
}

// shouldRun reports whether the request should be rewritten. When no upstream
// router (e.g. llm-header-router) has published a selected provider into the
// metadata, the proxy is in single-provider mode and the translator always
// runs. When a provider has been selected, the translator runs only if that
// selection matches its own "providerId".
func (p *TranslatorPolicy) shouldRun(reqCtx *policy.RequestContext) bool {
	selected := selectedProvider(reqCtx)
	if selected == "" {
		// Single-provider mode: no router selected a provider, so run.
		return true
	}
	return strings.EqualFold(selected, p.params.ProviderID)
}

func selectedProvider(reqCtx *policy.RequestContext) string {
	if reqCtx == nil || reqCtx.SharedContext == nil || reqCtx.Metadata == nil {
		return ""
	}
	raw, ok := reqCtx.Metadata[MetadataKeySelectedProvider]
	if !ok {
		return ""
	}
	v, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

// readModelFromBody reads the client's own model out of the request body.
//
// When reqModel is set (gateway-controller injected it from the PROXY's own
// template — see PolicyParams.RequestModel), the client's model is read via
// JSONPath at reqModel.Identifier against the raw body, exactly like the
// template says. Absent that (this policy attached outside gateway-
// controller, or an older build with no such injection), falls back to a
// plain top-level "model" field lookup — every current built-in template
// resolves to that same shape anyway, so this is never a behavior change for
// the common case, only a safety net.
func readModelFromBody(reqCtx *policy.RequestContext, reqModel requestModelConfig) string {
	if reqCtx.Body == nil || !reqCtx.Body.Present || len(reqCtx.Body.Content) == 0 {
		return ""
	}
	if reqModel.Location == "payload" {
		if val, err := utils.ExtractStringValueFromJsonpath(reqCtx.Body.Content, reqModel.Identifier); err == nil {
			return strings.TrimSpace(val)
		}
		return ""
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(reqCtx.Body.Content, &payload); err != nil {
		return ""
	}
	model, _ := payload["model"].(string)
	return strings.TrimSpace(model)
}

// buildAzurePath escapes the deployment as a single path segment and the
// apiVersion as a query value. The deployment may originate from the request
// body's "model" field, so it is untrusted and must not be able to inject
// additional path segments or query parameters. pathSuffix is operator-supplied
// configuration and is inserted verbatim.
func buildAzurePath(deployment, pathSuffix, apiVersion string) string {
	return fmt.Sprintf("/openai/deployments/%s%s?api-version=%s",
		url.PathEscape(deployment), pathSuffix, url.QueryEscape(apiVersion))
}

func parseParams(params map[string]interface{}) (PolicyParams, error) {
	result := PolicyParams{PathSuffix: DefaultPathSuffix}

	apiVersion, err := optionalString(params, "apiVersion")
	if err != nil {
		return result, err
	}
	if apiVersion == "" {
		return result, fmt.Errorf("'apiVersion' is required")
	}
	result.APIVersion = apiVersion

	if v, err := optionalString(params, "model"); err != nil {
		return result, err
	} else {
		result.Model = v
	}

	if v, err := optionalString(params, "pathSuffix"); err != nil {
		return result, err
	} else if v != "" {
		// PathSuffix must start with '/' so buildAzurePath can concatenate
		// without inspecting the operator-supplied string.
		if !strings.HasPrefix(v, "/") {
			v = "/" + v
		}
		result.PathSuffix = v
	}

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
// zero value signals readModelFromBody to use its own fallback. Present-but-
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

func errResponse(statusCode int, message string) policy.ImmediateResponse {
	body, _ := json.Marshal(map[string]string{"error": message})
	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}
