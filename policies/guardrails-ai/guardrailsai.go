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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	GuardrailErrorCode           = 422
	defaultRequestTimeout        = 10 * time.Second
	defaultMaxResponseBytes      = 1 << 20 // 1 MiB
	requestDefaultJSONPath       = "$.messages[-1].content"
	responseDefaultJSONPath      = "$.choices[0].message.content"
	requestFlowEnabledByDefault  = true
	responseFlowEnabledByDefault = false
)

// GuardrailsAIFlowParams holds per-flow (request or response) configuration.
type GuardrailsAIFlowParams struct {
	Enabled            bool
	JsonPath           string
	PassthroughOnError bool
	ShowAssessment     bool
}

// GuardrailsAIPolicy implements Guardrails AI Hub guardrail validation.
type GuardrailsAIPolicy struct {
	apiEndpoint       string
	apiKey            string
	guardName         string
	requestTimeout    time.Duration
	maxResponseBytes  int64
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     GuardrailsAIFlowParams
	responseParams    GuardrailsAIFlowParams
	httpClient        *http.Client
}

// guardrailsValidateRequest is the request body sent to the Guardrails AI validate endpoint.
type guardrailsValidateRequest struct {
	LLMOutput string `json:"llmOutput"`
	NumReasks int    `json:"numReasks"`
}

// guardrailsValidateResponse is the response from the Guardrails AI validate endpoint.
type guardrailsValidateResponse struct {
	CallID           string        `json:"callId"`
	RawLLMOutput     string        `json:"rawLlmOutput"`
	ValidatedOutput  interface{}   `json:"validatedOutput"`
	Error            *string       `json:"error"`
	Status           string        `json:"status"`
	FailedValidators []interface{} `json:"failedValidators,omitempty"`
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	if err := validateSystemParams(params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	timeout := defaultRequestTimeout
	if timeoutRaw, ok := params["requestTimeout"]; ok {
		parsed, err := coerceDuration(timeoutRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid params: 'requestTimeout' %w", err)
		}
		timeout = parsed
	}

	maxResponseBytes := int64(defaultMaxResponseBytes)
	if maxResponseBytesRaw, ok := params["maxResponseBytes"]; ok {
		parsed, err := coercePositiveInt(maxResponseBytesRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid params: 'maxResponseBytes' %w", err)
		}
		maxResponseBytes = parsed
	}

	// utils.SharedHTTPClient (pooling, config-driven timeouts, optional SSRF guard,
	// all wired once at policy-engine startup) is the newer, preferred pattern, but
	// it isn't in a published sdk/core release yet - using it here would require a
	// local-only go.mod replace directive that can't resolve outside this checkout.
	// Build our own client until a tagged sdk/core release carries it; the per-call
	// timeout and bounded response read below still apply either way.
	p := &GuardrailsAIPolicy{
		apiEndpoint:      strings.TrimSuffix(getStringParam(params, "guardrailsApiEndpoint"), "/"),
		apiKey:           getStringParam(params, "apiKey"),
		guardName:        getStringParam(params, "guardName"),
		requestTimeout:   timeout,
		maxResponseBytes: maxResponseBytes,
		httpClient:       &http.Client{Timeout: timeout},
	}

	if p.guardName == "" {
		return nil, fmt.Errorf("invalid params: 'guardName' parameter is required")
	}

	if requestParamsRaw, ok := params["request"].(map[string]interface{}); ok {
		requestParams, err := parseFlowParams(requestParamsRaw, false)
		if err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
		p.hasRequestParams = true
		p.requestParams = requestParams
	}

	if responseParamsRaw, ok := params["response"].(map[string]interface{}); ok {
		responseParams, err := parseFlowParams(responseParamsRaw, true)
		if err != nil {
			return nil, fmt.Errorf("invalid response parameters: %w", err)
		}
		p.hasResponseParams = true
		p.responseParams = responseParams
	}

	if !p.hasRequestParams && !p.hasResponseParams {
		return nil, fmt.Errorf("at least one of 'request' or 'response' parameters must be provided")
	}

	slog.Debug("GuardrailsAI: Policy initialized", "apiEndpoint", p.apiEndpoint, "guardName", p.guardName, "hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}

// Mode returns the processing mode for the Guardrails AI policy.
func (p *GuardrailsAIPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// parseFlowParams parses and validates per-flow (request or response) configuration.
func parseFlowParams(params map[string]interface{}, isResponse bool) (GuardrailsAIFlowParams, error) {
	result := GuardrailsAIFlowParams{
		JsonPath: requestDefaultJSONPath,
		Enabled:  requestFlowEnabledByDefault,
	}
	if isResponse {
		result.JsonPath = responseDefaultJSONPath
		result.Enabled = responseFlowEnabledByDefault
	}

	if enabledRaw, ok := params["enabled"]; ok {
		enabled, ok := enabledRaw.(bool)
		if !ok {
			return result, fmt.Errorf("'enabled' must be a boolean")
		}
		result.Enabled = enabled
	}

	if jsonPathRaw, ok := params["jsonPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			result.JsonPath = jsonPath
		} else {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
	}

	if passthroughOnErrorRaw, ok := params["passthroughOnError"]; ok {
		if passthroughOnError, ok := passthroughOnErrorRaw.(bool); ok {
			result.PassthroughOnError = passthroughOnError
		} else {
			return result, fmt.Errorf("'passthroughOnError' must be a boolean")
		}
	}

	if showAssessmentRaw, ok := params["showAssessment"]; ok {
		if showAssessment, ok := showAssessmentRaw.(bool); ok {
			result.ShowAssessment = showAssessment
		} else {
			return result, fmt.Errorf("'showAssessment' must be a boolean")
		}
	}

	return result, nil
}

// validateSystemParams validates required system-level configuration parameters.
func validateSystemParams(params map[string]interface{}) error {
	endpointRaw, ok := params["guardrailsApiEndpoint"]
	if !ok {
		return fmt.Errorf("'guardrailsApiEndpoint' parameter is required")
	}
	endpoint, ok := endpointRaw.(string)
	if !ok {
		return fmt.Errorf("'guardrailsApiEndpoint' must be a string")
	}
	if endpoint == "" {
		return fmt.Errorf("'guardrailsApiEndpoint' cannot be empty")
	}
	return nil
}

// getStringParam safely extracts a string parameter.
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// coerceDuration parses a systemParameters "requestTimeout" value (seconds) into a
// positive time.Duration, rejecting non-numeric or non-positive values outright
// rather than silently falling back to the default - a caller who typed the wrong
// shape should see an error at deploy time, not an accidentally-permissive default.
func coerceDuration(raw interface{}) (time.Duration, error) {
	seconds, err := toFloat64(raw)
	if err != nil {
		return 0, fmt.Errorf("must be a positive number of seconds: %w", err)
	}
	if seconds <= 0 {
		return 0, fmt.Errorf("must be a positive number of seconds, got %v", seconds)
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

// coercePositiveInt parses a systemParameters value into a positive int64 byte count.
func coercePositiveInt(raw interface{}) (int64, error) {
	value, err := toFloat64(raw)
	if err != nil {
		return 0, fmt.Errorf("must be a positive integer: %w", err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("must be a positive integer, got %v", value)
	}
	return int64(value), nil
}

func toFloat64(raw interface{}) (float64, error) {
	switch v := raw.(type) {
	case float64:
		return v, nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	default:
		return 0, fmt.Errorf("unsupported type %T", raw)
	}
}

// OnRequestBody validates the request body using the configured Guardrails AI guard.
func (p *GuardrailsAIPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	return p.validatePayload(ctx, content, p.requestParams, false).(policy.RequestAction)
}

// OnResponseBody validates the response body using the configured Guardrails AI guard.
func (p *GuardrailsAIPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.DownstreamResponseModifications{}
	}

	var content []byte
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	return p.validatePayload(ctx, content, p.responseParams, true).(policy.ResponseAction)
}

// validatePayload extracts content via JSONPath, calls the Guardrails AI validate API,
// and returns the appropriate policy action based on the validation result.
func (p *GuardrailsAIPolicy) validatePayload(ctx context.Context, payload []byte, params GuardrailsAIFlowParams, isResponse bool) interface{} {
	if payload == nil {
		if isResponse {
			return policy.DownstreamResponseModifications{}
		}
		return policy.UpstreamRequestModifications{}
	}

	extractedValue, err := utils.ExtractStringValueFromJsonpath(payload, params.JsonPath)
	if err != nil {
		if params.PassthroughOnError {
			slog.Debug("GuardrailsAI: JSONPath extraction error, passthrough enabled", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
			if isResponse {
				return policy.DownstreamResponseModifications{}
			}
			return policy.UpstreamRequestModifications{}
		}
		slog.Warn("GuardrailsAI: error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse(isResponse, params.ShowAssessment, nil)
	}

	extractedValue = strings.TrimSpace(extractedValue)

	validateResp, err := p.callValidateAPI(ctx, extractedValue)
	if err != nil {
		if params.PassthroughOnError {
			slog.Debug("GuardrailsAI: API call error, passthrough enabled", "error", err, "isResponse", isResponse)
			if isResponse {
				return policy.DownstreamResponseModifications{}
			}
			return policy.UpstreamRequestModifications{}
		}
		// The underlying error (connection refused, DNS failure, malformed upstream
		// JSON, internal hostnames/ports) is internal detail and must never reach the
		// client - log it server-side only and surface a sterile reason (error-handling.md).
		slog.Error("GuardrailsAI: error calling Guardrails AI API", "error", err, "isResponse", isResponse)
		return p.buildErrorResponse(isResponse, params.ShowAssessment, nil)
	}

	if validateResp.Status == "fail" {
		slog.Debug("GuardrailsAI: violation detected", "guardName", p.guardName, "isResponse", isResponse)
		return p.buildErrorResponse(isResponse, params.ShowAssessment, validateResp)
	}

	slog.Debug("GuardrailsAI: validation passed", "guardName", p.guardName, "isResponse", isResponse)
	if isResponse {
		return policy.DownstreamResponseModifications{}
	}
	return policy.UpstreamRequestModifications{}
}

// callValidateAPI calls the Guardrails AI validate endpoint for the configured guard.
func (p *GuardrailsAIPolicy) callValidateAPI(ctx context.Context, text string) (*guardrailsValidateResponse, error) {
	validateURL := fmt.Sprintf("%s/guards/%s/validate", p.apiEndpoint, p.guardName)

	reqBody := guardrailsValidateRequest{LLMOutput: text, NumReasks: 0}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	dialCtx, cancel := context.WithTimeout(ctx, p.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(dialCtx, http.MethodPost, validateURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Guardrails AI API: %w", err)
	}
	defer resp.Body.Close()

	respBodyBytes, err := readBounded(resp.Body, p.maxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read Guardrails AI API response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Guardrails AI API returned non-200 status: %d", resp.StatusCode)
	}

	var validateResp guardrailsValidateResponse
	if err := json.Unmarshal(respBodyBytes, &validateResp); err != nil {
		return nil, fmt.Errorf("failed to decode Guardrails AI API response: %w", err)
	}

	return &validateResp, nil
}

// readBounded reads at most limit+1 bytes and errors if that many were available - the
// "+1" makes an exactly-at-the-limit body indistinguishable from a real overflow, which
// is the correct conservative choice here (see file-access.md on configurable stream
// size limits).
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeded %d byte limit", limit)
	}
	return data, nil
}

// buildErrorResponse builds a policy error response for both request and response phases.
// validateResp is nil for JSONPath-extraction and transport/API-call failures - in those
// cases only a sterile, generic reason is surfaced to the client (never the underlying Go
// error text, which may contain internal hostnames, ports, or stack detail); the real
// error is already logged server-side by the caller.
func (p *GuardrailsAIPolicy) buildErrorResponse(isResponse bool, showAssessment bool, validateResp *guardrailsValidateResponse) interface{} {
	assessment := p.buildAssessmentObject(isResponse, showAssessment, validateResp)
	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  "GuardrailsAI",
	}

	responseBody := map[string]interface{}{
		"type":    "GUARDRAILS_AI_GUARDRAIL",
		"message": assessment,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"GUARDRAILS_AI_GUARDRAIL","message":"Internal error"}`)
	}

	if isResponse {
		statusCode := GuardrailErrorCode
		return policy.DownstreamResponseModifications{
			StatusCode:        &statusCode,
			Body:              bodyBytes,
			AnalyticsMetadata: analyticsMetadata,
			HeadersToSet:      map[string]string{"Content-Type": "application/json"},
		}
	}

	return policy.ImmediateResponse{
		StatusCode:        GuardrailErrorCode,
		AnalyticsMetadata: analyticsMetadata,
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              bodyBytes,
	}
}

// buildAssessmentObject builds the assessment object for the error response body.
// validateResp == nil means the block was caused by a JSONPath/transport/API error
// rather than an actual Guardrails AI validation failure - the reason surfaced there is
// always a fixed, sterile string, never internal error detail.
func (p *GuardrailsAIPolicy) buildAssessmentObject(isResponse bool, showAssessment bool, validateResp *guardrailsValidateResponse) map[string]interface{} {
	assessment := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "Guardrails AI",
		"guardName":            p.guardName,
	}

	if isResponse {
		assessment["direction"] = "RESPONSE"
	} else {
		assessment["direction"] = "REQUEST"
	}

	if validateResp == nil {
		assessment["actionReason"] = "Unable to complete guardrail validation."
		return assessment
	}

	assessment["actionReason"] = "Violation detected by Guardrails AI guard."

	if showAssessment {
		assessments := map[string]interface{}{}
		if validateResp.Error != nil {
			assessments["error"] = *validateResp.Error
		}
		if len(validateResp.FailedValidators) > 0 {
			assessments["failedValidators"] = validateResp.FailedValidators
		}
		if validateResp.CallID != "" {
			assessments["callId"] = validateResp.CallID
		}
		assessment["assessments"] = assessments
	}

	return assessment
}
