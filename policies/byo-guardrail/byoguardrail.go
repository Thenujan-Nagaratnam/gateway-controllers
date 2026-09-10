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

// Package byoguardrail implements the "Bring Your Own Guardrail" policy: it
// evaluates request/response content against a guardrail service the operator
// writes and hosts themselves, via a plain JSON/HTTP contract (see
// policy-definition.yaml). Unlike the vendor-specific guardrail policies in
// this repo, `endpoint` is an arbitrary, policy-instance-configured
// destination - see the SECURITY NOTE in policy-definition.yaml and in
// validateEndpoint below.
package byoguardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	blockStatusCode              = 422
	defaultRequestTimeout        = 10 * time.Second
	defaultMaxResponseBytes      = 1 << 20 // 1 MiB
	defaultGuardrailName         = "BYOGuardrail"
	requestDefaultJSONPath       = "$.messages[-1].content"
	responseDefaultJSONPath      = "$.choices[0].message.content"
	requestFlowEnabledByDefault  = true
	responseFlowEnabledByDefault = false

	verdictAllow  = "ALLOW"
	verdictBlock  = "BLOCK"
	verdictModify = "MODIFY"

	authTypeNone   = "none"
	authTypeAPIKey = "apiKey"
)

// FlowParams holds per-flow (request or response) configuration.
type FlowParams struct {
	Enabled            bool
	JsonPath           string
	PassthroughOnError bool
	ShowAssessment     bool
}

// authConfig describes how to authenticate outbound calls to the configured endpoint.
type authConfig struct {
	authType    string
	headerName  string
	valuePrefix string
	apiKeyValue string
}

// BYOGuardrailPolicy implements the generic "bring your own guardrail" contract.
type BYOGuardrailPolicy struct {
	endpoint          string
	guardrailName     string
	auth              authConfig
	requestTimeout    time.Duration
	maxResponseBytes  int64
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     FlowParams
	responseParams    FlowParams
	httpClient        *http.Client
}

// guardrailEvaluateRequest is the request body sent to the operator's guardrail endpoint.
type guardrailEvaluateRequest struct {
	Content   string `json:"content"`
	Direction string `json:"direction"`
	RequestID string `json:"requestId"`
}

// guardrailDecision is the response from the operator's guardrail endpoint.
type guardrailDecision struct {
	Verdict              string            `json:"verdict"`
	Reason               string            `json:"reason"`
	ModifiedContent      string            `json:"modifiedContent"`
	Assessment           map[string]string `json:"assessment"`
	InterveningGuardrail string            `json:"interveningGuardrail"`
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	endpoint := getStringParam(params, "endpoint")
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("invalid params: 'endpoint' %w", err)
	}

	guardrailName := getStringParam(params, "guardrailName")
	if guardrailName == "" {
		guardrailName = defaultGuardrailName
	}

	auth, err := parseAuthConfig(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: 'auth' %w", err)
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

	// The process-wide client built once at policy-engine startup (pooling, timeouts,
	// TLS, and - critically for this policy, since `endpoint` is arbitrary and
	// policy-instance-configured - an optional dial-time SSRF guard; see
	// utils.SharedHTTPClient's own doc and this policy's SECURITY NOTE). A nil return
	// means the engine hasn't installed one yet, which is a configuration error, not
	// something to paper over with a locally-built http.Client that would bypass those
	// hardened defaults.
	httpClient := utils.SharedHTTPClient()
	if httpClient == nil {
		return nil, fmt.Errorf("byo-guardrail: shared outbound HTTP client not initialized")
	}

	p := &BYOGuardrailPolicy{
		endpoint:         endpoint,
		guardrailName:    guardrailName,
		auth:             auth,
		requestTimeout:   timeout,
		maxResponseBytes: maxResponseBytes,
		httpClient:       httpClient,
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

	slog.Debug("BYOGuardrail: policy initialized", "endpoint", p.endpoint, "guardrailName", p.guardrailName, "hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}

// Mode returns the processing mode for the byo-guardrail policy.
func (p *BYOGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// validateEndpoint requires an absolute http(s) URL with no embedded userinfo. This is
// basic input hygiene, not a substitute for the shared client's SSRF guard (see the
// SECURITY NOTE in policy-definition.yaml) - it catches obviously-wrong configuration
// (a bare host, a non-HTTP scheme, a credential embedded in the URL) at deploy time.
func validateEndpoint(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("parameter is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("must be a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("must use the http or https scheme")
	}
	if u.Host == "" {
		return fmt.Errorf("must be an absolute URL with a host")
	}
	if u.User != nil {
		return fmt.Errorf("must not embed userinfo (username/password) in the URL")
	}
	return nil
}

// parseAuthConfig parses and validates the top-level "auth" parameter.
func parseAuthConfig(params map[string]interface{}) (authConfig, error) {
	result := authConfig{
		authType:    authTypeNone,
		headerName:  "Authorization",
		valuePrefix: "Bearer ",
	}

	authRaw, ok := params["auth"].(map[string]interface{})
	if !ok {
		return result, nil
	}

	if typeRaw, ok := authRaw["type"]; ok {
		authType, ok := typeRaw.(string)
		if !ok {
			return result, fmt.Errorf("'type' must be a string")
		}
		if authType != authTypeNone && authType != authTypeAPIKey {
			return result, fmt.Errorf("'type' must be one of %q, %q", authTypeNone, authTypeAPIKey)
		}
		result.authType = authType
	}

	if headerNameRaw, ok := authRaw["headerName"]; ok {
		headerName, ok := headerNameRaw.(string)
		if !ok || headerName == "" {
			return result, fmt.Errorf("'headerName' must be a non-empty string")
		}
		result.headerName = headerName
	}

	if valuePrefixRaw, ok := authRaw["valuePrefix"]; ok {
		valuePrefix, ok := valuePrefixRaw.(string)
		if !ok {
			return result, fmt.Errorf("'valuePrefix' must be a string")
		}
		result.valuePrefix = valuePrefix
	}

	if apiKeyRaw, ok := authRaw["apiKeyValue"]; ok {
		apiKeyValue, ok := apiKeyRaw.(string)
		if !ok {
			return result, fmt.Errorf("'apiKeyValue' must be a string")
		}
		result.apiKeyValue = apiKeyValue
	}

	if result.authType == authTypeAPIKey && result.apiKeyValue == "" {
		return result, fmt.Errorf("'apiKeyValue' is required when 'type' is %q", authTypeAPIKey)
	}

	return result, nil
}

// parseFlowParams parses and validates per-flow (request or response) configuration.
func parseFlowParams(params map[string]interface{}, isResponse bool) (FlowParams, error) {
	result := FlowParams{
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
		jsonPath, ok := jsonPathRaw.(string)
		if !ok {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
		result.JsonPath = jsonPath
	}

	if passthroughOnErrorRaw, ok := params["passthroughOnError"]; ok {
		passthroughOnError, ok := passthroughOnErrorRaw.(bool)
		if !ok {
			return result, fmt.Errorf("'passthroughOnError' must be a boolean")
		}
		result.PassthroughOnError = passthroughOnError
	}

	if showAssessmentRaw, ok := params["showAssessment"]; ok {
		showAssessment, ok := showAssessmentRaw.(bool)
		if !ok {
			return result, fmt.Errorf("'showAssessment' must be a boolean")
		}
		result.ShowAssessment = showAssessment
	}

	return result, nil
}

func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

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

// OnRequestBody evaluates the request body against the configured guardrail service.
func (p *BYOGuardrailPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	var content []byte
	var requestID string
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	if reqCtx.SharedContext != nil {
		requestID = reqCtx.SharedContext.RequestID
	}
	return p.evaluate(ctx, content, requestID, p.requestParams, false).(policy.RequestAction)
}

// OnResponseBody evaluates the response body against the configured guardrail service.
func (p *BYOGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.DownstreamResponseModifications{}
	}

	var content []byte
	var requestID string
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	if respCtx.SharedContext != nil {
		requestID = respCtx.SharedContext.RequestID
	}
	return p.evaluate(ctx, content, requestID, p.responseParams, true).(policy.ResponseAction)
}

// evaluate extracts content via JSONPath, calls the operator's guardrail service, and
// returns the appropriate policy action based on the returned verdict.
func (p *BYOGuardrailPolicy) evaluate(ctx context.Context, payload []byte, requestID string, params FlowParams, isResponse bool) interface{} {
	passThrough := func() interface{} {
		if isResponse {
			return policy.DownstreamResponseModifications{}
		}
		return policy.UpstreamRequestModifications{}
	}

	if payload == nil {
		return passThrough()
	}

	extractedValue, err := utils.ExtractStringValueFromJsonpath(payload, params.JsonPath)
	if err != nil {
		if params.PassthroughOnError {
			slog.Debug("BYOGuardrail: JSONPath extraction error, passthrough enabled", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
			return passThrough()
		}
		slog.Warn("BYOGuardrail: error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse(isResponse)
	}
	extractedValue = strings.TrimSpace(extractedValue)

	decision, err := p.callGuardrailEndpoint(ctx, extractedValue, requestID, isResponse)
	if err != nil {
		if params.PassthroughOnError {
			slog.Debug("BYOGuardrail: guardrail endpoint call error, passthrough enabled", "error", err, "isResponse", isResponse)
			return passThrough()
		}
		// The underlying error (connection refused, DNS failure, malformed upstream
		// JSON, internal hostnames/ports) is internal detail and must never reach the
		// client - log it server-side only and surface a sterile reason (error-handling.md).
		slog.Error("BYOGuardrail: error calling guardrail endpoint", "error", err, "isResponse", isResponse)
		return p.buildErrorResponse(isResponse)
	}

	switch decision.Verdict {
	case verdictAllow:
		slog.Debug("BYOGuardrail: ALLOW verdict", "isResponse", isResponse)
		return passThrough()

	case verdictBlock:
		slog.Debug("BYOGuardrail: BLOCK verdict", "isResponse", isResponse)
		return p.buildBlockResponse(isResponse, params.ShowAssessment, decision)

	case verdictModify:
		updatedPayload, err := rewriteJSONPath(payload, params.JsonPath, decision.ModifiedContent)
		if err != nil {
			slog.Warn("BYOGuardrail: failed to apply MODIFY verdict, treating as error", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
			if params.PassthroughOnError {
				return passThrough()
			}
			return p.buildErrorResponse(isResponse)
		}
		slog.Debug("BYOGuardrail: MODIFY verdict applied", "isResponse", isResponse)
		if isResponse {
			return policy.DownstreamResponseModifications{Body: updatedPayload}
		}
		return policy.UpstreamRequestModifications{Body: updatedPayload}

	default:
		slog.Warn("BYOGuardrail: unknown verdict returned by guardrail endpoint", "verdict", decision.Verdict, "isResponse", isResponse)
		if params.PassthroughOnError {
			return passThrough()
		}
		return p.buildErrorResponse(isResponse)
	}
}

// rewriteJSONPath decodes payload, sets jsonPath to value, and re-encodes it.
func rewriteJSONPath(payload []byte, jsonPath string, value string) ([]byte, error) {
	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return nil, fmt.Errorf("failed to decode payload as JSON: %w", err)
	}
	if err := utils.SetValueAtJSONPath(jsonData, jsonPath, value); err != nil {
		return nil, fmt.Errorf("failed to set value at JSONPath: %w", err)
	}
	updated, err := json.Marshal(jsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode updated payload: %w", err)
	}
	return updated, nil
}

// callGuardrailEndpoint calls the operator's guardrail evaluation endpoint.
func (p *BYOGuardrailPolicy) callGuardrailEndpoint(ctx context.Context, content string, requestID string, isResponse bool) (*guardrailDecision, error) {
	direction := "REQUEST"
	if isResponse {
		direction = "RESPONSE"
	}

	reqBody := guardrailEvaluateRequest{
		Content:   content,
		Direction: direction,
		RequestID: requestID,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	dialCtx, cancel := context.WithTimeout(ctx, p.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(dialCtx, http.MethodPost, p.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.auth.authType == authTypeAPIKey {
		req.Header.Set(p.auth.headerName, p.auth.valuePrefix+p.auth.apiKeyValue)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call guardrail endpoint: %w", err)
	}
	defer resp.Body.Close()

	respBodyBytes, err := readBounded(resp.Body, p.maxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read guardrail endpoint response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("guardrail endpoint returned non-200 status: %d", resp.StatusCode)
	}

	var decision guardrailDecision
	if err := json.Unmarshal(respBodyBytes, &decision); err != nil {
		return nil, fmt.Errorf("failed to decode guardrail endpoint response: %w", err)
	}

	return &decision, nil
}

// buildErrorResponse builds the 422 response for a transport/JSONPath/decode error -
// only a fixed, sterile reason is surfaced, never the underlying Go error text (which may
// contain internal hostnames, ports, or stack detail); the real error is already logged
// server-side by the caller.
func (p *BYOGuardrailPolicy) buildErrorResponse(isResponse bool) interface{} {
	return p.buildResponse(isResponse, p.guardrailName, "GUARDRAIL_INTERVENED", "Unable to complete guardrail evaluation.", nil)
}

// buildBlockResponse builds the 422 response for a genuine BLOCK verdict.
func (p *BYOGuardrailPolicy) buildBlockResponse(isResponse bool, showAssessment bool, decision *guardrailDecision) interface{} {
	guardrailName := p.guardrailName
	if decision.InterveningGuardrail != "" {
		guardrailName = decision.InterveningGuardrail
	}
	reason := decision.Reason
	if reason == "" {
		reason = "Blocked by guardrail."
	}

	var assessment map[string]string
	if showAssessment {
		assessment = decision.Assessment
	}

	return p.buildResponse(isResponse, guardrailName, "GUARDRAIL_INTERVENED", reason, assessment)
}

func (p *BYOGuardrailPolicy) buildResponse(isResponse bool, guardrailName, action, reason string, assessment map[string]string) interface{} {
	direction := "REQUEST"
	if isResponse {
		direction = "RESPONSE"
	}

	message := map[string]interface{}{
		"interveningGuardrail": guardrailName,
		"action":               action,
		"actionReason":         reason,
		"direction":            direction,
	}
	if assessment != nil {
		message["assessments"] = assessment
	}

	responseBody := map[string]interface{}{
		"type":    "BYO_GUARDRAIL",
		"message": message,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"BYO_GUARDRAIL","message":"Internal error"}`)
	}

	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  guardrailName,
	}

	if isResponse {
		statusCode := blockStatusCode
		return policy.DownstreamResponseModifications{
			StatusCode:        &statusCode,
			Body:              bodyBytes,
			AnalyticsMetadata: analyticsMetadata,
			HeadersToSet:      map[string]string{"Content-Type": "application/json"},
		}
	}

	return policy.ImmediateResponse{
		StatusCode:        blockStatusCode,
		AnalyticsMetadata: analyticsMetadata,
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              bodyBytes,
	}
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
