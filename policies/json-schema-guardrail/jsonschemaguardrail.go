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

package jsonschemaguardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
	"github.com/xeipuuv/gojsonschema"
)

const (
	GuardrailErrorCode           = 422
	DefaultRequestJSONPath       = "$.messages[-1].content"
	DefaultResponseJSONPath      = "$.choices[0].message.content"
	RequestFlowEnabledByDefault  = false
	ResponseFlowEnabledByDefault = true
)

// JSONSchemaGuardrailPolicy implements JSON schema validation
type JSONSchemaGuardrailPolicy struct {
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     JSONSchemaGuardrailPolicyParams
	responseParams    JSONSchemaGuardrailPolicyParams
}

type JSONSchemaGuardrailPolicyParams struct {
	Enabled        bool
	Schema         string
	JsonPath       string
	Invert         bool
	ShowAssessment bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &JSONSchemaGuardrailPolicy{}

	// Extract and parse request parameters if present
	if requestParamsRaw, ok := params["request"].(map[string]interface{}); ok {
		requestParams, err := parseParams(requestParamsRaw, DefaultRequestJSONPath, RequestFlowEnabledByDefault)
		if err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
		p.hasRequestParams = true
		p.requestParams = requestParams
	}

	// Extract and parse response parameters if present
	if responseParamsRaw, ok := params["response"].(map[string]interface{}); ok {
		responseParams, err := parseParams(responseParamsRaw, DefaultResponseJSONPath, ResponseFlowEnabledByDefault)
		if err != nil {
			return nil, fmt.Errorf("invalid response parameters: %w", err)
		}
		p.hasResponseParams = true
		p.responseParams = responseParams
	}

	// At least one of request or response must be present
	if !p.hasRequestParams && !p.hasResponseParams {
		return nil, fmt.Errorf("at least one of 'request' or 'response' parameters must be provided")
	}

	slog.Debug("JSONSchemaGuardrail: Policy initialized", "hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}


func (p *JSONSchemaGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}, defaultJSONPath string, defaultEnabled bool) (JSONSchemaGuardrailPolicyParams, error) {
	result := JSONSchemaGuardrailPolicyParams{
		Enabled:  defaultEnabled,
		JsonPath: defaultJSONPath,
	}
	enabledExplicitlyFalse := false

	// Extract optional enabled parameter
	if enabledRaw, ok := params["enabled"]; ok {
		enabled, ok := enabledRaw.(bool)
		if !ok {
			return result, fmt.Errorf("'enabled' must be a boolean")
		}
		result.Enabled = enabled
		enabledExplicitlyFalse = !enabled
	}

	schemaRaw, hasSchema := params["schema"]
	if !enabledExplicitlyFalse && !hasSchema {
		return result, fmt.Errorf("'schema' parameter is required")
	}

	if enabledExplicitlyFalse {
		hasSchema = false
	}

	if hasSchema {
		schema, ok := schemaRaw.(string)
		if !ok {
			return result, fmt.Errorf("'schema' must be a string")
		}
		if schema == "" {
			return result, fmt.Errorf("'schema' cannot be empty")
		}

		// Validate schema is valid JSON
		var schemaJSON interface{}
		if err := json.Unmarshal([]byte(schema), &schemaJSON); err != nil {
			return result, fmt.Errorf("'schema' must be valid JSON: %v", err)
		}
		result.Schema = schema
	}

	// Extract optional jsonPath parameter
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			result.JsonPath = jsonPath
		} else {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
	}

	// Extract optional invert parameter
	if invertRaw, ok := params["invert"]; ok {
		if invert, ok := invertRaw.(bool); ok {
			result.Invert = invert
		} else {
			return result, fmt.Errorf("'invert' must be a boolean")
		}
	}

	// Extract optional showAssessment parameter
	if showAssessmentRaw, ok := params["showAssessment"]; ok {
		if showAssessment, ok := showAssessmentRaw.(bool); ok {
			result.ShowAssessment = showAssessment
		} else {
			return result, fmt.Errorf("'showAssessment' must be a boolean")
		}
	}

	return result, nil
}

// extractValueFromJSONPathForSchema extracts a value from JSON using JSONPath and returns as JSON bytes
func extractValueFromJSONPathForSchema(payload []byte, jsonPath string) ([]byte, error) {
	var any interface{}
	if err := json.Unmarshal(payload, &any); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %w", err)
	}
	jsonData, ok := any.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("jsonPath extraction requires a JSON object payload (got %T)", any)
	}

	value, err := utils.ExtractValueFromJsonpath(jsonData, jsonPath)
	if err != nil {
		return nil, err
	}

	// Marshal back to JSON
	valueBytes, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("error marshaling extracted value: %w", err)
	}

	return valueBytes, nil
}

// buildAssessmentObject builds the assessment object
func (p *JSONSchemaGuardrailPolicy) buildAssessmentObject(reason string, validationError error, isResponse bool, showAssessment bool, errors []gojsonschema.ResultError) map[string]interface{} {
	assessment := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "json-schema-guardrail",
	}

	if isResponse {
		assessment["direction"] = "RESPONSE"
	} else {
		assessment["direction"] = "REQUEST"
	}

	if validationError != nil {
		assessment["actionReason"] = reason
	} else {
		assessment["actionReason"] = "Violation of JSON schema detected."
	}

	if showAssessment {
		if validationError != nil {
			assessment["assessments"] = validationError.Error()
		} else if len(errors) > 0 {
			errorDetails := make([]map[string]interface{}, 0, len(errors))
			for _, err := range errors {
				errorDetails = append(errorDetails, map[string]interface{}{
					"field":       err.Field(),
					"description": err.Description(),
					"value":       err.Value(),
				})
			}
			assessment["assessments"] = errorDetails
		}
	}

	return assessment
}

// OnRequestBody validates request body against JSON schema.
func (p *JSONSchemaGuardrailPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	content := []byte{}
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	return p.validatePayload(content, p.requestParams, false, reqCtx.IsLLMAPI()).(policy.RequestAction)
}

// OnResponseBody validates response body against JSON schema.
func (p *JSONSchemaGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.DownstreamResponseModifications{}
	}

	content := []byte{}
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	return p.validatePayload(content, p.responseParams, true, respCtx.IsLLMAPI()).(policy.ResponseAction)
}

// validatePayload validates payload against JSON schema, returning policy actions.
func (p *JSONSchemaGuardrailPolicy) validatePayload(payload []byte, params JSONSchemaGuardrailPolicyParams, isResponse bool, llm bool) interface{} {
	schemaLoader := gojsonschema.NewStringLoader(params.Schema)

	var documentLoader gojsonschema.JSONLoader
	if params.JsonPath != "" {
		extractedValue, err := extractValueFromJSONPathForSchema(payload, params.JsonPath)
		if err != nil {
			slog.Debug("JSONSchemaGuardrail: Error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
			return p.buildErrorResponse("Error extracting value from JSONPath", err, isResponse, params.ShowAssessment, nil, llm)
		}
		documentLoader = gojsonschema.NewBytesLoader(extractedValue)
	} else {
		documentLoader = gojsonschema.NewBytesLoader(payload)
	}

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		slog.Debug("JSONSchemaGuardrail: Error validating schema", "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error validating schema", err, isResponse, params.ShowAssessment, nil, llm)
	}

	var validationPassed bool
	if params.Invert {
		validationPassed = !result.Valid()
	} else {
		validationPassed = result.Valid()
	}

	if !validationPassed {
		slog.Debug("JSONSchemaGuardrail: Validation failed", "valid", result.Valid(), "invert", params.Invert, "errorCount", len(result.Errors()), "isResponse", isResponse)
		var reason string
		if params.Invert {
			reason = "JSON schema validation passed but invert is enabled"
		} else {
			reason = "JSON schema validation failed"
		}
		return p.buildErrorResponse(reason, nil, isResponse, params.ShowAssessment, result.Errors(), llm)
	}

	slog.Debug("JSONSchemaGuardrail: Validation passed", "invert", params.Invert, "isResponse", isResponse)
	if isResponse {
		return policy.DownstreamResponseModifications{}
	}
	return policy.UpstreamRequestModifications{}
}

// buildErrorResponse builds a policy error response for both request and response phases.
func (p *JSONSchemaGuardrailPolicy) buildErrorResponse(reason string, validationError error, isResponse bool, showAssessment bool, errors []gojsonschema.ResultError, llm bool) interface{} {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment, errors)
	analyticsMetadata := map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  "json-schema-guardrail",
	}

	bodyBytes := guardrailErrorBody(assessment, llm)

	if isResponse {
		statusCode := guardrailStatus(llm)
		return policy.DownstreamResponseModifications{
			StatusCode:        &statusCode,
			Body:              bodyBytes,
			AnalyticsMetadata: analyticsMetadata,
			HeadersToSet:      map[string]string{"Content-Type": "application/json"},
		}
	}

	return policy.ImmediateResponse{
		StatusCode:        guardrailStatus(llm),
		AnalyticsMetadata: analyticsMetadata,
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              bodyBytes,
	}
}

// guardrailErrorBody renders a guardrail intervention: an OpenAI-compatible error
// for LLM APIs, the {"type":"JSON_SCHEMA_GUARDRAIL","message":...} shape for other API kinds.
func guardrailErrorBody(assessment map[string]interface{}, llm bool) []byte {
	if llm {
		return policy.BuildOpenAIErrorResponseBody(policy.GuardrailStatusCode, policy.NewGuardrailOpenAIError(assessment))
	}
	bodyBytes, err := json.Marshal(map[string]interface{}{
		"type":    "JSON_SCHEMA_GUARDRAIL",
		"message": assessment,
	})
	if err != nil {
		return []byte(`{"type":"JSON_SCHEMA_GUARDRAIL","message":"Internal error"}`)
	}
	return bodyBytes
}

// guardrailStatus is the HTTP status of an intervention: 400 on LLM APIs, where
// OpenAI clients expect content-policy refusals as invalid_request_error, and
// GuardrailErrorCode for other API kinds.
func guardrailStatus(llm bool) int {
	if llm {
		return policy.GuardrailStatusCode
	}
	return GuardrailErrorCode
}
