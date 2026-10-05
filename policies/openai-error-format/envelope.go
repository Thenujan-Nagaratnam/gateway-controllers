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

package openaierrorformat

import (
	"encoding/json"
	"net/http"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// envelope is the OpenAI error object: {"error":{"message","type","param","code"}}.
type envelope struct {
	Error openAIError `json:"error"`
}

// openAIError carries the four fields every OpenAI SDK reads. Param is always null and
// Code is null when the failure has no code, so both are pointers without omitempty.
//
// FaultDetails.Description is deliberately absent: it is internal detail that must never
// reach the client.
type openAIError struct {
	Message   string          `json:"message"`
	Type      string          `json:"type"`
	Param     *string         `json:"param"`
	Code      *string         `json:"code"`
	Guardrail *guardrailBlock `json:"guardrail,omitempty"`
}

// guardrailBlock mirrors the gateway's own rendering of FaultDetails.Guardrail, field for
// field, so a client that already reads it reads this one too. Assessments is rendered only
// as the guardrail supplied it: the shipped guardrails populate it only when their own
// showAssessment parameter allows. It is `any` because a guardrail's own body may carry it
// as a string rather than an object.
type guardrailBlock struct {
	InterveningGuardrail string `json:"interveningGuardrail,omitempty"`
	Action               string `json:"action,omitempty"`
	ActionReason         string `json:"actionReason,omitempty"`
	Assessments          any    `json:"assessments,omitempty"`
}

// faultTypeToOpenAI maps the gateway's failure classes to OpenAI's error type names.
// A class missing here (mediation, configuration, or one added later) falls back to the
// status code.
var faultTypeToOpenAI = map[string]string{
	policy.FaultTypeAuthentication: "authentication_error",
	policy.FaultTypeAuthorization:  "permission_error",
	policy.FaultTypeThrottling:     "rate_limit_error",
	policy.FaultTypeGuardrail:      "invalid_request_error",
	policy.FaultTypeValidation:     "invalid_request_error",
	policy.FaultTypeRequestSize:    "invalid_request_error",
	policy.FaultTypeRouting:        "not_found_error",
	policy.FaultTypeUpstream:       "server_error",
	policy.FaultTypeInternal:       "server_error",
}

// errorType returns the OpenAI error type for a failure class, or for the status when the
// class is absent or has no OpenAI equivalent.
func errorType(faultType string, status int) string {
	if t, ok := faultTypeToOpenAI[faultType]; ok {
		return t
	}
	switch {
	case status == http.StatusUnauthorized:
		return "authentication_error"
	case status == http.StatusForbidden:
		return "permission_error"
	case status == http.StatusNotFound:
		return "not_found_error"
	case status == http.StatusTooManyRequests:
		return "rate_limit_error"
	case status >= 400 && status < 500:
		return "invalid_request_error"
	default:
		return "server_error"
	}
}

// buildEnvelope renders the OpenAI error body. f may be nil. bodyGuardrail is the
// assessment found in the policy's own body, used only when the fault carries none.
func buildEnvelope(f *policy.FaultDetails, status int, message string, bodyGuardrail *guardrailBlock) ([]byte, error) {
	e := openAIError{Message: message, Guardrail: bodyGuardrail}
	var faultType string
	if f != nil {
		faultType = f.Type
		if f.Code != "" {
			code := f.Code
			e.Code = &code
		}
		if g := f.Guardrail; g != nil {
			e.Guardrail = &guardrailBlock{
				InterveningGuardrail: g.InterveningGuardrail,
				Action:               g.Action,
				ActionReason:         g.ActionReason,
			}
			// A typed nil map inside `any` is not omitted, so set it only when there is content.
			if len(g.Assessments) > 0 {
				e.Guardrail.Assessments = g.Assessments
			}
		}
	}
	e.Type = errorType(faultType, status)
	return json.Marshal(envelope{Error: e})
}

// maxEnvelopeCheckBytes bounds the already-an-envelope check. It is independent of
// maxInspectBytes so that turning message recovery off never makes the policy rewrite an
// envelope that is already there.
const maxEnvelopeCheckBytes = 64 * 1024

// isOpenAIEnvelope reports whether body is already an OpenAI error object: a JSON object
// whose only key is "error", holding an object with a string message and a string type.
func isOpenAIEnvelope(body []byte) bool {
	if len(body) == 0 || len(body) > maxEnvelopeCheckBytes {
		return false
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil || len(doc) != 1 {
		return false
	}
	raw, ok := doc["error"]
	if !ok {
		return false
	}
	var inner map[string]interface{}
	if err := json.Unmarshal(raw, &inner); err != nil {
		return false
	}
	_, hasMessage := inner["message"].(string)
	_, hasType := inner["type"].(string)
	return hasMessage && hasType
}
