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
	"bytes"
	"encoding/json"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// maxPlainTextMessage is the longest plain-text body used as a message. Anything longer,
// or spanning lines, is more likely a stack trace or a page than a reason.
const maxPlainTextMessage = 1024

// bodyInfo is what the current error body says about the failure.
type bodyInfo struct {
	message   string
	guardrail *guardrailBlock
}

// inspectBody recovers the rejecting policy's message, and a guardrail's assessment, from
// the error body it wrote. It reads nothing from a body that is encoded, empty, or larger
// than maxBytes, so the cost is bounded.
func inspectBody(body []byte, headers *policy.Headers, maxBytes int) bodyInfo {
	if len(body) == 0 || maxBytes <= 0 || len(body) > maxBytes || isEncoded(headers) {
		return bodyInfo{}
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		var doc map[string]interface{}
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return bodyInfo{}
		}
		return bodyInfo{message: messageFromJSON(doc), guardrail: guardrailFromJSON(doc)}
	}

	if !isPlainText(headers) {
		return bodyInfo{}
	}
	text := string(trimmed)
	if text == "" || len(text) > maxPlainTextMessage || strings.ContainsAny(text, "\r\n") {
		return bodyInfo{}
	}
	return bodyInfo{message: text}
}

// messageFromJSON looks for a message in the field names the policy catalogue and common
// error formats use, in priority order:
// error.message, message, message.actionReason, error_description, detail, error.
func messageFromJSON(doc map[string]interface{}) string {
	if inner, ok := doc["error"].(map[string]interface{}); ok {
		if s := nonEmptyString(inner["message"]); s != "" {
			return s
		}
	}
	if s := nonEmptyString(doc["message"]); s != "" {
		return s
	}
	// The shipped guardrails write their assessment object under "message".
	if inner, ok := doc["message"].(map[string]interface{}); ok {
		if s := nonEmptyString(inner["actionReason"]); s != "" {
			return s
		}
	}
	for _, key := range []string{"error_description", "detail", "error"} {
		if s := nonEmptyString(doc[key]); s != "" {
			return s
		}
	}
	return ""
}

// guardrailFromJSON carries over the assessment a shipped guardrail wrote under "message".
// It holds only what the guardrail itself chose to show.
func guardrailFromJSON(doc map[string]interface{}) *guardrailBlock {
	inner, ok := doc["message"].(map[string]interface{})
	if !ok {
		return nil
	}
	name := nonEmptyString(inner["interveningGuardrail"])
	if name == "" {
		return nil
	}
	return &guardrailBlock{
		InterveningGuardrail: name,
		Action:               nonEmptyString(inner["action"]),
		ActionReason:         nonEmptyString(inner["actionReason"]),
		Assessments:          inner["assessments"],
	}
}

func nonEmptyString(v interface{}) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func isEncoded(headers *policy.Headers) bool {
	for _, v := range headers.Get("content-encoding") {
		if v = strings.TrimSpace(strings.ToLower(v)); v != "" && v != "identity" {
			return true
		}
	}
	return false
}

// isPlainText reports whether a non-JSON body may be read as text: either it declares no
// content type, or it declares text/plain.
func isPlainText(headers *policy.Headers) bool {
	types := headers.Get("content-type")
	if len(types) == 0 {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(strings.ToLower(types[0])), "text/plain")
}
