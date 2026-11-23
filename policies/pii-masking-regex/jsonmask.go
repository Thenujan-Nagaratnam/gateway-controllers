/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package piimaskingregex

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
)

// With jsonPath "$" the payload is a JSON document, so it is masked as one: the regexes
// run on decoded string values, never on the raw text, and the result is encoded again.
// Raw-text masking turned an escape letter next to an email, or part of a number, into
// part of a match and produced invalid JSON.

// appKeys are top-level request fields that belong to the application rather than to the
// users: the system prompt, tool definitions, model and other parameters.
var appKeys = map[string]bool{
	"system": true, "tools": true, "tool_choice": true, "metadata": true, "stop_sequences": true,
	"stop": true, "mcp_servers": true, "container": true, "betas": true, "model": true,
	"max_tokens": true, "max_completion_tokens": true, "temperature": true, "top_p": true,
	"top_k": true, "seed": true, "n": true, "stream": true, "thinking": true,
	"response_format": true, "functions": true, "function_call": true,
}

// opaqueKeys hold ids and signatures that must reach the upstream exactly as sent.
var opaqueKeys = map[string]bool{"id": true, "tool_use_id": true, "tool_call_id": true, "signature": true}

// opaqueTypes are content blocks that carry binary or encrypted data.
var opaqueTypes = map[string]bool{"image": true, "base64": true, "redacted_thinking": true}

// maskJSONPayload masks a JSON document. ok is false when payload is not JSON, so the
// caller can fall back to masking it as text.
func (p *PIIMaskingRegexPolicy) maskJSONPayload(payload []byte, metadata map[string]interface{}) (out []byte, changed, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber() // keep number literals as they were written
	var doc interface{}
	if err := dec.Decode(&doc); err != nil {
		return nil, false, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false, false
	}

	st := newMaskState()
	hits := false
	doc = p.maskValue(doc, st, &hits, true)
	if !hits {
		return payload, false, true
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, false, false
	}
	if !p.params.RedactPII {
		recordMapping(metadata, st.placeholders)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), true, true
}

// maskValue masks the strings under v. Keys are never touched.
func (p *PIIMaskingRegexPolicy) maskValue(v interface{}, st *maskState, hits *bool, top bool) interface{} {
	switch t := v.(type) {
	case string:
		return p.maskString(t, st, hits)
	case json.Number:
		// Only a number that is entirely PII is replaced, by a string. A match inside a
		// longer number is a coincidence of digits.
		if entity, whole := p.wholeMatch(t.String()); whole && !st.noNumbers {
			*hits = true
			if p.params.RedactPII {
				return redactedText
			}
			return st.placeholderFor(entity, t.String())
		}
		return t
	case []interface{}:
		for i := range t {
			t[i] = p.maskValue(t[i], st, hits, false)
		}
	case map[string]interface{}:
		if typ, _ := t["type"].(string); opaqueTypes[typ] {
			return t
		}
		if role, _ := t["role"].(string); role == "system" || role == "developer" {
			return t // the application's own prompt
		}
		_, chat := t["messages"].([]interface{})
		if top && chat {
			st.noNumbers = true // a number in a chat request is a typed argument, not a value to hide
		}
		for k, val := range t {
			switch {
			case opaqueKeys[k]:
			case top && chat && appKeys[k]:
			case k == "role" || k == "type":
			default:
				t[k] = p.maskValue(val, st, hits, false)
			}
		}
	}
	return v
}

// maskString masks or redacts one string value.
func (p *PIIMaskingRegexPolicy) maskString(s string, st *maskState, hits *bool) string {
	if p.params.RedactPII {
		if r := p.redactPIIFromContent(s, p.params.PIIEntities); r != "" {
			*hits = true
			return r
		}
		return s
	}
	before := len(st.placeholders)
	masked := p.maskText(s, p.params.PIIEntities, st)
	if masked != s || len(st.placeholders) != before {
		*hits = true
	}
	return masked
}

// redactedText replaces a value when redactPII is on.
const redactedText = "*****"

// wholeMatch reports the entity whose pattern matches all of s.
func (p *PIIMaskingRegexPolicy) wholeMatch(s string) (string, bool) {
	names := make([]string, 0, len(p.params.PIIEntities))
	for name := range p.params.PIIEntities {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if loc := p.params.PIIEntities[name].FindStringIndex(s); loc != nil && loc[0] == 0 && loc[1] == len(s) {
			return name, true
		}
	}
	return "", false
}
