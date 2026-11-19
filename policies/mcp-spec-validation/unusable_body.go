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

package mcpspecvalidation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// unusableBodyReason returns why the body cannot be read, or "" if it can. Mirrors the MCP
// resolver (policy-engine internal/resolver/mcp.go, mcp_ambiguity.go); keep the two in step.
func unusableBodyReason(body []byte) string {
	body = bytes.TrimLeft(body, " \t\r\n")
	if len(body) == 0 {
		return ""
	}
	// A batch array or a bare scalar names no single operation.
	if body[0] != '{' {
		return reasonNotAnObject
	}
	// Before the unmarshal, which silently keeps only the last of a repeated member.
	if hasAmbiguousMembers(body) {
		return reasonAmbiguous
	}

	var envelope struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return reasonSyntaxError
		}
		return reasonInvalidMemberType
	}

	// Inside params only the members the resolver reads a fact from are type-checked, and on
	// their own: encoding/json reports only the first type error, so a wrong-typed telemetry
	// member earlier in the object would otherwise hide one of these. The resolver accepts any
	// other member, and a stricter check here would reject bodies a resolver gateway forwards.
	if isJSONObject(envelope.Params) {
		var governed struct {
			Name            string `json:"name"`
			URI             string `json:"uri"`
			TaskID          string `json:"taskId"`
			ProtocolVersion string `json:"protocolVersion"`
		}
		var typeErr *json.UnmarshalTypeError
		if err := json.Unmarshal(envelope.Params, &governed); errors.As(err, &typeErr) {
			return reasonInvalidMemberType
		}
	}
	return ""
}

// Members the resolver reads. encoding/json matches names case-insensitively and keeps the
// last match, so naming one twice or in another letter case lets the backend read a different
// value than the gateway did.
var (
	envelopeMembers = []string{"method", "id", "params"}
	paramsMembers   = []string{"name", "uri", "taskId", "protocolVersion", "requestState", "_meta"}

	// clientInfo is deliberately absent: it is self-reported telemetry no policy governs on, so
	// two spellings of it can only disagree about who is calling, never about what the server
	// will execute - and an ambiguous body suppresses every fact. The resolver omits it too.
)

// hasAmbiguousMembers checks the envelope members, and the params members when params is an
// object. A body that is not a well-formed object is left to the unmarshal to classify.
func hasAmbiguousMembers(body []byte) bool {
	members, ok := objectMembers(body)
	if !ok {
		return false
	}
	if foldsOntoOneName(members, envelopeMembers) {
		return true
	}
	for _, member := range members {
		if member.name != "params" || !isJSONObject(member.value) {
			continue
		}
		params, ok := objectMembers(member.value)
		if !ok {
			return false
		}
		if foldsOntoOneName(params, paramsMembers) {
			return true
		}
	}
	return false
}

// jsonMember is one object member. A slice of these keeps repeated names that a map would merge.
type jsonMember struct {
	name  string
	value json.RawMessage
}

// objectMembers returns an object's members in document order, duplicates included. ok is
// false for anything that is not a well-formed object.
func objectMembers(raw []byte) ([]jsonMember, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	if delim, isDelim := tok.(json.Delim); !isDelim || delim != '{' {
		return nil, false
	}
	var members []jsonMember
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		name, isString := tok.(string)
		if !isString {
			return nil, false
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		members = append(members, jsonMember{name: name, value: value})
	}

	// The closing brace, then end of input. Without this, bytes after a complete object are
	// unread and a malformed body reports the wrong reason: {"method":"a","method":"b"}x is a
	// syntax error, not two readings of one member, and the unmarshal above classifies it so.
	if _, err := dec.Token(); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return members, true
}

// foldsOntoOneName reports a canonical name that appears twice, or in another letter case.
// A non-canonical spelling counts even alone: encoding/json accepts "Method" as "method",
// while a strict backend sees no method at all.
func foldsOntoOneName(members []jsonMember, canonical []string) bool {
	seen := make(map[string]bool, len(canonical))
	for _, member := range members {
		match := ""
		for _, name := range canonical {
			// EqualFold matches the way encoding/json does, Unicode folding included.
			if strings.EqualFold(member.name, name) {
				match = name
				break
			}
		}
		if match == "" {
			continue
		}
		if seen[match] || member.name != match {
			return true
		}
		seen[match] = true
	}
	return false
}

// isJSONObject reports whether raw is an object rather than another JSON value.
func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}
