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
	"strconv"
	"strings"
)

// What jsonPath "$" masks.
//
// "$" is the whole payload: every string value in it is masked, the system prompt
// and the tool definitions included. Choosing a subset is the job of a more
// specific jsonPath, not of "$".
//
// What is never touched, because changing it breaks the request rather than
// protecting anyone:
//
//   - Keys. A key is structure, not content.
//   - Signed or binary strings (opaqueString): a thinking signature, a base64 image
//     or a tool-call id only validates byte for byte.
//   - Numbers the API defines as numbers (typedNumber): a schema bound, a token
//     limit, a tool argument. Turning one into a placeholder string changes its
//     type and the upstream rejects the request.
//
// Any other number is data. When the whole literal is PII, it is replaced by a
// placeholder string, as it always was, so a numeric phone field does not leak.

// collectTargets returns every string and number node of the document that may
// hold PII.
func collectTargets(b []byte, root *node) []*node {
	return walkValues(b, root, "", nil, false, nil)
}

// typedSubtrees hold values whose types are fixed by the API: no number under
// these keys is ever replaced.
var typedSubtrees = map[string]bool{
	"tools": true, "functions": true, "tool_choice": true, "toolConfig": true, "tool_config": true,
	"response_format": true, "output_config": true, "inferenceConfig": true, "thinking": true,
	"input_schema": true, "inputSchema": true, "json_schema": true,
}

// typedNumberKeys are numeric request parameters, wherever they appear.
var typedNumberKeys = map[string]bool{
	"max_tokens": true, "max_completion_tokens": true, "max_output_tokens": true, "maxTokens": true,
	"temperature": true, "top_p": true, "topP": true, "top_k": true, "topK": true, "seed": true,
	"frequency_penalty": true, "presence_penalty": true, "top_logprobs": true, "budget_tokens": true,
}

// opaqueKeys hold signed or binary data under any parent.
var opaqueKeys = map[string]bool{
	"signature": true, "encrypted_content": true, "encrypted_index": true, "file_data": true, "bytes": true,
}

// idKeys hold the ids that tie a tool call to its result. The upstream validates
// their alphabet and compares them, so a placeholder in one breaks the pairing.
var idKeys = map[string]bool{
	"tool_use_id": true, "tool_call_id": true, "call_id": true, "toolUseId": true,
}

// toolTypes are block and call types whose "id" is a protocol identifier.
var toolTypes = map[string]bool{
	"tool_use": true, "server_tool_use": true, "mcp_tool_use": true,
	"function": true, "tool_call": true, "function_call": true,
}

// walkValues adds every maskable string and number under n. key is the name n sits
// under in its parent, which is what tells a signature from a sentence; typed says
// n is inside a subtree whose numbers must stay numbers.
func walkValues(b []byte, n *node, key string, parent *node, typed bool, out []*node) []*node {
	switch n.kind {
	case kindString:
		if !opaqueString(b, n, key, parent) {
			out = append(out, n)
		}
	case kindNumber:
		if !typed && !typedNumberKeys[key] {
			out = append(out, n)
		}
	case kindObject:
		for i, k := range n.keys {
			t := typed || typedSubtrees[k]
			if k == "input" && (key == "toolUse" || toolTypes[typeOf(b, n)]) {
				t = true // a tool call's arguments keep their types
			}
			out = walkValues(b, n.kids[i], k, n, t, out)
		}
	case kindArray:
		for _, c := range n.kids {
			out = walkValues(b, c, key, parent, typed, out)
		}
	}
	return out
}

// typeOf returns the "type" string of an object, or "".
func typeOf(b []byte, n *node) string {
	t, _ := n.get("type").str(b)
	return t
}

// typedContext reports whether n sits inside a subtree whose numbers must stay
// numbers: tool definitions, schemas, response formats, or a tool call's input.
func typedContext(b []byte, n *node) bool {
	for cur := n; cur != nil; cur = cur.parent {
		if typedSubtrees[cur.key] {
			return true
		}
		if cur.key == "input" && cur.parent != nil && (cur.parent.key == "toolUse" || toolTypes[typeOf(b, cur.parent)]) {
			return true
		}
	}
	return false
}

// opaqueString reports whether the string n (the value of key in parent) is binary
// or signed data that must reach the upstream exactly as the client sent it.
func opaqueString(b []byte, n *node, key string, parent *node) bool {
	raw := b[n.start:n.end]
	if idKeys[key] {
		return identifierLike(raw)
	}
	if opaqueKeys[key] {
		// Signed and encoded values are one unbroken token. Anything that reads as
		// text or an address under the same key (an email "signature") is masked.
		return tokenLike(raw)
	}
	if key == "id" && parent != nil {
		if t, _ := parent.get("type").str(b); toolTypes[t] && identifierLike(raw) {
			return true
		}
	}
	if key == "data" && parent != nil {
		if t, _ := parent.get("type").str(b); t == "base64" || t == "redacted_thinking" {
			return true
		}
		// Binary payloads that name their media type or format (input_audio,
		// inline_data, Bedrock sources): opaque when the value is encoded data, not
		// when the same fields wrap plain text such as a CSV.
		for _, k := range []string{"format", "mime_type", "mimeType"} {
			if parent.get(k) != nil {
				return tokenLike(raw)
			}
		}
	}
	if key == "url" || key == "data" {
		// data: URLs (inline images and files)
		return bytes.HasPrefix(raw, []byte(`"data:`)) && bytes.Contains(raw, []byte(";base64,"))
	}
	return false
}

// identifierLike reports whether a JSON string literal reads as an id: letters,
// digits, underscore, dash, at least one letter and no spaces or address
// characters. A bare phone number or an email address is not one.
func identifierLike(raw []byte) bool {
	if len(raw) < 8 { // 6 characters and the quotes
		return false
	}
	letter := false
	for _, c := range raw[1 : len(raw)-1] {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			letter = true
		case c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return letter
}

// tokenLike reports whether a JSON string literal is a long run of base64 or
// identifier characters, with no spaces, punctuation or address characters: the
// shape of a signature, an id or encoded data, never of a sentence or a contact.
func tokenLike(raw []byte) bool {
	if len(raw) < 18 { // 16 characters and the quotes
		return false
	}
	for _, c := range raw[1 : len(raw)-1] {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '+', c == '/', c == '=', c == '_', c == '-', c == '\\':
		default:
			return false
		}
	}
	return true
}

// ─── jsonPath resolution on the scanned tree ─────────────────────────────────

// resolvePath finds the values a simple JSONPath points at: $, .key, ['key'],
// ["key"], [n] and [-n]. A key written twice in one object yields every copy. It
// returns false for anything else, so the caller can fall back to the general
// JSONPath library.
func resolvePath(root *node, path string) ([]*node, bool) {
	if !strings.HasPrefix(path, "$") {
		return nil, false
	}
	cur := []*node{root}
	rest := path[1:]
	step := func(key string) bool {
		var next []*node
		for _, c := range cur {
			next = append(next, c.getAll(key)...)
		}
		cur = next
		return len(cur) > 0
	}
	for rest != "" {
		switch {
		case rest[0] == '.':
			end := 1
			for end < len(rest) && rest[end] != '.' && rest[end] != '[' {
				end++
			}
			key := rest[1:end]
			if key == "" || key == "*" || strings.ContainsAny(key, "?()@,:") {
				return nil, false
			}
			rest = rest[end:]
			if !step(key) {
				return nil, false
			}
		case rest[0] == '[':
			// A quoted name may itself contain "]" or an escaped quote, so read it
			// as a string rather than looking for the next bracket.
			if len(rest) > 1 && (rest[1] == '\'' || rest[1] == '"') {
				key, n, ok := readQuotedName(rest[1:])
				if !ok || len(rest) < 1+n+1 || rest[1+n] != ']' {
					return nil, false
				}
				rest = rest[1+n+1:]
				if !step(key) {
					return nil, false
				}
				continue
			}
			close := strings.Index(rest, "]")
			if close < 0 {
				return nil, false
			}
			inner := rest[1:close]
			rest = rest[close+1:]
			idx, err := strconv.Atoi(inner)
			if err != nil {
				return nil, false
			}
			var next []*node
			for _, c := range cur {
				if c.kind != kindArray {
					continue
				}
				i := idx
				if i < 0 {
					i += len(c.kids)
				}
				if i >= 0 && i < len(c.kids) {
					next = append(next, c.kids[i])
				}
			}
			if len(next) == 0 {
				return nil, false
			}
			cur = next
		default:
			return nil, false
		}
	}
	return cur, true
}

// readQuotedName reads a quoted member name from the start of s (which begins
// with the quote) and returns the name, and how many bytes of s it used,
// including both quotes. It understands the escapes RFC 9535 allows.
func readQuotedName(s string) (string, int, bool) {
	q := s[0]
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == q:
			return b.String(), i + 1, true
		case c == '\\' && i+1 < len(s):
			i++
			switch s[i] {
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '/', '\\', '\'', '"':
				b.WriteByte(s[i])
			case 'u':
				if i+4 >= len(s) {
					return "", 0, false
				}
				v, err := strconv.ParseUint(s[i+1:i+5], 16, 32)
				if err != nil {
					return "", 0, false
				}
				b.WriteRune(rune(v))
				i += 4
			default:
				return "", 0, false
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, false
}
