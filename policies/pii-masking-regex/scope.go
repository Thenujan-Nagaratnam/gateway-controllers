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
	"strconv"
	"strings"
)

// Which parts of a request are user content.
//
// With jsonPath "$" the whole payload is in play, but a chat request is two things
// at once: what people and tools said (messages) and what the application
// configured (system prompt, tool definitions, model, limits, schemas). Masking the
// second changes the application's own prompt and breaks tool schemas, so only the
// first is masked. Keys are never masked: a key is structure, not content.
//
// A payload with no "messages" array is not a chat request this policy can scope,
// so every string in it is content, as it always was.

// appKeys are top-level request fields that belong to the application, across the
// Anthropic Messages, OpenAI chat, Bedrock and Azure shapes.
var appKeys = map[string]bool{
	"system": true, "tools": true, "tool_choice": true, "metadata": true, "stop_sequences": true,
	"stop": true, "mcp_servers": true, "container": true, "betas": true, "model": true,
	"max_tokens": true, "max_completion_tokens": true, "max_output_tokens": true, "temperature": true,
	"top_p": true, "top_k": true, "seed": true, "n": true, "stream": true, "stream_options": true,
	"thinking": true, "frequency_penalty": true, "presence_penalty": true, "logprobs": true,
	"top_logprobs": true, "logit_bias": true, "response_format": true, "functions": true,
	"function_call": true, "parallel_tool_calls": true, "anthropic_version": true, "anthropic_beta": true,
	"toolConfig": true, "tool_config": true, "inferenceConfig": true, "output_config": true,
	"service_tier": true, "store": true, "reasoning_effort": true, "modalities": true,
	"audio": true, "prediction": true, "web_search_options": true,
}

// collectTargets returns the string and number nodes to scan for PII.
func collectTargets(b []byte, root *node) []*node {
	var out []*node
	if root.kind == kindObject {
		if msgs := root.get("messages"); msgs != nil && msgs.kind == kindArray {
			for i, k := range root.keys {
				v := root.kids[i]
				switch {
				case k == "messages":
					out = walkMessages(b, v, out)
				case appKeys[k]:
					// application configuration: untouched
				default:
					out = walkAll(v, out)
				}
			}
			return out
		}
	}
	return walkAll(root, out)
}

// walkAll adds every string and number value under n. Keys are not nodes, so they
// are never included.
func walkAll(n *node, out []*node) []*node {
	switch n.kind {
	case kindString, kindNumber:
		return append(out, n)
	case kindObject, kindArray:
		for _, c := range n.kids {
			out = walkAll(c, out)
		}
	}
	return out
}

// walkStrings adds every string value under n and no numbers.
func walkStrings(n *node, out []*node) []*node {
	switch n.kind {
	case kindString:
		return append(out, n)
	case kindObject, kindArray:
		for _, c := range n.kids {
			out = walkStrings(c, out)
		}
	}
	return out
}

func walkMessages(b []byte, arr *node, out []*node) []*node {
	for _, m := range arr.kids {
		if m.kind != kindObject {
			continue
		}
		if role, ok := m.get("role").str(b); ok && (role == "system" || role == "developer") {
			continue // the application's own prompt
		}
		for i, k := range m.keys {
			v := m.kids[i]
			switch k {
			case "content":
				out = walkContent(b, v, out)
			case "tool_calls":
				for _, call := range v.kids {
					if args := call.get("function").get("arguments"); args != nil && args.kind == kindString {
						out = append(out, args)
					}
				}
			case "function_call":
				if args := v.get("arguments"); args != nil && args.kind == kindString {
					out = append(out, args)
				}
			case "refusal", "reasoning_content", "reasoning":
				if v.kind == kindString {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

// walkContent handles a message's content: a string, or an array of blocks.
func walkContent(b []byte, n *node, out []*node) []*node {
	switch n.kind {
	case kindString:
		return append(out, n)
	case kindArray:
		for _, blk := range n.kids {
			if blk.kind == kindObject {
				out = walkBlock(b, blk, out)
			} else if blk.kind == kindString {
				out = append(out, blk)
			}
		}
	}
	return out
}

func walkBlock(b []byte, blk *node, out []*node) []*node {
	typ, _ := blk.get("type").str(b)
	switch typ {
	case "text", "input_text", "output_text":
		if t := blk.get("text"); t != nil && t.kind == kindString {
			out = append(out, t)
		}
	case "tool_result":
		if c := blk.get("content"); c != nil {
			out = walkContent(b, c, out)
		}
	case "tool_use", "server_tool_use", "mcp_tool_use":
		// Strings only: a number here is a typed argument, and masking it would
		// turn it into a string.
		if in := blk.get("input"); in != nil {
			out = walkStrings(in, out)
		}
	case "thinking":
		if t := blk.get("thinking"); t != nil && t.kind == kindString {
			out = append(out, t) // the signature is opaque and never touched
		}
	case "document":
		src := blk.get("source")
		if st, _ := src.get("type").str(b); st == "text" {
			if d := src.get("data"); d != nil && d.kind == kindString {
				out = append(out, d)
			}
		}
	case "redacted_thinking", "image", "image_url", "input_audio", "audio", "file":
		// opaque or binary data
	case "":
		// Bedrock Converse blocks have no type: {"text": ...}, {"toolUse": ...}.
		if t := blk.get("text"); t != nil && t.kind == kindString {
			out = append(out, t)
		}
		if tr := blk.get("toolResult"); tr != nil {
			if c := tr.get("content"); c != nil {
				out = walkContent(b, c, out)
			}
		}
		if tu := blk.get("toolUse"); tu != nil {
			if in := tu.get("input"); in != nil {
				out = walkStrings(in, out)
			}
		}
	default:
		if t := blk.get("text"); t != nil && t.kind == kindString {
			out = append(out, t)
		}
	}
	return out
}

// ─── jsonPath resolution on the scanned tree ─────────────────────────────────

// resolvePath finds the value a simple JSONPath points at: $, .key, ['key'],
// ["key"], [n] and [-n]. It returns false for anything else, so the caller can
// fall back to the general JSONPath library.
func resolvePath(root *node, path string) (*node, bool) {
	if !strings.HasPrefix(path, "$") {
		return nil, false
	}
	cur := root
	rest := path[1:]
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
			if cur == nil || cur.kind != kindObject {
				return nil, false
			}
			if cur = cur.get(key); cur == nil {
				return nil, false
			}
		case rest[0] == '[':
			close := strings.Index(rest, "]")
			if close < 0 {
				return nil, false
			}
			inner := rest[1:close]
			rest = rest[close+1:]
			if len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') && inner[len(inner)-1] == inner[0] {
				key := inner[1 : len(inner)-1]
				if cur == nil || cur.kind != kindObject {
					return nil, false
				}
				if cur = cur.get(key); cur == nil {
					return nil, false
				}
				continue
			}
			idx, err := strconv.Atoi(inner)
			if err != nil || cur == nil || cur.kind != kindArray {
				return nil, false
			}
			if idx < 0 {
				idx += len(cur.kids)
			}
			if idx < 0 || idx >= len(cur.kids) {
				return nil, false
			}
			cur = cur.kids[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}
