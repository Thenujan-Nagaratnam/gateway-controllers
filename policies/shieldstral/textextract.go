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

package shieldstral

import (
	"encoding/json"
	"strings"
)

// maxCollectDepth bounds recursion into nested content so a hostile document cannot
// overflow the stack.
const maxCollectDepth = 32

// extractTexts evaluates path against a JSON payload and returns every piece of text the
// selected nodes carry. An empty path means "the whole payload is the text", for routes
// that carry plain text.
//
// What counts as text, for each selected node:
//   - a string is text;
//   - an array contributes the text of each element;
//   - an object contributes its "text" string (OpenAI / Anthropic / Gemini content parts,
//     `{"type":"text","text":"..."}`) and, if it has none, the text of its "content"
//     (a chat message selected whole, `{"role":"user","content":[...]}`);
//   - numbers, booleans and null carry none, and neither do non-text parts such as images.
//
// A path that selects nothing, or nodes with no text (an assistant message that only made a
// tool call has null content; a provider's error body has no choices), is not an error: there
// is simply nothing to check, and the payload passes. Only a body that is not JSON at all
// cannot be read.
func extractTexts(payload []byte, path *jsonPath, rawPath string) ([]string, error) {
	if rawPath == "" {
		return []string{string(payload)}, nil
	}
	nodes, err := selectNodes(payload, path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range nodes {
		collectText(n, &out, 0)
	}
	return out, nil
}

func collectText(node interface{}, out *[]string, depth int) {
	if depth > maxCollectDepth {
		return
	}
	switch v := node.(type) {
	case string:
		*out = append(*out, v)
	case []interface{}:
		for _, e := range v {
			collectText(e, out, depth+1)
		}
	case map[string]interface{}:
		if t, ok := v["text"].(string); ok {
			*out = append(*out, t)
			return
		}
		if c, ok := v["content"]; ok {
			collectText(c, out, depth+1)
		}
	}
}

// ─── Server-sent events ─────────────────────────────────────────────────────

const (
	sseDataField = "data:"
	sseDone      = "[DONE]"
)

// nextLine splits off the first line of s, dropping its terminator ("\n" or "\r\n").
func nextLine(s string) (line, rest string) {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSuffix(s[:i], "\r"), s[i+1:]
	}
	return strings.TrimSuffix(s, "\r"), ""
}

// isSSEFieldLine reports whether a line is a server-sent-event field or comment line.
func isSSEFieldLine(line string) bool {
	return strings.HasPrefix(line, ":") ||
		strings.HasPrefix(line, "data:") ||
		strings.HasPrefix(line, "event:") ||
		strings.HasPrefix(line, "id:") ||
		strings.HasPrefix(line, "retry:")
}

// looksLikeSSE reports whether s is server-sent events rather than a JSON document: its
// first non-blank line is an SSE field or comment line.
func looksLikeSSE(s string) bool {
	for rest := s; rest != ""; {
		var line string
		line, rest = nextLine(rest)
		if strings.TrimSpace(line) == "" {
			continue
		}
		return isSSEFieldLine(line)
	}
	return false
}

// sseDataPayload returns the value of a "data:" line (one optional leading space is part of
// the syntax and is dropped) and whether the line is a data line.
func sseDataPayload(line string) (string, bool) {
	if !strings.HasPrefix(line, sseDataField) {
		return "", false
	}
	return strings.TrimPrefix(line[len(sseDataField):], " "), true
}

// sseFrameTexts returns the text carried by every complete "data:" line in s, reading each
// frame's JSON with path. Frames that are not JSON, are "[DONE]", or carry no text at the
// path (role deltas, usage frames, comments) contribute nothing.
func sseFrameTexts(s string, path *jsonPath) []string {
	var out []string
	for rest := s; rest != ""; {
		var line string
		line, rest = nextLine(rest)
		payload, ok := sseDataPayload(line)
		if !ok {
			continue
		}
		payload = strings.TrimSpace(payload)
		if payload == "" || payload == sseDone {
			continue
		}
		var doc interface{}
		if err := json.Unmarshal([]byte(payload), &doc); err != nil {
			continue
		}
		nodes, err := path.evaluate(doc)
		if err != nil {
			continue
		}
		for _, n := range nodes {
			collectText(n, &out, 0)
		}
	}
	return out
}

// endsAtSSEEventBoundary reports whether s ends where one event ends, so a flush released
// there never cuts a "data:" line in half. Both "\n\n" and "\r\n\r\n" terminate an event.
func endsAtSSEEventBoundary(s []byte) bool {
	t := string(s)
	return strings.HasSuffix(t, "\n\n") || strings.HasSuffix(t, "\r\n\r\n")
}

// looksLikeJSONDocument reports whether b opens a JSON object or array, ignoring leading
// whitespace. A test of the first meaningful byte, not a parse, so a partial document
// answers the same as a complete one.
func looksLikeJSONDocument(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// splitTrailingPartialLine splits s at its last newline: complete lines, then the unfinished
// line after it (empty when s ends in a newline).
func splitTrailingPartialLine(s string) (complete, partial string) {
	i := strings.LastIndexByte(s, '\n')
	if i < 0 {
		return "", s
	}
	return s[:i+1], s[i+1:]
}
