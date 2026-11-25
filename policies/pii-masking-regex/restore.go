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

package piimaskingregex

import (
	"encoding/json"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// fragmentKind says what a streamed text fragment carries, which decides how a
// restored value must be written back.
type fragmentKind int

const (
	// kindText is assistant text: the original value is written as is.
	kindText fragmentKind = iota
	// kindToolArguments is a fragment of JSON text (input_json_delta). The
	// original value lands inside a JSON string of that text, so it must be
	// JSON-escaped once before the event itself is encoded.
	kindToolArguments
	// kindThinking is reasoning text, restored like assistant text.
	kindThinking
)

func kindOfPath(path string) fragmentKind {
	switch path {
	case "$.delta.partial_json":
		return kindToolArguments
	case "$.delta.thinking":
		return kindThinking
	default:
		return kindText
	}
}

// streamFragment is the text carried by one SSE data event.
type streamFragment struct {
	lineIdx int
	text    string
	path    string
}

// fragmentGroup is the text of one content block within a flushed batch. Text
// from different blocks is never joined, so a later block keeps its own text.
type fragmentGroup struct {
	kind      fragmentKind
	fragments []streamFragment
}

// groupKey identifies the content block an event belongs to: the delta kind and
// the event's "index" (the block number in Anthropic Messages). Shapes that have
// no block index share one group per kind, which is how they were handled before.
func groupKey(jsonStr, path string) string {
	var ev struct {
		Index *int `json:"index"`
	}
	idx := "-"
	if err := json.Unmarshal([]byte(jsonStr), &ev); err == nil && ev.Index != nil {
		idx = strconv.Itoa(*ev.Index)
	}
	return strconv.Itoa(int(kindOfPath(path))) + ":" + idx
}

// collectFragmentGroups reads every SSE data line in lines and returns the
// content groups in order of first appearance.
func collectFragmentGroups(lines []string) ([]string, map[string]*fragmentGroup) {
	var order []string
	groups := make(map[string]*fragmentGroup)
	for i, line := range lines {
		jsonStr, ok := sseDataPayload(line)
		if !ok || jsonStr == sseDone {
			continue
		}
		text, path := extractFirstDeltaContentKeyed(jsonStr, DefaultStreamingJSONPaths)
		if text == "" {
			continue
		}
		key := groupKey(jsonStr, path)
		g, exists := groups[key]
		if !exists {
			g = &fragmentGroup{kind: kindOfPath(path)}
			groups[key] = g
			order = append(order, key)
		}
		g.fragments = append(g.fragments, streamFragment{lineIdx: i, text: text, path: path})
	}
	return order, groups
}

func (g *fragmentGroup) joined() string {
	var sb strings.Builder
	for _, f := range g.fragments {
		sb.WriteString(f.text)
	}
	return sb.String()
}

// anyGroupCouldCompletePlaceholder reports whether the joined text of any content
// block ends in an unclosed "[" that could still become a placeholder.
func anyGroupCouldCompletePlaceholder(s string) bool {
	order, groups := collectFragmentGroups(strings.Split(s, "\n"))
	for _, key := range order {
		if couldCompletePlaceholder(groups[key].joined()) {
			return true
		}
	}
	return false
}

// restoreForKind restores placeholders in text. For tool-call arguments the
// original is JSON-escaped first, because the text is itself JSON.
func restoreForKind(kind fragmentKind, text string, placeholderToOriginal map[string]string) string {
	if kind != kindToolArguments {
		return restore(text, placeholderToOriginal)
	}
	result := text
	for placeholder, original := range placeholderToOriginal {
		if !strings.Contains(result, placeholder) {
			continue
		}
		encoded, err := json.Marshal(original)
		if err != nil || len(encoded) < 2 {
			continue
		}
		result = strings.ReplaceAll(result, placeholder, string(encoded[1:len(encoded)-1]))
	}
	return result
}

// restoreSSEChunk handles SSE streaming format: "data: {...}" lines.
//
// When the accumulator flushes a batch of SSE events (for example the placeholder
// [EMAIL_3fa91c0b] split across "[", "EMAIL", "_3fa9", "1c0b]" in separate
// events), no single event holds the full placeholder. The fragments of one
// content block are therefore joined, restored together, and written into that
// block's first event; the block's other text events are dropped. A different
// block in the same batch is restored on its own and keeps its own events.
func (p *PIIMaskingRegexPolicy) restoreSSEChunk(chunkStr string, placeholderToOriginal map[string]string) policy.ForwardResponseChunk {
	lines := strings.Split(chunkStr, "\n")
	order, groups := collectFragmentGroups(lines)
	if len(order) == 0 {
		return policy.ForwardResponseChunk{}
	}

	removeLines := make(map[int]bool)
	changed := false
	for _, key := range order {
		g := groups[key]
		full := g.joined()
		restored := restoreForKind(g.kind, full, placeholderToOriginal)
		if restored == full {
			continue
		}
		changed = true
		first := g.fragments[0]
		lines[first.lineIdx] = replaceContentInSSELine(lines[first.lineIdx], first.text, restored, DefaultStreamingJSONPaths)
		for _, f := range g.fragments[1:] {
			markEventBlockForRemoval(lines, f.lineIdx, removeLines)
		}
	}
	if !changed {
		return policy.ForwardResponseChunk{}
	}

	filtered := lines[:0:0]
	for i, line := range lines {
		if removeLines[i] {
			continue
		}
		filtered = append(filtered, line)
	}
	return policy.ForwardResponseChunk{Body: []byte(strings.Join(filtered, "\n"))}
}
