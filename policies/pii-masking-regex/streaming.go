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
	"sort"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Streamed restoration works on channels. A channel is one string that a stream
// delivers in pieces: the text of one content block, the thinking of one block,
// the argument JSON of one tool call. A placeholder can be split across the pieces
// of a channel, never across channels, so each channel is joined, restored and
// written back on its own. Joining everything in a flush, as the policy once did,
// let a later block's text land in the first block and left tool arguments and
// thinking (which the old path never looked at) with their placeholders in them.

// channelRef locates one streamed string inside one event payload.
type channelRef struct {
	key    string // identifies the channel across events
	isJSON bool   // the string is a piece of JSON text, so originals need JSON escaping
	n      *node  // the string value in the payload
}

// eventChannels returns the channels one SSE data payload carries.
func eventChannels(payload []byte) []channelRef {
	root, err := parseJSON(payload)
	if err != nil || root.kind != kindObject {
		return nil
	}
	var refs []channelRef
	add := func(key string, isJSON bool, n *node) {
		if n != nil && n.kind == kindString {
			refs = append(refs, channelRef{key: key, isJSON: isJSON, n: n})
		}
	}
	raw := func(n *node) string {
		if n == nil {
			return ""
		}
		return string(payload[n.start:n.end])
	}

	// Anthropic Messages: content_block_delta.
	if d := root.get("delta"); d != nil && d.kind == kindObject {
		idx := raw(root.get("index"))
		if t := d.get("text"); t != nil {
			add("a"+idx+":text", false, t)
		}
		if t := d.get("thinking"); t != nil {
			add("a"+idx+":thinking", false, t)
		}
		if t := d.get("partial_json"); t != nil {
			add("a"+idx+":json", true, t)
		}
		if len(refs) > 0 {
			return refs
		}
	}

	// OpenAI chat completions.
	if ch := root.get("choices"); ch != nil && ch.kind == kindArray {
		for i, c := range ch.kids {
			d := c.get("delta")
			if d == nil {
				continue
			}
			pfx := "o" + string(rune('0'+i%10))
			if i >= 10 {
				pfx = "o" + strings.Repeat("x", i/10) + string(rune('0'+i%10))
			}
			add(pfx+":content", false, d.get("content"))
			add(pfx+":reasoning", false, d.get("reasoning_content"))
			add(pfx+":fc", true, d.get("function_call").get("arguments"))
			if tcs := d.get("tool_calls"); tcs != nil && tcs.kind == kindArray {
				for j, tc := range tcs.kids {
					idx := raw(tc.get("index"))
					if idx == "" {
						idx = "p" + string(rune('0'+j%10))
					}
					add(pfx+":t"+idx, true, tc.get("function").get("arguments"))
				}
			}
		}
		if len(refs) > 0 {
			return refs
		}
	}

	// Amazon Bedrock Converse stream.
	if cbd := root.get("contentBlockDelta"); cbd != nil {
		idx := raw(cbd.get("contentBlockIndex"))
		d := cbd.get("delta")
		add("b"+idx+":text", false, d.get("text"))
		add("b"+idx+":json", true, d.get("toolUse").get("input"))
		add("b"+idx+":thinking", false, d.get("reasoningContent").get("text"))
		if len(refs) > 0 {
			return refs
		}
	}

	// Every other provider shape this policy already knew, first match wins.
	typ, _ := root.get("type").str(payload)
	for _, path := range DefaultStreamingJSONPaths {
		if nodes, ok := resolvePath(root, path); ok && nodes[0].kind == kindString {
			// Responses-API events of different kinds (output text, reasoning
			// summary, tool arguments) and different items never share a channel.
			key := "p:" + path + ":" + typ
			for _, f := range []string{"item_id", "output_index", "content_index", "summary_index"} {
				key += ":" + raw(root.get(f))
			}
			add(key, strings.Contains(typ, "function_call_arguments"), nodes[0])
			break
		}
	}
	return refs
}

// channelText is the joined text of one channel across a flush.
type channelText struct {
	key    string
	isJSON bool
	text   string
}

// joinChannels joins the pieces of every channel in an SSE buffer, in the order
// the channels first appear.
func joinChannels(s string) []channelText {
	var order []string
	byKey := map[string]*channelText{}
	for _, line := range strings.Split(s, "\n") {
		payload, ok := sseDataPayload(line)
		if !ok || payload == sseDone {
			continue
		}
		pb := []byte(payload)
		for _, r := range eventChannels(pb) {
			txt, _ := r.n.str(pb)
			ct := byKey[r.key]
			if ct == nil {
				ct = &channelText{key: r.key, isJSON: r.isJSON}
				byKey[r.key] = ct
				order = append(order, r.key)
			}
			ct.text += txt
		}
	}
	out := make([]channelText, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

// restoreChannel puts the originals back into a joined channel. Inside JSON text
// an original has to be escaped to stay a valid JSON string.
func restoreChannel(text string, isJSON bool, restoreMap map[string]string) string {
	if isJSON {
		return restoreJSONBytes(text, restoreMap)
	}
	return restore(text, restoreMap)
}

// encodeJSONString returns s as a JSON string literal, without HTML escaping.
func encodeJSONString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

type lineEdit struct {
	start, end int
	repl       []byte
}

// restoreSSEChunk restores placeholders in a flush of SSE events.
//
// For each channel whose joined text changes, the first event carrying the channel
// receives the whole restored text and the later events of that channel are
// dropped (or, when such an event also carries another channel, emptied). Events
// of other channels, and every event that needs no change, are forwarded as they
// arrived.
func (p *PIIMaskingRegexPolicy) restoreSSEChunk(chunkStr string, restoreMap map[string]string) policy.ForwardResponseChunk {
	lines := strings.Split(chunkStr, "\n")

	type entry struct {
		line int
		ref  channelRef
		text string
	}
	type eventInfo struct {
		payload []byte
		refs    int
	}
	events := map[int]*eventInfo{}
	var order []string
	byKey := map[string][]entry{}
	for i, line := range lines {
		payload, ok := sseDataPayload(line)
		if !ok || payload == sseDone {
			continue
		}
		pb := []byte(payload)
		refs := eventChannels(pb)
		if len(refs) == 0 {
			continue
		}
		events[i] = &eventInfo{payload: pb, refs: len(refs)}
		for _, r := range refs {
			txt, _ := r.n.str(pb)
			if _, seen := byKey[r.key]; !seen {
				order = append(order, r.key)
			}
			byKey[r.key] = append(byKey[r.key], entry{line: i, ref: r, text: txt})
		}
	}
	if len(order) == 0 {
		return policy.ForwardResponseChunk{}
	}

	edits := map[int][]lineEdit{}
	removeLines := map[int]bool{}
	changed := false
	for _, key := range order {
		es := byKey[key]
		var joined strings.Builder
		for _, e := range es {
			joined.WriteString(e.text)
		}
		restored := restoreChannel(joined.String(), es[0].ref.isJSON, restoreMap)
		if restored == joined.String() {
			continue
		}
		changed = true
		first := es[0]
		edits[first.line] = append(edits[first.line], lineEdit{first.ref.n.start, first.ref.n.end, encodeJSONString(restored)})
		for _, e := range es[1:] {
			if events[e.line].refs == 1 {
				markEventBlockForRemoval(lines, e.line, removeLines)
			} else {
				edits[e.line] = append(edits[e.line], lineEdit{e.ref.n.start, e.ref.n.end, []byte(`""`)})
			}
		}
	}
	if !changed {
		return policy.ForwardResponseChunk{}
	}

	for li, es := range edits {
		pb := events[li].payload
		sort.Slice(es, func(a, b int) bool { return es[a].start > es[b].start })
		for _, e := range es {
			pb = append(append(append([]byte(nil), pb[:e.start]...), e.repl...), pb[e.end:]...)
		}
		lines[li] = rebuildSSEDataLine(lines[li], string(pb))
	}
	filtered := lines[:0:0]
	for i, line := range lines {
		if !removeLines[i] {
			filtered = append(filtered, line)
		}
	}
	return policy.ForwardResponseChunk{Body: []byte(strings.Join(filtered, "\n"))}
}

// anyChannelMayComplete reports whether some channel in an SSE buffer ends in an
// unclosed "[" that could still become a placeholder, so the flush must wait.
func anyChannelMayComplete(s string) bool {
	for _, ct := range joinChannels(s) {
		if couldCompletePlaceholder(ct.text) {
			return true
		}
	}
	return false
}
