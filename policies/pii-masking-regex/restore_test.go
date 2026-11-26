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
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const testPlaceholder = "[EMAIL_3fa91c0b]"

// blockText is what a client assembles from a Messages stream, per content block.
type blockText struct {
	text, args, thinking, signature string
}

func assembleBlocks(t *testing.T, raw string) map[int]*blockText {
	t.Helper()
	blocks := map[int]*blockText{}
	for _, line := range strings.Split(raw, "\n") {
		payload, ok := sseDataPayload(line)
		if !ok {
			continue
		}
		var ev struct {
			Type  string `json:"type"`
			Index int    `json:"index"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
				Thinking    string `json:"thinking"`
				Signature   string `json:"signature"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			t.Fatalf("event is not valid JSON: %q (%v)", payload, err)
		}
		if ev.Type != "content_block_delta" {
			continue
		}
		b := blocks[ev.Index]
		if b == nil {
			b = &blockText{}
			blocks[ev.Index] = b
		}
		b.text += ev.Delta.Text
		b.args += ev.Delta.PartialJSON
		b.thinking += ev.Delta.Thinking
		b.signature += ev.Delta.Signature
	}
	return blocks
}

func restoringPolicy(t *testing.T) (*PIIMaskingRegexPolicy, *policy.ResponseStreamContext) {
	t.Helper()
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$"})
	ctx := streamingRespCtx("text/event-stream", map[string]string{"bob@example.org": testPlaceholder})
	return p, ctx
}

// Item 3: streamed tool-call arguments are restored.
func TestStream_ToolCallArgumentsAreRestored(t *testing.T) {
	p, ctx := restoringPolicy(t)
	raw := readFixture(t, "testdata/messages/stream_tool_args.sse")
	for _, size := range []int{len(raw), 200, 64, 17, 5} {
		out := driveResponseStream(t, p, ctx, splitEvery(raw, size))
		args := assembleBlocks(t, out)[0].args
		if args != `{"email": "bob@example.org"}` {
			t.Fatalf("chunk size %d: tool arguments not restored, got %q", size, args)
		}
		var parsed map[string]string
		if err := json.Unmarshal([]byte(args), &parsed); err != nil {
			t.Fatalf("restored arguments must be valid JSON: %v", err)
		}
	}
}

// The restored value sits inside a JSON string of the argument text, so special
// characters in the original must be escaped for that inner JSON.
func TestStream_ToolCallArgumentsEscapeTheOriginalForTheInnerJSON(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"customPIIEntities": []interface{}{
		map[string]interface{}{"piiEntity": "NOTE", "piiRegex": `x`},
	}, "jsonPath": "$"})
	original := `say "hi" \ there`
	ctx := streamingRespCtx("text/event-stream", map[string]string{original: "[NOTE_0a0b0c0d]"})
	raw := readFixture(t, "testdata/messages/stream_tool_args.sse")
	raw = strings.ReplaceAll(raw, "[EMAIL_", "[NOTE_")
	raw = strings.ReplaceAll(raw, "3fa91c0b]", "0a0b0c0d]")
	out := driveResponseStream(t, p, ctx, splitEvery(raw, 40))
	args := assembleBlocks(t, out)[0].args
	var parsed map[string]string
	if err := json.Unmarshal([]byte(args), &parsed); err != nil {
		t.Fatalf("restored arguments must be valid JSON, got %q: %v", args, err)
	}
	if parsed["email"] != original {
		t.Fatalf("got %q want %q", parsed["email"], original)
	}
}

// Item 5: streamed thinking is restored.
func TestStream_ThinkingIsRestored(t *testing.T) {
	p, ctx := restoringPolicy(t)
	raw := readFixture(t, "testdata/messages/stream_thinking.sse")
	for _, size := range []int{len(raw), 90, 23} {
		out := driveResponseStream(t, p, ctx, splitEvery(raw, size))
		b := assembleBlocks(t, out)[0]
		if b.thinking != "I should look up bob@example.org now." {
			t.Fatalf("chunk size %d: thinking not restored, got %q", size, b.thinking)
		}
		if b.signature != "c2ln" {
			t.Fatalf("the signature must be untouched, got %q", b.signature)
		}
	}
}

// A placeholder cut across many events, with a stream that ends cleanly.
func TestStream_SplitPlaceholderIsHeldAndRestoredWithoutLeakingFragments(t *testing.T) {
	p, ctx := restoringPolicy(t)
	mk := func(val string) string {
		ev, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": val}})
		return "event: content_block_delta\ndata: " + string(ev) + "\n\n"
	}
	var events []string
	for _, piece := range []string{"Hi ", "[", "EMAIL", "_3fa9", "1c0b", "]", "!"} {
		events = append(events, mk(piece))
	}
	out := driveResponseStream(t, p, ctx, events)
	if got := assembleBlocks(t, out)[0].text; got != "Hi bob@example.org!" {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(out, "EMAIL_") {
		t.Fatalf("a placeholder fragment leaked: %s", out)
	}
}

// FR-010: the buffered (non-streamed) response restores text, tool arguments and thinking too.
func TestBufferedResponse_RestoresTextToolArgumentsAndThinking(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$"})
	body := `{"id":"msg_1","type":"message","content":[` +
		`{"type":"thinking","thinking":"look up [EMAIL_3fa91c0b]","signature":"c2ln"},` +
		`{"type":"text","text":"Sent to [EMAIL_3fa91c0b]."},` +
		`{"type":"tool_use","id":"tu","name":"lookup","input":{"email":"[EMAIL_3fa91c0b]"}}]}`
	respCtx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{RequestID: "r", Metadata: map[string]interface{}{MetadataKeyPIIEntities: map[string]string{"bob@example.org": testPlaceholder}}},
		ResponseBody:  &policy.Body{Content: []byte(body), Present: true},
	}
	mods, ok := p.OnResponseBody(context.Background(), respCtx, nil).(policy.DownstreamResponseModifications)
	if !ok || len(mods.Body) == 0 {
		t.Fatalf("expected a modified body, got %T", p.OnResponseBody(context.Background(), respCtx, nil))
	}
	if strings.Contains(string(mods.Body), "EMAIL_") || strings.Count(string(mods.Body), "bob@example.org") != 3 {
		t.Fatalf("not fully restored: %s", mods.Body)
	}
	if !json.Valid(mods.Body) {
		t.Fatalf("restored body must stay valid JSON: %s", mods.Body)
	}
}
