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

// Response-side differential tests: every response shape that v1.1.0 restored
// must be handed to the client byte for byte as before, for any chunking.

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/gateway-controllers/policies/pii-masking-regex/internal/legacy"
)

type streamer interface {
	NeedsMoreResponseData(accumulated []byte) bool
	OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingResponseAction
}

func driveAny(t *testing.T, p streamer, mapping map[string]string, chunks [][]byte) string {
	t.Helper()
	shared := &policy.SharedContext{RequestID: "d", Metadata: map[string]interface{}{MetadataKeyPIIEntities: mapping}}
	var out strings.Builder
	var acc []byte
	for i, c := range chunks {
		eos := i == len(chunks)-1
		acc = append(acc, c...)
		if !eos && p.NeedsMoreResponseData(acc) {
			continue
		}
		fwd, ok := p.OnResponseBodyChunk(context.Background(), &policy.ResponseStreamContext{SharedContext: shared},
			&policy.StreamBody{Chunk: acc, EndOfStream: eos, Index: uint64(i)}, nil).(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("expected ForwardResponseChunk")
		}
		if fwd.Body == nil {
			out.Write(acc)
		} else {
			out.Write(fwd.Body)
		}
		acc = nil
	}
	return out.String()
}

// responseShape builds a full provider response from the pieces of the answer.
type responseShape struct {
	name  string
	build func(pieces []string) string
}

func dataLine(payload interface{}) string { return "data: " + marshalJSON(payload) + "\n\n" }

var responseShapes = []responseShape{
	{"openai-chat-sse", func(p []string) string {
		var sb strings.Builder
		sb.WriteString(dataLine(map[string]interface{}{"id": "c1", "object": "chat.completion.chunk", "choices": []interface{}{map[string]interface{}{"index": 0, "delta": map[string]interface{}{"role": "assistant"}}}}))
		for _, piece := range p {
			sb.WriteString(dataLine(map[string]interface{}{"id": "c1", "object": "chat.completion.chunk", "choices": []interface{}{map[string]interface{}{"index": 0, "delta": map[string]interface{}{"content": piece}}}}))
		}
		sb.WriteString(dataLine(map[string]interface{}{"id": "c1", "choices": []interface{}{map[string]interface{}{"index": 0, "delta": map[string]interface{}{}, "finish_reason": "stop"}}}))
		sb.WriteString("data: [DONE]\n\n")
		return sb.String()
	}},
	{"openai-chat-sse-crlf", func(p []string) string {
		var sb strings.Builder
		for _, piece := range p {
			sb.WriteString("data: " + marshalJSON(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"delta": map[string]interface{}{"content": piece}}}}) + "\r\n\r\n")
		}
		sb.WriteString("data: [DONE]\r\n\r\n")
		return sb.String()
	}},
	{"openai-chat-sse-with-comments-and-usage", func(p []string) string {
		var sb strings.Builder
		sb.WriteString(": keep-alive\n\n")
		for i, piece := range p {
			sb.WriteString(dataLine(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"delta": map[string]interface{}{"content": piece}}}}))
			if i%3 == 2 {
				sb.WriteString(": ping\n\n")
			}
		}
		sb.WriteString(dataLine(map[string]interface{}{"choices": []interface{}{}, "usage": map[string]interface{}{"prompt_tokens": 12, "completion_tokens": 30}}))
		sb.WriteString("data: [DONE]\n\n")
		return sb.String()
	}},
	{"openai-chat-json", func(p []string) string {
		return marshalJSON(map[string]interface{}{"id": "c1", "object": "chat.completion", "choices": []interface{}{
			map[string]interface{}{"index": 0, "message": map[string]interface{}{"role": "assistant", "content": strings.Join(p, "")}, "finish_reason": "stop"}}}) + "\n"
	}},
	{"anthropic-text-sse", func(p []string) string {
		var sb strings.Builder
		sb.WriteString("event: message_start\ndata: " + marshalJSON(map[string]interface{}{"type": "message_start"}) + "\n\n")
		sb.WriteString("event: content_block_start\ndata: " + marshalJSON(map[string]interface{}{"type": "content_block_start", "index": 0, "content_block": map[string]interface{}{"type": "text", "text": ""}}) + "\n\n")
		for _, piece := range p {
			sb.WriteString("event: content_block_delta\ndata: " + marshalJSON(map[string]interface{}{"type": "content_block_delta", "index": 0, "delta": map[string]interface{}{"type": "text_delta", "text": piece}}) + "\n\n")
		}
		sb.WriteString("event: content_block_stop\ndata: " + marshalJSON(map[string]interface{}{"type": "content_block_stop", "index": 0}) + "\n\n")
		sb.WriteString("event: message_stop\ndata: " + marshalJSON(map[string]interface{}{"type": "message_stop"}) + "\n\n")
		return sb.String()
	}},
	{"anthropic-json", func(p []string) string {
		return marshalJSON(map[string]interface{}{"id": "m1", "type": "message", "content": []interface{}{map[string]interface{}{"type": "text", "text": strings.Join(p, "")}}})
	}},
	{"gemini-sse", func(p []string) string {
		var sb strings.Builder
		for _, piece := range p {
			sb.WriteString(dataLine(map[string]interface{}{"candidates": []interface{}{map[string]interface{}{"content": map[string]interface{}{"role": "model", "parts": []interface{}{map[string]interface{}{"text": piece}}}}}}))
		}
		return sb.String()
	}},
	{"bedrock-converse-sse", func(p []string) string {
		var sb strings.Builder
		for _, piece := range p {
			sb.WriteString(dataLine(map[string]interface{}{"contentBlockDelta": map[string]interface{}{"contentBlockIndex": 0, "delta": map[string]interface{}{"text": piece}}}))
		}
		return sb.String()
	}},
	{"legacy-completions-sse", func(p []string) string {
		var sb strings.Builder
		for _, piece := range p {
			sb.WriteString(dataLine(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"text": piece}}}))
		}
		return sb.String()
	}},
	{"anthropic-legacy-completion-sse", func(p []string) string {
		var sb strings.Builder
		for _, piece := range p {
			sb.WriteString(dataLine(map[string]interface{}{"completion": piece}))
		}
		return sb.String()
	}},
	{"bedrock-titan-sse", func(p []string) string {
		var sb strings.Builder
		for _, piece := range p {
			sb.WriteString(dataLine(map[string]interface{}{"outputText": piece}))
		}
		return sb.String()
	}},
	{"responses-api-sse", func(p []string) string {
		var sb strings.Builder
		for _, piece := range p {
			sb.WriteString("event: response.output_text.delta\ndata: " + marshalJSON(map[string]interface{}{"type": "response.output_text.delta", "item_id": "i1", "output_index": 0, "content_index": 0, "delta": piece}) + "\n\n")
		}
		return sb.String()
	}},
	{"plain-text", func(p []string) string { return strings.Join(p, "") }},
	{"generic-json-object", func(p []string) string {
		return marshalJSON(map[string]interface{}{"answer": strings.Join(p, ""), "n": 3, "nested": map[string]interface{}{"also": strings.Join(p, "")}})
	}},
}

var answerTexts = []string{
	"Hello [EMAIL_0000], please call [PHONE_0001] about [SSN_0002].",
	"Nothing to restore here, and a [bracket] or [ lonely one and [A_B] and [EMAIL_zz].",
	"Back to back [EMAIL_0000][EMAIL_0000] and [PHONE_0001]!",
	"Ends with an open bracket [",
	"Ends mid placeholder [EMAIL_00",
	"Unicode héllo 日本語 😀 [EMAIL_0000] ✓ \"quoted\" back\\slash <tag> & done",
	"[EMAIL_0000]",
	"",
	"Same [EMAIL_0000] twice [EMAIL_0000] and a [PHONE_0001] with [SSN_0002] at the end [SSN_0002]",
}

var oldMapping = map[string]string{
	"bob@example.org":  "[EMAIL_0000]",
	"(415) 555-0199":   "[PHONE_0001]",
	"123-45-6789":      "[SSN_0002]",
	"a \"quoted\" one": "[A_B]",
}

func piecesOf(rng *rand.Rand, text string, mode int) []string {
	switch mode {
	case 0:
		return []string{text}
	case 1:
		var out []string
		for _, r := range text {
			out = append(out, string(r))
		}
		return out
	default:
		return splitters[2].fn(rng, text)
	}
}

// TestDifferential_ResponsesAreByteIdenticalToV110 compares what the client
// receives from the previous release and from this one.
func TestDifferential_ResponsesAreByteIdenticalToV110(t *testing.T) {
	newPolicy := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "phone": true, "ssn": true, "jsonPath": "$"})
	oldAny, err := legacy.GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"email": true, "phone": true, "ssn": true, "jsonPath": "$"})
	if err != nil {
		t.Fatal(err)
	}
	oldPolicy := oldAny.(*legacy.PIIMaskingRegexPolicy)

	compared := 0
	for _, shape := range responseShapes {
		for ti, text := range answerTexts {
			for mode := 0; mode < 3; mode++ {
				rng := rand.New(rand.NewSource(int64(ti*10 + mode)))
				body := shape.build(piecesOf(rng, text, mode))
				for _, ck := range chunkers {
					name := fmt.Sprintf("%s/text%d/pieces%d/%s", shape.name, ti, mode, ck.name)
					chunks := ck.fn(rand.New(rand.NewSource(99)), []byte(body))
					want := driveAny(t, oldPolicy, oldMapping, chunks)
					got := driveAny(t, newPolicy, oldMapping, chunks)
					compared++
					if got != want {
						t.Errorf("%s: the client sees different bytes than with v1.1.0\nbody:\n%.600s\nv1.1.0:\n%.600s\nnew:\n%.600s", name, body, want, got)
						return
					}
				}
			}
		}
	}
	t.Logf("compared %d response streams, all byte-identical to v1.1.0", compared)
}

// The buffered path (OnResponseBody) as well.
func TestDifferential_BufferedResponsesAreByteIdenticalToV110(t *testing.T) {
	newPolicy := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "phone": true, "ssn": true, "jsonPath": "$"})
	oldAny, _ := legacy.GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"email": true, "phone": true, "ssn": true, "jsonPath": "$"})
	oldPolicy := oldAny.(*legacy.PIIMaskingRegexPolicy)

	compared := 0
	for _, shape := range responseShapes {
		for ti, text := range answerTexts {
			body := shape.build(piecesOf(rand.New(rand.NewSource(1)), text, 0))
			mk := func() *policy.ResponseContext {
				return &policy.ResponseContext{
					SharedContext: &policy.SharedContext{RequestID: "d", Metadata: map[string]interface{}{MetadataKeyPIIEntities: oldMapping}},
					ResponseBody:  &policy.Body{Content: []byte(body), Present: true},
				}
			}
			run := func(a policy.ResponseAction) string {
				if m, ok := a.(policy.DownstreamResponseModifications); ok && m.Body != nil {
					return string(m.Body)
				}
				return body
			}
			want := run(oldPolicy.OnResponseBody(context.Background(), mk(), nil))
			got := run(newPolicy.OnResponseBody(context.Background(), mk(), nil))
			compared++
			if got != want {
				t.Errorf("%s/text%d: buffered result differs from v1.1.0\nbody:\n%.500s\nv1.1.0:\n%.500s\nnew:\n%.500s", shape.name, ti, body, want, got)
			}
		}
	}
	t.Logf("compared %d buffered responses", compared)
}

// Redaction never restores anything, before and now.
func TestDifferential_RedactModeNeverTouchesTheResponse(t *testing.T) {
	newPolicy := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "redactPII": true, "jsonPath": "$"})
	for _, shape := range responseShapes {
		body := shape.build([]string{"hello ", "[EMAIL_0000]", " bye"})
		got := driveAny(t, newPolicy, oldMapping, chunkers[3].fn(rand.New(rand.NewSource(1)), []byte(body)))
		if got != body {
			t.Errorf("%s: redact mode must pass the response through untouched", shape.name)
		}
	}
}
