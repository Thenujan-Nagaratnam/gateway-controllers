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

// Edge cases found by reading the code for what could go wrong, written as
// permanent regression tests.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func requestBodyOf(t *testing.T, p *PIIMaskingRegexPolicy, body string) (string, map[string]interface{}, bool) {
	t.Helper()
	ctx := piiRequestContext(body)
	switch a := p.OnRequestBody(context.Background(), ctx, nil).(type) {
	case policy.UpstreamRequestModifications:
		if a.Body != nil {
			return string(a.Body), ctx.Metadata, false
		}
		return body, ctx.Metadata, false
	case policy.ImmediateResponse:
		return "", ctx.Metadata, true
	}
	t.Fatalf("unexpected action")
	return "", nil, false
}

func withinSeconds(t *testing.T, limit time.Duration, name string, f func()) {
	t.Helper()
	if raceEnabled {
		limit *= 30 // the race detector makes everything several times slower
	}
	start := time.Now()
	f()
	if d := time.Since(start); d > limit {
		t.Fatalf("%s took %v, limit %v", name, d, limit)
	}
}

// ───────────── request: structure of the JSON itself ─────────────

func TestEdge_TopLevelValuesOtherThanObjects(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	cases := map[string]string{
		"array":         `["bob@example.org",{"a":"carol@example.org"},3]`,
		"string":        `"bob@example.org"`,
		"nested arrays": `[[["bob@example.org"]]]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			out, _, _ := requestBodyOf(t, p, body)
			if strings.Contains(out, "@example.org") || !json.Valid([]byte(out)) {
				t.Fatalf("got %s", out)
			}
		})
	}
	for _, body := range []string{`123`, `true`, `null`, `-1.5e3`, `[]`, `{}`} {
		if out, _, _ := requestBodyOf(t, p, body); out != body {
			t.Errorf("%s must be left alone, got %s", body, out)
		}
	}
}

func TestEdge_DeepNestingDoesNotOverflowOrHang(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	for _, depth := range []int{100, 5000, 9000} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			body := strings.Repeat(`{"a":`, depth) + `"bob@example.org"` + strings.Repeat(`}`, depth)
			withinSeconds(t, 5*time.Second, "deep nesting", func() {
				out, _, _ := requestBodyOf(t, p, body)
				if strings.Contains(out, "bob@example.org") || !json.Valid([]byte(out)) {
					t.Fatalf("not masked or invalid at depth %d", depth)
				}
			})
		})
	}
	// Beyond the JSON decoder's own depth limit the body is not valid JSON; the
	// policy must still return promptly and without a panic.
	body := strings.Repeat(`[`, 20000) + `"bob@example.org"` + strings.Repeat(`]`, 20000)
	withinSeconds(t, 5*time.Second, "over-deep nesting", func() { requestBodyOf(t, p, body) })
}

func TestEdge_DuplicateKeysAreBothMasked(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	out, _, _ := requestBodyOf(t, p, `{"a":"bob@example.org","a":"carol@example.org"}`)
	if strings.Contains(out, "@example.org") {
		t.Fatalf("got %s", out)
	}
}

func TestEdge_WhitespaceAndEscapesInUntouchedTokensArePreserved(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	body := "{\n \"slash\" : \"a\\/b\" ,\n \"hex\" : \"\\u00E9\\u00e8\" ,\n \"mail\" : \"bob@example.org\" ,\n \"n\" : 1.50\n}\n"
	out, _, _ := requestBodyOf(t, p, body)
	for _, keep := range []string{`"a\/b"`, "\"\\u00E9\\u00e8\"", "1.50\n}\n", "\"slash\" : "} {
		if !strings.Contains(out, keep) {
			t.Fatalf("%q was altered: %s", keep, out)
		}
	}
}

func TestEdge_ControlCharactersAndNul(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	out, _, _ := requestBodyOf(t, p, `{"a":"x\u0000y\u001f bob@example.org \u007f"}`)
	if strings.Contains(out, "bob@") || !json.Valid([]byte(out)) {
		t.Fatalf("got %q", out)
	}
	if !strings.Contains(out, `x\u0000y\u001f`) {
		t.Fatalf("control characters must stay escaped: %q", out)
	}
}

func TestEdge_InvalidUTF8AndLoneSurrogates(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	// An untouched token keeps its exact bytes, even if they are not valid UTF-8.
	body := "{\"keep\":\"a\xffb\",\"mail\":\"bob@example.org\"}"
	out, _, _ := requestBodyOf(t, p, body)
	if !strings.Contains(out, "\"a\xffb\"") {
		t.Fatalf("an untouched token must keep its bytes, got %q", out)
	}
	if !json.Valid([]byte(out)) || strings.Contains(out, "bob@") {
		t.Fatalf("got %q", out)
	}
	// A lone surrogate escape in a token that is masked becomes the replacement
	// character; the request stays valid and the email is still hidden.
	out2, _, _ := requestBodyOf(t, p, `{"a":"\ud800 bob@example.org"}`)
	if !json.Valid([]byte(out2)) || strings.Contains(out2, "bob@") {
		t.Fatalf("got %q", out2)
	}
}

func TestEdge_BOMAndTrailingGarbageFallBackToPlainText(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	for name, body := range map[string]string{
		"bom":      "\xef\xbb\xbf{\"a\":\"bob@example.org\"}",
		"trailing": `{"a":"bob@example.org"} trailing carol@example.org`,
	} {
		out, _, _ := requestBodyOf(t, p, body)
		if strings.Contains(out, "@example.org") {
			t.Errorf("%s: email not masked: %q", name, out)
		}
	}
}

func TestEdge_EmptyAndAbsentBodies(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	ctx := piiRequestContext("")
	if _, ok := p.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications); !ok {
		t.Fatal("an empty body must pass")
	}
	ctx.Body = nil
	if mods, ok := p.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications); !ok || mods.Body != nil {
		t.Fatal("an absent body must pass untouched")
	}
}

// ───────────── request: patterns ─────────────

func TestEdge_PatternThatMatchesTheEmptyString(t *testing.T) {
	p := mustGetPIIPolicy(t, params{"jsonPath": "$", "customPIIEntities": []interface{}{
		map[string]interface{}{"piiEntity": "X", "piiRegex": `x*`}}})
	body := `{"a":"abc xx def"}`
	withinSeconds(t, 2*time.Second, "empty-match pattern", func() {
		out, _, _ := requestBodyOf(t, p, body)
		if !json.Valid([]byte(out)) || strings.Contains(out, "[X_") == false {
			t.Fatalf("got %s", out)
		}
		if strings.Count(out, "[X_") != 1 {
			t.Fatalf("only the real match may be replaced, got %s", out)
		}
	})
}

func TestEdge_AnchoredAndMultilinePatternsApplyPerValue(t *testing.T) {
	p := mustGetPIIPolicy(t, params{"jsonPath": "$", "customPIIEntities": []interface{}{
		map[string]interface{}{"piiEntity": "PIN", "piiRegex": `^[0-9]{4}$`}}})
	out, _, _ := requestBodyOf(t, p, `{"pin":"1234","note":"pin 1234 here"}`)
	if strings.Contains(out, `"pin":"1234"`) || !strings.Contains(out, "pin 1234 here") {
		t.Fatalf("anchors apply to each string value: %s", out)
	}
	p2 := mustGetPIIPolicy(t, params{"jsonPath": "$", "customPIIEntities": []interface{}{
		map[string]interface{}{"piiEntity": "LN", "piiRegex": `(?m)^secret-[0-9]+$`}}})
	out2, _, _ := requestBodyOf(t, p2, `{"a":"line1\nsecret-42\nline3"}`)
	if strings.Contains(out2, "secret-42") {
		t.Fatalf("got %s", out2)
	}
}

func TestEdge_OverlappingEntitiesAreDeterministic(t *testing.T) {
	cfg := params{"jsonPath": "$", "email": true, "customPIIEntities": []interface{}{
		map[string]interface{}{"piiEntity": "ACCOUNT", "piiRegex": `[a-z]+@example\.org`}}}
	first := ""
	for i := 0; i < 30; i++ {
		p := mustGetPIIPolicy(t, cfg)
		out, md, _ := requestBodyOf(t, p, `{"a":"bob@example.org"}`)
		if first == "" {
			first = out
		} else if out != first {
			t.Fatalf("overlapping entities gave different results: %s vs %s", first, out)
		}
		if n := len(md[MetadataKeyPIIEntities].(map[string]string)); n != 1 {
			t.Fatalf("one value must have one placeholder, got %d", n)
		}
	}
	if !strings.Contains(first, "[ACCOUNT_") {
		t.Fatalf("the entity that sorts first by name claims the value, got %s", first)
	}
}

func TestEdge_ValueThatContainsAnotherValue(t *testing.T) {
	p := mustGetPIIPolicy(t, params{"jsonPath": "$", "customPIIEntities": []interface{}{
		map[string]interface{}{"piiEntity": "LONG", "piiRegex": `acct-[0-9]+-vip`},
		map[string]interface{}{"piiEntity": "SHORT", "piiRegex": `acct-[0-9]+`}}})
	out, md, _ := requestBodyOf(t, p, `{"a":"acct-12-vip and acct-12 and acct-123"}`)
	mapping := md[MetadataKeyPIIEntities].(map[string]string)
	if len(mapping) != 3 || strings.Contains(out, "acct-") {
		t.Fatalf("each value is masked on its own: %v %s", mapping, out)
	}
}

func TestEdge_EntityNamesWithUnderscores(t *testing.T) {
	p := mustGetPIIPolicy(t, params{"jsonPath": "$", "customPIIEntities": []interface{}{
		map[string]interface{}{"piiEntity": "credit_card", "piiRegex": `[0-9]{4}-[0-9]{4}`},
		map[string]interface{}{"piiEntity": "_edge_", "piiRegex": `zz[0-9]+`}}})
	out, md, _ := requestBodyOf(t, p, `{"a":"card 1111-2222 and zz9"}`)
	mapping := md[MetadataKeyPIIEntities].(map[string]string)
	for original, ph := range mapping {
		if !placeholderShape.MatchString(ph) {
			t.Errorf("placeholder %q for %q has the wrong shape", ph, original)
		}
	}
	if strings.Contains(out, "1111-2222") || strings.Contains(out, "zz9") {
		t.Fatalf("got %s", out)
	}
}

func TestEdge_SpecialCharactersInOriginalValuesRestoreLiterally(t *testing.T) {
	p := mustGetPIIPolicy(t, params{"jsonPath": "$", "customPIIEntities": []interface{}{
		map[string]interface{}{"piiEntity": "TOK", "piiRegex": `tok\$[&\\0-9]+`}}})
	original := `tok$&\1`
	ctx := streamingRespCtx("text/event-stream", map[string]string{original: "[TOK_0a0b0c0d]"})
	raw := sseEvent("see [TOK_0a0b0c0d] now")
	out := driveResponseStream(t, p, ctx, []string{raw})
	if got := assembleSSEContent(t, out); got != "see "+original+" now" {
		t.Fatalf("got %q", got)
	}
}

// ───────────── request: size and speed ─────────────

func TestEdge_LargeBodiesStayFast(t *testing.T) {
	p := mustGetPIIPolicy(t, allBuiltins)
	t.Run("one 8MB string", func(t *testing.T) {
		body := `{"a":"` + strings.Repeat("lorem ipsum dolor ", 450000) + ` tail@example.org"}`
		withinSeconds(t, 10*time.Second, "8MB string", func() {
			out, _, _ := requestBodyOf(t, p, body)
			if strings.Contains(out, "tail@") {
				t.Fatal("not masked")
			}
		})
	})
	t.Run("200k small strings", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString(`{"items":[`)
		for i := 0; i < 200000; i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, `"v%d"`, i)
		}
		sb.WriteString(`,"bob@example.org"]}`)
		withinSeconds(t, 10*time.Second, "200k strings", func() {
			out, _, _ := requestBodyOf(t, p, sb.String())
			if strings.Contains(out, "bob@") {
				t.Fatal("not masked")
			}
		})
	})
	t.Run("pathological pattern input", func(t *testing.T) {
		body := `{"a":"` + strings.Repeat("a@", 300000) + `"}`
		withinSeconds(t, 10*time.Second, "regex stress", func() { requestBodyOf(t, p, body) })
	})
	t.Run("scoped path over a large body", func(t *testing.T) {
		sp := mustGetPIIPolicy(t, params{"email": true, "jsonPath": userAndToolContentPath})
		var parts []string
		for i := 0; i < 20000; i++ {
			parts = append(parts, jsonMsg(t, []string{"user", "assistant"}[i%2], fmt.Sprintf("m%d bob%d@example.org", i, i)))
		}
		body := `{"messages":[` + strings.Join(parts, ",") + `]}`
		withinSeconds(t, 15*time.Second, "scoped 20k messages", func() {
			out, _, _ := requestBodyOf(t, sp, body)
			if strings.Contains(out, "bob0@example.org") {
				t.Fatal("user message not masked")
			}
			if !strings.Contains(out, "bob1@example.org") {
				t.Fatal("assistant message must be untouched")
			}
		})
	})
}

// ───────────── request: metadata and parameters ─────────────

func TestEdge_ExistingMetadataOfAnotherTypeDoesNotBreakMasking(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	ctx := piiRequestContext(`{"a":"bob@example.org"}`)
	ctx.Metadata[MetadataKeyPIIEntities] = "not a map"
	if _, ok := p.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications); !ok {
		t.Fatal("must not fail")
	}
	if m, ok := ctx.Metadata[MetadataKeyPIIEntities].(map[string]string); !ok || len(m) != 1 {
		t.Fatalf("mapping not stored: %v", ctx.Metadata[MetadataKeyPIIEntities])
	}
}

func TestEdge_MappingOfAnotherTypeOnTheResponseIsIgnored(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	for _, v := range []interface{}{"x", 5, map[string]interface{}{"a": "b"}, map[string]string{}, nil} {
		ctx := &policy.ResponseStreamContext{SharedContext: &policy.SharedContext{RequestID: "r", Metadata: map[string]interface{}{MetadataKeyPIIEntities: v}}}
		fwd := p.OnResponseBodyChunk(context.Background(), ctx, &policy.StreamBody{Chunk: []byte(sseEvent("hi [EMAIL_0000]")), EndOfStream: true}, nil)
		if f, ok := fwd.(policy.ForwardResponseChunk); !ok || f.Body != nil {
			t.Fatalf("a mapping of type %T must leave the response alone", v)
		}
	}
}

func TestEdge_RedactWithScopedPath(t *testing.T) {
	p := mustGetPIIPolicy(t, params{"email": true, "redactPII": true, "jsonPath": userAndToolContentPath})
	out, md, _ := requestBodyOf(t, p, `{"system":"a@example.org","messages":[{"role":"user","content":"b@example.org"}]}`)
	if !strings.Contains(out, `"system":"a@example.org"`) || !strings.Contains(out, `"content":"*****"`) {
		t.Fatalf("got %s", out)
	}
	if _, ok := md[MetadataKeyPIIEntities]; ok {
		t.Fatal("redaction stores no mapping")
	}
}

// ───────────── response ─────────────

func TestEdge_ResponsesAPITwoOutputItemsInOneFlushKeepTheirOwnText(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	mk := func(outputIdx, contentIdx int, delta string) string {
		return "event: response.output_text.delta\ndata: " + marshalJSON(map[string]interface{}{
			"type": "response.output_text.delta", "output_index": outputIdx, "content_index": contentIdx, "delta": delta}) + "\n\n"
	}
	raw := mk(0, 0, "First [EMAIL_") + mk(0, 0, "3fa91c0b] done") + mk(1, 0, "Second item") + mk(1, 1, " and part two")
	ctx := streamingRespCtx("text/event-stream", map[string]string{"bob@example.org": "[EMAIL_3fa91c0b]"})
	out := driveResponseStream(t, p, ctx, []string{raw})

	got := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		payload, ok := sseDataPayload(line)
		if !ok {
			continue
		}
		var ev struct {
			OutputIndex  int    `json:"output_index"`
			ContentIndex int    `json:"content_index"`
			Delta        string `json:"delta"`
		}
		if json.Unmarshal([]byte(payload), &ev) == nil {
			got[fmt.Sprintf("%d.%d", ev.OutputIndex, ev.ContentIndex)] += ev.Delta
		}
	}
	want := map[string]string{"0.0": "First bob@example.org done", "1.0": "Second item", "1.1": " and part two"}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("item %s: got %q want %q\nstream:\n%s", k, got[k], v, out)
		}
	}
}

func TestEdge_OpenAIMultipleChoicesAreRestoredAndKeptApart(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	mk := func(choice int, text string) string {
		return dataLine(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"index": choice, "delta": map[string]interface{}{"content": text}}}})
	}
	raw := mk(0, "A [EMAIL_") + mk(1, "B [EMAIL_3fa91c0b]") + mk(0, "3fa91c0b] x") + mk(1, " more")
	ctx := streamingRespCtx("text/event-stream", map[string]string{"bob@example.org": "[EMAIL_3fa91c0b]"})
	out := driveResponseStream(t, p, ctx, []string{raw})
	got := map[int]string{}
	for _, line := range strings.Split(out, "\n") {
		payload, ok := sseDataPayload(line)
		if !ok {
			continue
		}
		var ev struct {
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(payload), &ev) == nil && len(ev.Choices) > 0 {
			got[ev.Choices[0].Index] += ev.Choices[0].Delta.Content
		}
	}
	if got[0] != "A bob@example.org x" || got[1] != "B bob@example.org more" {
		t.Fatalf("each choice keeps its own text: got %q and %q\n%s", got[0], got[1], out)
	}
}

func TestEdge_AnthropicNoiseEventsAreLeftAlone(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	mk := func(name string, payload map[string]interface{}) string {
		return "event: " + name + "\ndata: " + marshalJSON(payload) + "\n\n"
	}
	raw := mk("ping", map[string]interface{}{"type": "ping"}) +
		mk("content_block_start", map[string]interface{}{"type": "content_block_start", "index": 0, "content_block": map[string]interface{}{"type": "tool_use", "id": "t", "name": "n", "input": map[string]interface{}{"email": "[EMAIL_3fa91c0b]"}}}) +
		mk("content_block_delta", map[string]interface{}{"type": "content_block_delta", "index": 0, "delta": map[string]interface{}{"type": "text_delta", "text": ""}}) +
		mk("content_block_delta", map[string]interface{}{"type": "content_block_delta", "index": 1, "delta": map[string]interface{}{"type": "text_delta", "text": "hi [EMAIL_3fa91c0b]"}}) +
		mk("content_block_delta", map[string]interface{}{"type": "content_block_delta", "index": 2, "delta": map[string]interface{}{"type": "citations_delta", "citation": map[string]interface{}{"cited_text": "x"}}}) +
		mk("error", map[string]interface{}{"type": "error", "error": map[string]interface{}{"type": "overloaded_error", "message": "busy"}})
	ctx := streamingRespCtx("text/event-stream", map[string]string{"bob@example.org": "[EMAIL_3fa91c0b]"})
	out := driveResponseStream(t, p, ctx, []string{raw})
	if !strings.Contains(out, "hi bob@example.org") {
		t.Fatalf("text not restored:\n%s", out)
	}
	for _, keep := range []string{`"type":"ping"`, "overloaded_error", "citations_delta"} {
		if !strings.Contains(out, keep) {
			t.Fatalf("%s must be preserved:\n%s", keep, out)
		}
	}
}

func TestEdge_InterleavedBlocksInOneFlush(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	mk := func(i int, kind, key, v string) string {
		return "data: " + marshalJSON(map[string]interface{}{"type": "content_block_delta", "index": i, "delta": map[string]interface{}{"type": kind, key: v}}) + "\n\n"
	}
	raw := mk(0, "text_delta", "text", "a [EMA") + mk(1, "thinking_delta", "thinking", "t [EMA") + mk(0, "text_delta", "text", "IL_3fa91c0b] z") + mk(1, "thinking_delta", "thinking", "IL_3fa91c0b] y")
	ctx := streamingRespCtx("text/event-stream", map[string]string{"bob@example.org": "[EMAIL_3fa91c0b]"})
	out := driveResponseStream(t, p, ctx, []string{raw})
	blocks := assembleBlocks(t, out)
	if blocks[0].text != "a bob@example.org z" || blocks[1].thinking != "t bob@example.org y" {
		t.Fatalf("got %+v %+v\n%s", blocks[0], blocks[1], out)
	}
}

func TestEdge_StreamEndingInsideAPlaceholderLosesNothing(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	ctx := streamingRespCtx("text/event-stream", map[string]string{"bob@example.org": "[EMAIL_3fa91c0b]"})
	raw := sseEvent("done, mail [EMAIL_3fa") // the upstream stops here
	out := driveResponseStream(t, p, ctx, splitEvery(raw, 9))
	if got := assembleSSEContent(t, out); got != "done, mail [EMAIL_3fa" {
		t.Fatalf("got %q", got)
	}
}

func TestEdge_LargeMappingRestoresQuickly(t *testing.T) {
	p := mustGetPIIPolicy(t, emailWhole)
	mapping := map[string]string{}
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		ph := placeholderFor("EMAIL", fmt.Sprintf("user%d@example.org", i), 0)
		mapping[fmt.Sprintf("user%d@example.org", i)] = ph
		sb.WriteString(ph + " ")
	}
	ctx := streamingRespCtx("text/event-stream", mapping)
	raw := sseEvent(sb.String())
	withinSeconds(t, 10*time.Second, "5000-entry mapping", func() {
		out := driveResponseStream(t, p, ctx, []string{raw})
		if strings.Contains(out, "EMAIL_") {
			t.Fatal("not all placeholders restored")
		}
	})
}

// A restored value that itself looks like another placeholder must be left as it
// is: restoring is a single pass, not a chain of replacements.
func TestEdge_RestoreIsASinglePass(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := mustGetPIIPolicy(t, emailWhole)
		mapping := map[string]string{
			"first [PHONE_11111111] original": "[EMAIL_aaaaaaaa]",
			"second":                          "[PHONE_11111111]",
		}
		ctx := streamingRespCtx("text/event-stream", mapping)
		out := driveResponseStream(t, p, ctx, []string{sseEvent("x [EMAIL_aaaaaaaa] y [PHONE_11111111] z")})
		if got := assembleSSEContent(t, out); got != "x first [PHONE_11111111] original y second z" {
			t.Fatalf("run %d: got %q", i, got)
		}
	}
}

func TestEdge_LongEntityNamesStillRestoreWhileStreaming(t *testing.T) {
	for _, n := range []int{20, 54, 55, 60, 80, 120} {
		name := strings.Repeat("A", n)
		p := mustGetPIIPolicy(t, params{"jsonPath": "$", "customPIIEntities": []interface{}{
			map[string]interface{}{"piiEntity": name, "piiRegex": `zzz[0-9]+`}}})
		ph := placeholderFor(name, "zzz1", 0)
		ctx := streamingRespCtx("text/event-stream", map[string]string{"zzz1": ph})
		var events []string
		for _, piece := range splitters[2].fn(rand.New(rand.NewSource(int64(n))), "pre "+ph+" post") {
			events = append(events, sseEvent(piece))
		}
		out := driveResponseStream(t, p, ctx, events)
		if got := assembleSSEContent(t, out); got != "pre zzz1 post" {
			t.Fatalf("entity name of %d characters: got %q", n, got)
		}
	}
}

func TestEdge_ScopedMaskingOnPathologicalDocuments(t *testing.T) {
	cases := map[string]string{
		"9000 levels deep": strings.Repeat(`{"messages":[{"role":"user","content":`, 1) + strings.Repeat(`{"a":`, 9000) + `"x"` + strings.Repeat(`}`, 9000) + `}]}`,
		"wide array":       `{"messages":[` + strings.Repeat(`{"role":"user","content":"a"},`, 50000) + `{"role":"user","content":"bob@example.org"}]}`,
		"many keys": func() string {
			var sb strings.Builder
			sb.WriteString(`{"messages":[{"role":"user","content":"bob@example.org"}]`)
			for i := 0; i < 50000; i++ {
				fmt.Fprintf(&sb, `,"k%d":"v"`, i)
			}
			sb.WriteString("}")
			return sb.String()
		}(),
	}
	for _, path := range []string{userAndToolContentPath, `$..content`, `$.messages[*].content`} {
		p := mustGetPIIPolicy(t, params{"email": true, "jsonPath": path})
		for name, body := range cases {
			t.Run(path+"/"+name, func(t *testing.T) {
				withinSeconds(t, 10*time.Second, name, func() {
					out, _, rejected := requestBodyOf(t, p, body)
					if rejected {
						return
					}
					if !json.Valid([]byte(out)) {
						t.Fatal("invalid JSON out")
					}
				})
			})
		}
	}
}
