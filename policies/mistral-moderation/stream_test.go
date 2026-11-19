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

package mistralmoderation

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// sseFrame is one OpenAI-style streaming event carrying text.
func sseFrame(text string) string {
	return fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", text)
}

const sseRoleFrame = "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n"
const sseDoneFrame = "data: [DONE]\n\n"

// streamHarness drives OnResponseBodyChunk the way the engine does: one state per response,
// flushes in order.
type streamHarness struct {
	t   *testing.T
	p   policy.Policy
	ctx *policy.ResponseStreamContext
	idx uint64
}

func newHarness(t *testing.T, p policy.Policy) *streamHarness {
	return &streamHarness{t: t, p: p, ctx: &policy.ResponseStreamContext{SharedContext: &policy.SharedContext{}, ResponseStatus: 200}}
}

func (h *streamHarness) flush(data string, end bool) policy.StreamingResponseAction {
	h.t.Helper()
	h.idx++
	return h.p.(policy.StreamingResponsePolicy).OnResponseBodyChunk(context.Background(), h.ctx,
		&policy.StreamBody{Chunk: []byte(data), EndOfStream: end, Index: h.idx}, nil)
}

// bodyOf returns the bytes an action delivers and whether it ends the stream.
func bodyOf(t *testing.T, a policy.StreamingResponseAction) (body string, terminated bool, nilBody bool) {
	t.Helper()
	switch v := a.(type) {
	case policy.ForwardResponseChunk:
		return string(v.Body), false, v.Body == nil
	case policy.TerminateResponseChunk:
		return string(v.Body), true, false
	}
	t.Fatalf("unexpected action %T", a)
	return
}

func streamPolicy(t *testing.T, m *mockMistral, phase map[string]interface{}) policy.Policy {
	t.Helper()
	if phase == nil {
		phase = map[string]interface{}{}
	}
	if _, ok := phase["streamingTextUnitChars"]; !ok {
		phase["streamingTextUnitChars"] = 100
	}
	return newPolicy(t, m, map[string]interface{}{"request": nil, "response": phase})
}

func TestStreamSafeIsHeldThenReleasedInOrder(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, nil))

	var delivered strings.Builder
	frames := []string{sseRoleFrame, sseFrame("Hello "), sseFrame("there, "), sseFrame(strings.Repeat("x", 110)), sseFrame(" and more text"), sseDoneFrame}
	for i, f := range frames {
		body, term, nilBody := bodyOf(t, h.flush(f, i == len(frames)-1))
		if term || nilBody && f != "" {
			// a nil body would pass the flush through unchecked
			t.Fatalf("flush %d: terminated=%v nilBody=%v", i, term, nilBody)
		}
		delivered.WriteString(body)
	}
	if delivered.String() != strings.Join(frames, "") {
		t.Errorf("delivered bytes differ from the stream:\n%q\nvs\n%q", delivered.String(), strings.Join(frames, ""))
	}
	if m.calls.Load() < 2 {
		t.Errorf("expected at least a unit-triggered and an end-of-stream check, got %d calls", m.calls.Load())
	}
}

func TestStreamNothingIsDeliveredBeforeItsTextIsChecked(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, map[string]interface{}{"streamingTextUnitChars": 100}))

	body, term, nilBody := bodyOf(t, h.flush(sseFrame("short text"), false))
	if term || nilBody || body != "" {
		t.Errorf("a flush below the text unit must be withheld with an empty non-nil body; got body=%q nil=%v", body, nilBody)
	}
	if m.calls.Load() != 0 {
		t.Error("nothing should have been checked yet")
	}
	body, _, _ = bodyOf(t, h.flush(sseDoneFrame, true))
	if body != sseFrame("short text")+sseDoneFrame {
		t.Errorf("end of stream should release the held bytes, got %q", body)
	}
	if m.calls.Load() != 1 {
		t.Errorf("the short stream should be checked once at its end, got %d calls", m.calls.Load())
	}
}

func TestStreamViolationEndsStreamAndDropsHeldBytes(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, nil))

	if _, term, _ := bodyOf(t, h.flush(sseFrame(strings.Repeat("a", 120)), false)); term { // batch 1 passes and is released
		t.Fatal("clean batch terminated")
	}
	a := h.flush(sseFrame("I will kill you ")+sseFrame(strings.Repeat("b", 120)), false)
	tr, ok := a.(policy.TerminateResponseChunk)
	if !ok {
		t.Fatalf("expected the stream to be terminated, got %T", a)
	}
	body := string(tr.Body)
	if !strings.HasPrefix(body, "data: {") || !strings.HasSuffix(body, "\n\n") {
		t.Errorf("last event is not an SSE data event: %q", body)
	}
	if strings.Contains(body, "kill") || strings.Contains(body, "bbbb") {
		t.Errorf("the held text leaked into the terminating event: %q", body)
	}
	if !strings.Contains(body, `"MISTRAL_MODERATION"`) || !strings.Contains(body, "GUARDRAIL_INTERVENED") {
		t.Errorf("unexpected body %q", body)
	}
	if !tr.IsFault || tr.Fault == nil || tr.Fault.Code != policy.GuardrailCodeViolence || tr.Fault.Direction != policy.DirectionResponse {
		t.Errorf("fault = %+v isFault=%v", tr.Fault, tr.IsFault)
	}
}

func TestStreamFramingOnlyIsForwardedImmediately(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, nil))
	body, term, _ := bodyOf(t, h.flush(": keep-alive\n\n"+sseRoleFrame, false))
	if term || body != ": keep-alive\n\n"+sseRoleFrame {
		t.Errorf("framing with no text should pass straight through, got %q", body)
	}
	if m.calls.Load() != 0 {
		t.Error("no text, no check")
	}
}

func TestStreamPhraseSplitAcrossBatchesIsStillCaught(t *testing.T) {
	// Batch 1 ends "...kill", batch 2 starts " you...". Neither contains "kill you";
	// the second check carries the end of the first as context.
	m := newMock(t, keywordReply("kill you"))
	h := newHarness(t, streamPolicy(t, m, nil))
	if _, term, _ := bodyOf(t, h.flush(sseFrame(strings.Repeat("z", 110)+" I will kill"), false)); term {
		t.Fatal("first batch terminated")
	}
	a := h.flush(sseFrame(" you "+strings.Repeat("q", 110)), false)
	if _, ok := a.(policy.TerminateResponseChunk); !ok {
		t.Fatalf("a phrase split across batches evaded the check: %T", a)
	}
}

func TestStreamFlushCutMidLineKeepsThePartialLineHeld(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, nil))
	full := sseFrame(strings.Repeat("a", 150)) // exceeds the unit
	cut := len(full) - 7
	body, _, _ := bodyOf(t, h.flush(full[:cut], false)) // ends mid-line: its text cannot be read yet
	if body != "" {
		t.Errorf("an incomplete line must not be released, got %q", body)
	}
	body, _, _ = bodyOf(t, h.flush(full[cut:]+sseDoneFrame, true))
	if body != full+sseDoneFrame {
		t.Errorf("after completion everything is released in order, got %q", body)
	}
}

func TestStreamCRLFAndNoSpaceAfterColon(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, nil))
	stream := "data:{\"choices\":[{\"delta\":{\"content\":\"I will kill you\"}}]}\r\n\r\ndata: [DONE]\r\n\r\n"
	if _, ok := h.flush(stream, true).(policy.TerminateResponseChunk); !ok {
		t.Error("CRLF framing / no-space data: line evaded the check")
	}
}

func TestStreamEndOfStreamEmptyChunkStillChecksPendingText(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, nil))
	h.flush(sseFrame("I will kill you"), false) // below the unit: held
	if _, ok := h.flush("", true).(policy.TerminateResponseChunk); !ok {
		t.Error("the bare end-of-stream sentinel must still trigger the last check")
	}
}

func TestStreamWholeStreamMode(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, map[string]interface{}{"streamingTextUnitChars": 0}))
	for i := 0; i < 20; i++ {
		body, term, nilBody := bodyOf(t, h.flush(sseFrame(strings.Repeat("a", 200)), false))
		if term || nilBody || body != "" {
			t.Fatalf("whole-stream mode must hold everything: body=%q", body)
		}
	}
	if m.calls.Load() != 0 {
		t.Error("checked before the end")
	}
	h.flush(sseDoneFrame, true)
	if m.calls.Load() != 1 {
		t.Errorf("calls = %d, want exactly one at the end", m.calls.Load())
	}
}

func TestStreamHeldBytesLimitForcesACheck(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, map[string]interface{}{"streamingTextUnitChars": 0}))
	big := ": " + strings.Repeat("p", maxHeldBytes+10) + "\n\n"
	body, term, _ := bodyOf(t, h.flush(sseFrame("some text")+big, false))
	if term || body == "" {
		t.Errorf("exceeding the held-bytes limit should check and release, got body len %d term=%v", len(body), term)
	}
	if m.calls.Load() != 1 {
		t.Errorf("calls = %d", m.calls.Load())
	}
}

func TestStreamAPIFailureFailsClosedOrPassesThrough(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { http.Error(w, "x", 401) })
	h := newHarness(t, streamPolicy(t, m, nil))
	tr, ok := h.flush(sseFrame(strings.Repeat("a", 150)), false).(policy.TerminateResponseChunk)
	if !ok {
		t.Fatal("expected the stream to be terminated when the check cannot run")
	}
	if !strings.Contains(string(tr.Body), "SERVICE_UNAVAILABLE") || tr.Fault.Code != policy.FaultCodeMediationFailed {
		t.Errorf("body=%s fault=%+v", tr.Body, tr.Fault)
	}

	m2 := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { http.Error(w, "x", 401) })
	h2 := newHarness(t, streamPolicy(t, m2, map[string]interface{}{"passthroughOnError": true}))
	frame := sseFrame(strings.Repeat("a", 150))
	body, term, _ := bodyOf(t, h2.flush(frame, false))
	if term || body != frame {
		t.Errorf("passthroughOnError should release the bytes, got term=%v body=%q", term, body)
	}
}

func TestStreamNon2xxAndUnconfiguredAndEmptyForward(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, nil))
	h.ctx.ResponseStatus = 500
	if f, ok := h.flush(`{"error":"I will kill you"}`, true).(policy.ForwardResponseChunk); !ok || f.Body != nil {
		t.Error("a non-2xx upstream body must pass through untouched")
	}
	h2 := newHarness(t, newPolicy(t, m, nil)) // request-only attachment
	if f, ok := h2.flush(sseFrame("I will kill you"), true).(policy.ForwardResponseChunk); !ok || f.Body != nil {
		t.Error("an unconfigured response phase must pass through")
	}
	h3 := newHarness(t, streamPolicy(t, m, nil))
	if f, ok := h3.flush("", false).(policy.ForwardResponseChunk); !ok || f.Body != nil {
		t.Error("an empty mid-stream chunk is a no-op")
	}
	if m.calls.Load() != 0 {
		t.Errorf("no check expected, got %d", m.calls.Load())
	}
}

func TestStreamedJSONDocumentIsHeldWholeAndChecked(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, nil))
	body, term, nilBody := bodyOf(t, h.flush(`{"choices":[{"message":{"content":"I will `, false))
	if term || nilBody || body != "" {
		t.Fatalf("a chunked JSON body must be held until complete: body=%q", body)
	}
	tr, ok := h.flush(`kill you"}}]}`, true).(policy.TerminateResponseChunk)
	if !ok {
		t.Fatal("violating JSON document was released")
	}
	if strings.HasPrefix(string(tr.Body), "data:") || !strings.Contains(string(tr.Body), "MISTRAL_MODERATION") {
		t.Errorf("a JSON document is answered with the JSON error body, got %q", tr.Body)
	}

	m2 := newMock(t, keywordReply("kill"))
	h2 := newHarness(t, streamPolicy(t, m2, nil))
	h2.flush(`{"choices":[{"message":`, false)
	doc := `{"choices":[{"message":{"content":"fine"}}]}`
	body, term, _ = bodyOf(t, h2.flush(`{"content":"fine"}}]}`, true))
	if term || body != doc {
		t.Errorf("clean JSON document should be released whole, got %q", body)
	}
}

func TestStreamOpaqueFormatIsForwardedUnchecked(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, nil))
	if f, ok := h.flush("\x00\x01 binary I will kill you", true).(policy.ForwardResponseChunk); !ok || f.Body != nil {
		t.Error("an unreadable stream cannot be checked and is forwarded")
	}
}

func TestStreamCustomStreamingPath(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	h := newHarness(t, streamPolicy(t, m, map[string]interface{}{"streamingJsonPath": "$.delta.text"}))
	frame := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"I will kill you\"}}\n\n"
	if _, ok := h.flush(frame, true).(policy.TerminateResponseChunk); !ok {
		t.Error("an Anthropic-style frame was not read with the custom streamingJsonPath")
	}
}

func TestNeedsMoreResponseData(t *testing.T) {
	m := newMock(t, keywordReply(""))
	p := streamPolicy(t, m, nil).(policy.StreamingResponsePolicy)
	big := strings.Repeat("a", streamFlushPacerBytes)
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"small flush keeps accumulating", sseFrame("hi"), true},
		{"large SSE flush ending on a boundary", ": " + big + "\n\n", false},
		{"large SSE flush cut mid-event", ": " + big + "\ndata: {", true},
		{"large SSE flush ending in a single newline", ": " + big + "\n", true},
		{"CRLF boundary", ": " + big + "\r\n\r\n", false},
		{"JSON document is held whole", `{"a":"` + big + `"}`, true},
		{"large opaque flush", "\x00" + big, false},
	}
	for _, tc := range cases {
		if got := p.NeedsMoreResponseData([]byte(tc.in)); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
	reqOnly := newPolicy(t, m, nil).(policy.StreamingResponsePolicy)
	if reqOnly.NeedsMoreResponseData([]byte("x")) {
		t.Error("an unconfigured response phase never asks for more data")
	}
}

func TestBufferedFallbackReadsAnSSEBody(t *testing.T) {
	// When the engine buffers a streamed reply, OnResponseBody receives the whole SSE text.
	m := newMock(t, keywordReply("kill"))
	p := newPolicy(t, m, map[string]interface{}{"request": nil, "response": map[string]interface{}{}})
	safe := sseRoleFrame + sseFrame("all ") + sseFrame("good") + sseDoneFrame
	if a := runResponse(p, 200, safe).(policy.DownstreamResponseModifications); a.IsFault {
		t.Errorf("clean buffered SSE blocked: %+v", a)
	}
	if got := m.lastReq.Input; len(got) != 1 || got[0] != "all good" {
		t.Errorf("input = %q, want the frames' text joined", got)
	}
	bad := sseRoleFrame + sseFrame("I will ") + sseFrame("kill you") + sseDoneFrame
	if a := runResponse(p, 200, bad).(policy.DownstreamResponseModifications); !a.IsFault {
		t.Error("violating buffered SSE was released")
	}
}

func TestStreamingParamsValidation(t *testing.T) {
	base := func(phase map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"apiKey": "k", "response": phase}
	}
	bad := map[string]map[string]interface{}{
		"unit too small":         {"streamingTextUnitChars": 50},
		"unit not an integer":    {"streamingTextUnitChars": 150.5},
		"unit negative":          {"streamingTextUnitChars": -1},
		"empty streaming path":   {"streamingJsonPath": ""},
		"invalid streaming path": {"streamingJsonPath": "$.a["},
		"invalid jsonPath":       {"jsonPath": "$.a[?(@.x ==)]"},
		"bad maxContentChars":    {"maxContentChars": 0},
	}
	for name, phase := range bad {
		if _, err := GetPolicy(policy.PolicyMetadata{}, base(phase)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	for _, key := range []string{"streamingJsonPath", "streamingTextUnitChars"} {
		_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"apiKey": "k", "request": map[string]interface{}{key: map[string]interface{}{}}})
		if err == nil || !strings.Contains(err.Error(), "response phase only") {
			t.Errorf("%s on the request phase: %v", key, err)
		}
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, base(map[string]interface{}{"streamingTextUnitChars": 0, "jsonPath": "$.a[*].b"})); err != nil {
		t.Errorf("valid params rejected: %v", err)
	}
}

// ─── Multi-text payloads (arrays, wildcards, content parts) ─────────────────

func TestWildcardPathChecksEveryMessageInBatches(t *testing.T) {
	m := newMock(t, keywordReply("kill you"))
	var msgs []string
	for i := 0; i < 45; i++ {
		msgs = append(msgs, fmt.Sprintf(`{"role":"user","content":"message %d"}`, i))
	}
	msgs[33] = `{"role":"user","content":"I will kill you"}`
	body := `{"messages":[` + strings.Join(msgs, ",") + `]}`
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"jsonPath": "$.messages[*].content"}})

	r := asImmediate(t, runRequest(p, body))
	if r.StatusCode != 422 {
		t.Errorf("status = %d", r.StatusCode)
	}
	reqs := m.allRequests()
	if len(reqs) != 3 {
		t.Fatalf("45 texts should go out in 3 calls of at most %d, got %d", textsPerCall, len(reqs))
	}
	total := 0
	for _, rq := range reqs {
		if len(rq.Input) > textsPerCall {
			t.Errorf("call carried %d inputs", len(rq.Input))
		}
		total += len(rq.Input)
	}
	if total != 45 {
		t.Errorf("%d of 45 messages were checked", total)
	}
}

func TestContentPartsArrayIsChecked(t *testing.T) {
	m := newMock(t, keywordReply("kill you"))
	body := `{"messages":[{"role":"user","content":[
	  {"type":"text","text":"describe this picture"},
	  {"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}},
	  {"type":"text","text":"I will kill you"}]}]}`
	r := asImmediate(t, runRequest(newPolicy(t, m, nil), body)) // the default last-message path
	if r.StatusCode != 422 {
		t.Errorf("status = %d: a multimodal message used to fail the whole request with a path error", r.StatusCode)
	}
	if in := m.lastReq.Input; len(in) != 2 || in[0] != "describe this picture" || in[1] != "I will kill you" {
		t.Errorf("inputs = %q, want the two text parts and not the image", in)
	}
}

func TestFilterPathSelectsOnlyUserMessages(t *testing.T) {
	m := newMock(t, keywordReply("kill you"))
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{
		"jsonPath": "$.messages[?(@.role=='user')].content",
	}})
	body := `{"messages":[{"role":"system","content":"I will kill you"},{"role":"user","content":"hello"},{"role":"assistant","content":"hi"}]}`
	assertAllowedRequest(t, runRequest(p, body))
	if in := m.lastReq.Input; len(in) != 1 || in[0] != "hello" {
		t.Errorf("inputs = %q", in)
	}
}

func TestPathWithNoTextIsNothingToCheck(t *testing.T) {
	m := newMock(t, keywordReply("kill"))
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"jsonPath": "$.messages[*].content"}})
	assertAllowedRequest(t, runRequest(p, `{"messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"1"}]}]}`))
	assertAllowedRequest(t, runRequest(p, `{"messages":[]}`))
	p2 := newPolicy(t, m, nil)
	assertAllowedRequest(t, runRequest(p2, `{"messages":[{"role":"assistant","content":null}]}`)) // last message with null content
	if m.calls.Load() != 0 {
		t.Errorf("no text, no API call; got %d", m.calls.Load())
	}
}

func TestTooManyTextsAndTooMuchContentFailClosed(t *testing.T) {
	m := newMock(t, keywordReply(""))
	var msgs []string
	for i := 0; i < maxTexts+1; i++ {
		msgs = append(msgs, `{"content":"x"}`)
	}
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"jsonPath": "$.m[*].content"}})
	if r := asImmediate(t, runRequest(p, `{"m":[`+strings.Join(msgs, ",")+`]}`)); r.StatusCode != 503 {
		t.Errorf("too many texts: status = %d", r.StatusCode)
	}
	small := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"maxContentChars": 10}})
	if r := asImmediate(t, runRequest(small, `{"messages":[{"content":"this is longer than ten characters"}]}`)); r.StatusCode != 503 {
		t.Errorf("too much content: status = %d", r.StatusCode)
	}
	pass := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"maxContentChars": 10, "passthroughOnError": true}})
	assertAllowedRequest(t, runRequest(pass, `{"messages":[{"content":"this is longer than ten characters"}]}`))
	if m.calls.Load() != 0 {
		t.Errorf("limits are enforced before any API call; got %d", m.calls.Load())
	}
}

func TestResultCountMismatchFailsClosed(t *testing.T) {
	m := newMock(t, func(_ *mockMistral, w http.ResponseWriter, _ int) { safeReply(w) }) // always one result
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"jsonPath": "$.m[*]"}})
	if r := asImmediate(t, runRequest(p, `{"m":["a","b","c"]}`)); r.StatusCode != 503 {
		t.Errorf("status = %d", r.StatusCode)
	}
}

func TestStrongestViolationAcrossTextsIsReported(t *testing.T) {
	m := newMock(t, func(m *mockMistral, w http.ResponseWriter, _ int) {
		results := []interface{}{
			map[string]interface{}{"categories": map[string]bool{"sexual": true}, "category_scores": map[string]float64{"sexual": 0.6}},
			map[string]interface{}{"categories": map[string]bool{"sexual": true}, "category_scores": map[string]float64{"sexual": 0.9}},
		}
		_ = jsonEncode(w, map[string]interface{}{"results": results})
	})
	p := newPolicy(t, m, map[string]interface{}{"request": map[string]interface{}{"jsonPath": "$.m[*]", "showAssessment": true}})
	r := asImmediate(t, runRequest(p, `{"m":["a","b"]}`))
	cats := decodeEnvelope(t, r.Body)["message"].(map[string]interface{})["assessments"].(map[string]interface{})["categories"].([]interface{})
	if len(cats) != 1 || cats[0].(map[string]interface{})["score"].(float64) != 0.9 {
		t.Errorf("categories = %v", cats)
	}
}

func TestStreamWithoutSharedContextFailsClosed(t *testing.T) {
	m := newMock(t, keywordReply(""))
	p := streamPolicy(t, m, nil).(policy.StreamingResponsePolicy)
	a := p.OnResponseBodyChunk(context.Background(), &policy.ResponseStreamContext{ResponseStatus: 200},
		&policy.StreamBody{Chunk: []byte(sseFrame("x"))}, nil)
	if _, ok := a.(policy.TerminateResponseChunk); !ok {
		t.Errorf("got %T, want the stream terminated", a)
	}
	pt := streamPolicy(t, m, map[string]interface{}{"passthroughOnError": true}).(policy.StreamingResponsePolicy)
	a = pt.OnResponseBodyChunk(context.Background(), &policy.ResponseStreamContext{ResponseStatus: 200},
		&policy.StreamBody{Chunk: []byte(sseFrame("x"))}, nil)
	if f, ok := a.(policy.ForwardResponseChunk); !ok || f.Body != nil {
		t.Errorf("got %#v, want pass-through", a)
	}
}
