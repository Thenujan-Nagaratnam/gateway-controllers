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

package aicontentdisclosure

import (
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func mustPolicy(t *testing.T, params map[string]interface{}) *AiContentDisclosurePolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*AiContentDisclosurePolicy)
}

func chatResponse(t *testing.T, content string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"id": "x", "choices": []map[string]interface{}{{
			"index": 0, "finish_reason": "stop",
			"message": map[string]string{"role": "assistant", "content": content},
		}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func respCtx(body []byte) *policy.ResponseContext {
	return &policy.ResponseContext{
		SharedContext: &policy.SharedContext{},
		ResponseBody:  &policy.Body{Content: body, Present: true, EndOfStream: true},
	}
}

func asDownstream(t *testing.T, a policy.ResponseAction) policy.DownstreamResponseModifications {
	t.Helper()
	m, ok := a.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %#v", a)
	}
	return m
}

func extractContent(t *testing.T, body []byte) string {
	t.Helper()
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	choices := parsed["choices"].([]interface{})
	msg := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	return msg["content"].(string)
}

// ─── GetPolicy validation ────────────────────────────────────────────────────

func TestGetPolicy_Defaults(t *testing.T) {
	p := mustPolicy(t, nil)
	if p.cfg.placement != placementAppend || p.cfg.disclosureStandard != "eu-ai-act-art50" {
		t.Fatalf("unexpected defaults: %+v", p.cfg)
	}
}

func TestGetPolicy_InvalidPlacement(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"placement": "sideways"}); err == nil {
		t.Fatal("expected error for invalid placement")
	}
}

func TestGetPolicy_InvalidInvisibleMarkerTag(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"invisibleMarkerTag": ""}); err == nil {
		t.Fatal("expected error for empty invisibleMarkerTag")
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"invisibleMarkerTag": strings.Repeat("x", 33)}); err == nil {
		t.Fatal("expected error for an over-long invisibleMarkerTag")
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"invisibleMarkerTag": "tag\nwith\nnewlines"}); err == nil {
		t.Fatal("expected error for a non-printable invisibleMarkerTag")
	}
}

// ─── never blocks, always forwards ───────────────────────────────────────────

func TestNeverBlocks(t *testing.T) {
	p := mustPolicy(t, nil)
	a := p.OnResponseBody(nil, respCtx(chatResponse(t, "hello there")), nil)
	m := asDownstream(t, a)
	if m.Body == nil {
		t.Fatal("expected the body to be rewritten by default (placement=append)")
	}
}

// ─── placement: append / prepend / metadata-only ─────────────────────────────

func TestPlacement_Append(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"disclosureText": "AI DISCLOSURE"})
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "original reply")), nil))
	got := extractContent(t, m.Body)
	if !strings.HasPrefix(got, "original reply") || !strings.HasSuffix(got, "AI DISCLOSURE") {
		t.Fatalf("expected notice appended after the original content, got %q", got)
	}
}

func TestPlacement_Prepend(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"disclosureText": "AI DISCLOSURE", "placement": "prepend"})
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "original reply")), nil))
	got := extractContent(t, m.Body)
	if !strings.HasPrefix(got, "AI DISCLOSURE") || !strings.HasSuffix(got, "original reply") {
		t.Fatalf("expected notice prepended before the original content, got %q", got)
	}
}

func TestPlacement_MetadataOnly_LeavesTextUnchanged(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"placement": "metadata-only"})
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "original reply")), nil))
	if m.Body != nil {
		t.Fatalf("metadata-only must not rewrite the body, got %s", m.Body)
	}
	if m.HeadersToSet["x-ai-generated"] != "true" {
		t.Fatalf("expected the header still set, got %#v", m.HeadersToSet)
	}
}

// ─── header / disclosure standard ────────────────────────────────────────────

func TestHeader_SetByDefault(t *testing.T) {
	p := mustPolicy(t, nil)
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "hi")), nil))
	if m.HeadersToSet["x-ai-generated"] != "true" || m.HeadersToSet["x-ai-disclosure-standard"] != "eu-ai-act-art50" {
		t.Fatalf("unexpected headers: %#v", m.HeadersToSet)
	}
}

func TestHeader_CustomStandard(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"disclosureStandard": "ca-ai-transparency-act"})
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "hi")), nil))
	if m.HeadersToSet["x-ai-disclosure-standard"] != "ca-ai-transparency-act" {
		t.Fatalf("expected custom standard label, got %#v", m.HeadersToSet)
	}
}

func TestHeader_DisabledWhenAddHeaderFalse(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"addHeader": false})
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "hi")), nil))
	if _, ok := m.HeadersToSet["x-ai-generated"]; ok {
		t.Fatalf("expected no x-ai-generated header when addHeader is false, got %#v", m.HeadersToSet)
	}
}

// ─── idempotency ──────────────────────────────────────────────────────────────

func TestSkipIfAlreadyDisclosed_VisibleText(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"disclosureText": "AI DISCLOSURE"})
	already := "original reply\n\nAI DISCLOSURE"
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, already)), nil))
	if m.Body != nil {
		t.Fatalf("expected no rewrite when the notice is already present, got %s", m.Body)
	}
}

func TestSkipIfAlreadyDisclosed_False_AppendsAgain(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"disclosureText": "AI DISCLOSURE", "skipIfAlreadyDisclosed": false})
	already := "original reply\n\nAI DISCLOSURE"
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, already)), nil))
	got := extractContent(t, m.Body)
	if strings.Count(got, "AI DISCLOSURE") != 2 {
		t.Fatalf("expected the notice appended a second time, got %q", got)
	}
}

func TestSkipIfAlreadyDisclosed_InvisibleMarker(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"placement": "metadata-only", "embedInvisibleMarker": true, "invisibleMarkerTag": "AI-GEN"})
	first := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "reply")), nil))
	marked := extractContent(t, first.Body)

	second := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, marked)), nil))
	if second.Body != nil {
		t.Fatalf("expected no second marker embedded, got %s", second.Body)
	}
}

// ─── invisible marker round-trip ─────────────────────────────────────────────

func TestInvisibleMarker_RoundTrip(t *testing.T) {
	cases := []string{"AI-GEN", "x", "EU-AI-ACT", "A1_z9"}
	for _, tag := range cases {
		enc := encodeInvisibleTag(tag)
		dec, ok := decodeInvisibleTag(enc)
		if !ok || dec != tag {
			t.Fatalf("round-trip failed for %q: got %q ok=%v", tag, dec, ok)
		}
	}
}

func TestInvisibleMarker_IsActuallyInvisible(t *testing.T) {
	enc := encodeInvisibleTag("AI-GEN")
	visible := strings.Map(func(r rune) rune {
		switch r {
		case markerStart, markerZero, markerOne:
			return -1
		}
		return r
	}, enc)
	if visible != "" {
		t.Fatalf("expected the encoded marker to contain only zero-width runes, got visible remainder %q", visible)
	}
}

func TestInvisibleMarker_EmbeddedInVisibleText_StillDecodes(t *testing.T) {
	tag := "AI-GEN"
	text := "Hello" + encodeInvisibleTag(tag) + " world"
	dec, ok := decodeInvisibleTag(text)
	if !ok || dec != tag {
		t.Fatalf("expected to decode the tag embedded in visible text, got %q ok=%v", dec, ok)
	}
}

func TestInvisibleMarker_NoMarkerPresent(t *testing.T) {
	if _, ok := decodeInvisibleTag("just a normal reply"); ok {
		t.Fatal("expected no marker to be found in plain text")
	}
}

func TestEmbedInvisibleMarker_ActuallyEmbedsInBody(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"placement": "metadata-only", "embedInvisibleMarker": true, "invisibleMarkerTag": "AI-GEN"})
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "reply text")), nil))
	got := extractContent(t, m.Body)
	dec, ok := decodeInvisibleTag(got)
	if !ok || dec != "AI-GEN" {
		t.Fatalf("expected an embedded, decodable marker, got %q (decoded=%q ok=%v)", got, dec, ok)
	}
	if !strings.Contains(got, "reply text") {
		t.Fatalf("expected the original reply text preserved, got %q", got)
	}
}

// ─── edge cases ───────────────────────────────────────────────────────────────

func TestEmptyContent_Skipped(t *testing.T) {
	p := mustPolicy(t, nil)
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "")), nil))
	if len(m.HeadersToSet) != 0 || m.Body != nil {
		t.Fatalf("expected a no-op for empty content, got %#v", m)
	}
}

func TestMinContentChars(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"minContentChars": 20.0})
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "short")), nil))
	if len(m.HeadersToSet) != 0 {
		t.Fatalf("expected content shorter than minContentChars to be skipped, got %#v", m.HeadersToSet)
	}
}

func TestNonJSONBody_NoOp(t *testing.T) {
	p := mustPolicy(t, nil)
	m := asDownstream(t, p.OnResponseBody(nil, respCtx([]byte("not json")), nil))
	if len(m.HeadersToSet) != 0 || m.Body != nil {
		t.Fatalf("expected a no-op for a non-JSON body, got %#v", m)
	}
}

func TestNoContentField_NoOp(t *testing.T) {
	p := mustPolicy(t, nil)
	m := asDownstream(t, p.OnResponseBody(nil, respCtx([]byte(`{"choices":[]}`)), nil))
	if len(m.HeadersToSet) != 0 || m.Body != nil {
		t.Fatalf("expected a no-op when the content path resolves to nothing, got %#v", m)
	}
}

func TestCustomContentJsonPath(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"contentJsonPath": "$.output_text", "disclosureText": "AI NOTICE",
	})
	body, _ := json.Marshal(map[string]interface{}{"output_text": "custom shape reply"})
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(body), nil))
	var parsed map[string]interface{}
	json.Unmarshal(m.Body, &parsed)
	got := parsed["output_text"].(string)
	if !strings.Contains(got, "AI NOTICE") {
		t.Fatalf("expected disclosure appended at the custom path, got %q", got)
	}
}

// ─── both visible + invisible together ───────────────────────────────────────

func TestVisibleAndInvisible_BothApplied(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"disclosureText": "AI NOTICE", "embedInvisibleMarker": true, "invisibleMarkerTag": "AI-GEN",
	})
	m := asDownstream(t, p.OnResponseBody(nil, respCtx(chatResponse(t, "reply")), nil))
	got := extractContent(t, m.Body)
	if !strings.Contains(got, "AI NOTICE") {
		t.Fatalf("expected visible notice present, got %q", got)
	}
	if dec, ok := decodeInvisibleTag(got); !ok || dec != "AI-GEN" {
		t.Fatalf("expected invisible marker present, got decoded=%q ok=%v", dec, ok)
	}
}
