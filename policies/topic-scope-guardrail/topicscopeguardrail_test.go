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

package topicscopeguardrail

import (
	"context"
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const bankingScope = "personal banking assistant: checking account balances, reviewing recent transactions, card management, loan and mortgage inquiries, setting up transfers between accounts"

func mustPolicy(t *testing.T, extra map[string]interface{}) *TopicScopeGuardrailPolicy {
	t.Helper()
	params := map[string]interface{}{"scopeDescription": bankingScope}
	for k, v := range extra {
		params[k] = v
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*TopicScopeGuardrailPolicy)
}

func chatReqBody(t *testing.T, content string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"messages": []map[string]string{{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func chatRespBody(t *testing.T, content string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"choices": []map[string]interface{}{{"message": map[string]string{"role": "assistant", "content": content}}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func reqCtx(body []byte) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Body:          &policy.Body{Content: body, Present: true, EndOfStream: true},
	}
}

func respCtx(body []byte) *policy.ResponseContext {
	return &policy.ResponseContext{
		SharedContext: &policy.SharedContext{},
		ResponseBody:  &policy.Body{Content: body, Present: true, EndOfStream: true},
	}
}

func asImmediate(t *testing.T, a policy.RequestAction) policy.ImmediateResponse {
	t.Helper()
	ir, ok := a.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %#v", a)
	}
	return ir
}

func asUpstream(t *testing.T, a policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	m, ok := a.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %#v", a)
	}
	return m
}

func asDownstream(t *testing.T, a policy.ResponseAction) policy.DownstreamResponseModifications {
	t.Helper()
	m, ok := a.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %#v", a)
	}
	return m
}

// ─── GetPolicy validation ────────────────────────────────────────────────────

func TestGetPolicy_RequiresScopeDescription(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, nil); err == nil {
		t.Fatal("expected error when scopeDescription is missing")
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"scopeDescription": "short"}); err == nil {
		t.Fatal("expected error for a too-short scopeDescription")
	}
}

func TestGetPolicy_InvalidMinScopeScore(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"scopeDescription": bankingScope, "minScopeScore": 1.5}); err == nil {
		t.Fatal("expected error for minScopeScore > 1")
	}
}

func TestGetPolicy_InvalidOnOffTopic(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"scopeDescription": bankingScope, "onOffTopic": "ignore"}); err == nil {
		t.Fatal("expected error for an invalid onOffTopic")
	}
}

func TestGetPolicy_InvalidDeniedTopicsType(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"scopeDescription": bankingScope, "deniedTopics": "not-an-array"}); err == nil {
		t.Fatal("expected error when deniedTopics is not an array")
	}
}

// ─── in-scope traffic passes ─────────────────────────────────────────────────

func TestInScopeMessage_Passes(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx(chatReqBody(t, "What is my checking account balance and can you show recent transactions?"))
	asUpstream(t, p.OnRequestBody(context.Background(), rc, nil))
}

func TestShortGreeting_NeverBlocked(t *testing.T) {
	p := mustPolicy(t, nil)
	for _, greeting := range []string{"hi", "hello!", "thanks", "ok"} {
		rc := reqCtx(chatReqBody(t, greeting))
		asUpstream(t, p.OnRequestBody(context.Background(), rc, nil))
	}
}

// ─── off-topic (low overlap score) is blocked ────────────────────────────────

func TestOffTopicMessage_Blocked(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx(chatReqBody(t, "Write me a Python script that scrapes stock prices from a website every five minutes"))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	if ir.StatusCode != 422 {
		t.Fatalf("expected 422 for an off-topic request, got %d", ir.StatusCode)
	}
	var parsed map[string]interface{}
	json.Unmarshal(ir.Body, &parsed)
	if parsed["type"] != guardrailType {
		t.Fatalf("unexpected envelope type: %v", parsed["type"])
	}
	msg := parsed["message"].(map[string]interface{})
	if msg["direction"] != "REQUEST" {
		t.Fatalf("expected direction REQUEST, got %v", msg["direction"])
	}
}

// ─── denied topics always block, regardless of score ─────────────────────────

func TestDeniedTopic_AlwaysBlocks(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"deniedTopics": []interface{}{"medical advice", "diagnose", "legal advice"},
	})
	// Otherwise banking-adjacent phrasing (mentions "account") but crosses a denied topic.
	rc := reqCtx(chatReqBody(t, "Can you diagnose why my account balance feels off given these medical advice symptoms I have?"))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	if ir.StatusCode != 422 {
		t.Fatalf("expected 422 for a denied-topic match, got %d", ir.StatusCode)
	}
}

func TestDeniedTopic_CaseInsensitive(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"deniedTopics": []interface{}{"legal advice"}})
	rc := reqCtx(chatReqBody(t, "I need some LEGAL ADVICE about my loan contract terms please"))
	asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
}

// ─── inScopeExamples enrich the reference vocabulary ─────────────────────────

func TestInScopeExamples_WidenAcceptedVocabulary(t *testing.T) {
	narrow := "personal banking assistant"
	// Without examples, this specific phrasing scores low against the bare description.
	pNarrow, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"scopeDescription": narrow + " for everyday use"})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	rc := reqCtx(chatReqBody(t, "Can you help me dispute a fraudulent charge on my statement?"))
	blocked := asImmediate(t, pNarrow.(*TopicScopeGuardrailPolicy).OnRequestBody(context.Background(), rc, nil))
	if blocked.StatusCode != 422 {
		t.Fatalf("expected the narrow scope to block this message, got %d (test setup assumption failed)", blocked.StatusCode)
	}

	pWide, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"scopeDescription": narrow + " for everyday use",
		"inScopeExamples":  []interface{}{"Can you help me dispute a fraudulent charge on my statement?", "How do I report a fraudulent transaction?"},
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	rc2 := reqCtx(chatReqBody(t, "Can you help me dispute a fraudulent charge on my statement?"))
	asUpstream(t, pWide.(*TopicScopeGuardrailPolicy).OnRequestBody(context.Background(), rc2, nil))
}

// ─── onOffTopic: annotate ────────────────────────────────────────────────────

func TestOnOffTopic_Annotate_Forwards(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"onOffTopic": "annotate"})
	rc := reqCtx(chatReqBody(t, "Write me a Python script that scrapes stock prices from a website"))
	mods := asUpstream(t, p.OnRequestBody(context.Background(), rc, nil))
	if mods.HeadersToSet["x-topic-scope"] != "off-topic" {
		t.Fatalf("expected x-topic-scope: off-topic header, got %#v", mods.HeadersToSet)
	}
}

// ─── checkResponse ────────────────────────────────────────────────────────────

func TestCheckResponse_Disabled_NeverBlocksReply(t *testing.T) {
	p := mustPolicy(t, nil) // checkResponse defaults false
	rc := respCtx(chatRespBody(t, "Here's a Python script to scrape stock prices from a website every five minutes"))
	m := asDownstream(t, p.OnResponseBody(context.Background(), rc, nil))
	if m.Body != nil || m.StatusCode != nil {
		t.Fatalf("expected no-op when checkResponse is false, got %#v", m)
	}
}

func TestCheckResponse_Enabled_BlocksDriftedReply(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"checkResponse": true})
	rc := respCtx(chatRespBody(t, "Here's a Python script to scrape stock prices from a website every five minutes using requests and BeautifulSoup"))
	a := p.OnResponseBody(context.Background(), rc, nil)
	m, ok := a.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %#v", a)
	}
	if m.StatusCode == nil || *m.StatusCode != 422 {
		t.Fatalf("expected the drifted reply to be blocked with 422, got %#v", m)
	}
}

func TestCheckResponse_Enabled_PassesOnTopicReply(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"checkResponse": true})
	rc := respCtx(chatRespBody(t, "Your checking account balance is $1,204.53 and your most recent transaction was a $42 card payment."))
	m := asDownstream(t, p.OnResponseBody(context.Background(), rc, nil))
	if m.StatusCode != nil {
		t.Fatalf("expected the on-topic reply to pass, got %#v", m)
	}
}

func TestMode_ChecksResponseBodyOnlyWhenEnabled(t *testing.T) {
	pOff := mustPolicy(t, nil)
	if pOff.Mode().ResponseBodyMode != policy.BodyModeSkip {
		t.Fatal("expected ResponseBodyMode Skip when checkResponse is false")
	}
	pOn := mustPolicy(t, map[string]interface{}{"checkResponse": true})
	if pOn.Mode().ResponseBodyMode != policy.BodyModeBuffer {
		t.Fatal("expected ResponseBodyMode Buffer when checkResponse is true")
	}
}

// ─── showAssessment ──────────────────────────────────────────────────────────

func TestShowAssessment_IncludesReasons(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"showAssessment": true})
	rc := reqCtx(chatReqBody(t, "Write me a Python script that scrapes stock prices from a website"))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	var parsed map[string]interface{}
	json.Unmarshal(ir.Body, &parsed)
	msg := parsed["message"].(map[string]interface{})
	if _, ok := msg["assessments"]; !ok {
		t.Fatalf("expected assessments in body: %s", ir.Body)
	}
}

func TestShowAssessment_False_OmitsReasons(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"showAssessment": false})
	rc := reqCtx(chatReqBody(t, "Write me a Python script that scrapes stock prices from a website"))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	var parsed map[string]interface{}
	json.Unmarshal(ir.Body, &parsed)
	msg := parsed["message"].(map[string]interface{})
	if _, ok := msg["assessments"]; ok {
		t.Fatalf("did not expect assessments: %s", ir.Body)
	}
}

// ─── edge cases ───────────────────────────────────────────────────────────────

func TestNonJSONBody_PassthroughOnErrorFalse_Blocks(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx([]byte("not json"))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	if ir.StatusCode != 422 {
		t.Fatalf("expected 422 on unparseable body with passthroughOnError=false, got %d", ir.StatusCode)
	}
}

func TestNonJSONBody_PassthroughOnErrorTrue_Forwards(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"passthroughOnError": true})
	rc := reqCtx([]byte("not json"))
	asUpstream(t, p.OnRequestBody(context.Background(), rc, nil))
}

func TestCustomMinMessageChars(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"minMessageChars": 100.0})
	// A message that WOULD be off-topic, but is short enough to skip scoring entirely.
	rc := reqCtx(chatReqBody(t, "write code"))
	asUpstream(t, p.OnRequestBody(context.Background(), rc, nil))
}

func TestCustomJsonPaths(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"requestJsonPath": "$.prompt"})
	body, _ := json.Marshal(map[string]interface{}{"prompt": "What's my current loan balance and interest rate?"})
	rc := reqCtx(body)
	asUpstream(t, p.OnRequestBody(context.Background(), rc, nil))
}
