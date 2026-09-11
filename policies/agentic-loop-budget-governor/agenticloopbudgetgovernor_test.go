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

package agenticloopbudgetgovernor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func reqCtx(headers map[string][]string, body []byte) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Headers:       headersFrom(headers),
		Body:          &policy.Body{Content: body, Present: true, EndOfStream: true},
	}
}

func headersFrom(m map[string][]string) *policy.Headers {
	return policy.NewHeaders(m)
}

func mustPolicy(t *testing.T, params map[string]interface{}) *AgenticLoopBudgetGovernorPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*AgenticLoopBudgetGovernorPolicy)
}

func chatBody(t *testing.T, content string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"messages": []map[string]string{{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func toolCallBody(t *testing.T, name string, args map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": name, "arguments": args},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func isBlocked(a policy.RequestAction) (int, bool) {
	ir, ok := a.(policy.ImmediateResponse)
	if !ok {
		return 0, false
	}
	return ir.StatusCode, true
}

// ─── GetPolicy validation ────────────────────────────────────────────────────

func TestGetPolicy_Defaults(t *testing.T) {
	p := mustPolicy(t, nil)
	if p.cfg.maxCalls != 40 || p.cfg.maxTokens != 200000 || p.cfg.maxDurationSeconds != 900 || p.cfg.maxConsecutiveIdentical != 3 {
		t.Fatalf("unexpected defaults: %+v", p.cfg)
	}
	if p.cfg.onBreach != actionBlock {
		t.Fatalf("default onBreach = %q, want block", p.cfg.onBreach)
	}
	if p.cfg.sessionKey.header != "x-agent-session-id" || !p.cfg.sessionKey.fallbackToHash {
		t.Fatalf("unexpected sessionKey defaults: %+v", p.cfg.sessionKey)
	}
}

func TestGetPolicy_AllLimitsZero_Errors(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"maxCalls": 0.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
	})
	if err == nil {
		t.Fatal("expected error when every limit is 0")
	}
}

func TestGetPolicy_InvalidOnBreach(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"onBreach": "ignore"}); err == nil {
		t.Fatal("expected error for invalid onBreach")
	}
}

func TestGetPolicy_NegativeMaxCalls(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"maxCalls": -1.0}); err == nil {
		t.Fatal("expected error for negative maxCalls")
	}
}

func TestGetPolicy_WindowSecondsTooSmall(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"windowSeconds": 0.0}); err == nil {
		t.Fatal("expected error for windowSeconds < 1")
	}
}

func TestGetPolicy_SessionKeyWrongType(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"sessionKey": "nope"}); err == nil {
		t.Fatal("expected error for non-object sessionKey")
	}
}

func TestGetPolicy_SessionKeyFieldTypes(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"sessionKey": map[string]interface{}{"header": 5},
	}); err == nil {
		t.Fatal("expected error for non-string sessionKey.header")
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"sessionKey": map[string]interface{}{"fallbackToHash": "yes"},
	}); err == nil {
		t.Fatal("expected error for non-bool fallbackToHash")
	}
}

// ─── maxCalls ────────────────────────────────────────────────────────────────

func TestMaxCalls_BlocksOnceExceeded(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 2.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
	})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, chatBody(t, "hi"))
	for i := 0; i < 2; i++ {
		a := p.OnRequestBody(context.Background(), rc, nil)
		if _, blocked := isBlocked(a); blocked {
			t.Fatalf("call %d unexpectedly blocked", i+1)
		}
	}
	a := p.OnRequestBody(context.Background(), rc, nil)
	code, blocked := isBlocked(a)
	if !blocked || code != 429 {
		t.Fatalf("expected 429 on 3rd call, got %#v", a)
	}
}

func TestMaxCalls_IndependentPerSession(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 1.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
	})
	rc1 := reqCtx(map[string][]string{"x-agent-session-id": {"alice"}}, chatBody(t, "hi"))
	rc2 := reqCtx(map[string][]string{"x-agent-session-id": {"bob"}}, chatBody(t, "hi"))
	if _, blocked := isBlocked(p.OnRequestBody(context.Background(), rc1, nil)); blocked {
		t.Fatal("alice's first call should pass")
	}
	if _, blocked := isBlocked(p.OnRequestBody(context.Background(), rc2, nil)); blocked {
		t.Fatal("bob's first call should pass (separate session)")
	}
	if _, blocked := isBlocked(p.OnRequestBody(context.Background(), rc1, nil)); !blocked {
		t.Fatal("alice's second call should be blocked")
	}
}

// ─── maxTokens ───────────────────────────────────────────────────────────────

func TestMaxTokens_BlocksOnceExceeded(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 0.0, "maxTokens": 5.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
	})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, chatBody(t, string(make([]byte, 200))))
	a := p.OnRequestBody(context.Background(), rc, nil)
	if _, blocked := isBlocked(a); !blocked {
		t.Fatalf("expected token ceiling to be exceeded on first oversized call, got %#v", a)
	}
}

// ─── maxDurationSeconds ──────────────────────────────────────────────────────

func TestMaxDuration_BlocksAfterWindowElapses(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 0.0, "maxTokens": 0.0, "maxDurationSeconds": 0.05, "maxConsecutiveIdenticalToolCalls": 0.0,
		"windowSeconds": 3600.0,
	})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, chatBody(t, "hi"))
	if _, blocked := isBlocked(p.OnRequestBody(context.Background(), rc, nil)); blocked {
		t.Fatal("first call should pass")
	}
	time.Sleep(80 * time.Millisecond)
	a := p.OnRequestBody(context.Background(), rc, nil)
	if _, blocked := isBlocked(a); !blocked {
		t.Fatalf("expected duration ceiling breach, got %#v", a)
	}
}

// ─── maxConsecutiveIdenticalToolCalls ────────────────────────────────────────

func TestConsecutiveIdenticalToolCalls_Blocks(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 0.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 2.0,
	})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, toolCallBody(t, "search", map[string]interface{}{"q": "same"}))
	for i := 0; i < 2; i++ {
		if _, blocked := isBlocked(p.OnRequestBody(context.Background(), rc, nil)); blocked {
			t.Fatalf("call %d should pass", i+1)
		}
	}
	a := p.OnRequestBody(context.Background(), rc, nil)
	if _, blocked := isBlocked(a); !blocked {
		t.Fatalf("expected loop breach on 3rd identical call, got %#v", a)
	}
}

func TestConsecutiveIdenticalToolCalls_ResetsOnDifferentArgs(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 0.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 2.0,
	})
	same := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, toolCallBody(t, "search", map[string]interface{}{"q": "same"}))
	diff := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, toolCallBody(t, "search", map[string]interface{}{"q": "different"}))
	p.OnRequestBody(context.Background(), same, nil)
	p.OnRequestBody(context.Background(), diff, nil) // different args -> counter resets
	a := p.OnRequestBody(context.Background(), same, nil)
	if _, blocked := isBlocked(a); blocked {
		t.Fatalf("counter should have reset after a different call, got %#v", a)
	}
}

func TestConsecutiveIdenticalToolCalls_ResetsOnDifferentTool(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 0.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 1.0,
	})
	rcA := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, toolCallBody(t, "search", map[string]interface{}{"q": "x"}))
	rcB := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, toolCallBody(t, "fetch", map[string]interface{}{"q": "x"}))
	p.OnRequestBody(context.Background(), rcA, nil)
	if _, blocked := isBlocked(p.OnRequestBody(context.Background(), rcB, nil)); blocked {
		t.Fatal("a different tool name should not count as identical")
	}
}

// ─── onBreach: annotate ──────────────────────────────────────────────────────

func TestOnBreach_Annotate_ForwardsWithHeaders(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 1.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
		"onBreach": "annotate",
	})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, chatBody(t, "hi"))
	p.OnRequestBody(context.Background(), rc, nil)
	a := p.OnRequestBody(context.Background(), rc, nil)
	mods, ok := a.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications (annotate forwards), got %#v", a)
	}
	if mods.HeadersToSet["x-loop-budget"] != "breach" {
		t.Fatalf("expected x-loop-budget: breach header, got %#v", mods.HeadersToSet)
	}
}

// ─── showAssessment ──────────────────────────────────────────────────────────

func TestShowAssessment_IncludesReasonsInBody(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 1.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
		"showAssessment": true,
	})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, chatBody(t, "hi"))
	p.OnRequestBody(context.Background(), rc, nil)
	a := p.OnRequestBody(context.Background(), rc, nil)
	ir := a.(policy.ImmediateResponse)
	var parsed map[string]interface{}
	if err := json.Unmarshal(ir.Body, &parsed); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	msg := parsed["message"].(map[string]interface{})
	if _, ok := msg["assessments"]; !ok {
		t.Fatalf("expected assessments in body: %s", ir.Body)
	}
	if parsed["type"] != governorType {
		t.Fatalf("unexpected envelope type: %v", parsed["type"])
	}
}

func TestShowAssessment_False_OmitsReasons(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 1.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
		"showAssessment": false,
	})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, chatBody(t, "hi"))
	p.OnRequestBody(context.Background(), rc, nil)
	a := p.OnRequestBody(context.Background(), rc, nil)
	ir := a.(policy.ImmediateResponse)
	var parsed map[string]interface{}
	_ = json.Unmarshal(ir.Body, &parsed)
	msg := parsed["message"].(map[string]interface{})
	if _, ok := msg["assessments"]; ok {
		t.Fatalf("did not expect assessments when showAssessment is false: %s", ir.Body)
	}
}

// ─── session key resolution ──────────────────────────────────────────────────

func TestSessionKey_FromHeader(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"maxCalls": 1.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"sess-header"}}, chatBody(t, "hi"))
	p.OnRequestBody(context.Background(), rc, nil)
	p.mu.Lock()
	_, ok := p.sessions["h:sess-header"]
	p.mu.Unlock()
	if !ok {
		t.Fatal("expected session tracked under the header-derived key")
	}
}

func TestSessionKey_FromJsonPath_WhenHeaderAbsent(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"maxCalls": 1.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0})
	body, _ := json.Marshal(map[string]interface{}{"session_id": "body-sess", "messages": []map[string]string{{"role": "user", "content": "hi"}}})
	rc := reqCtx(nil, body)
	p.OnRequestBody(context.Background(), rc, nil)
	p.mu.Lock()
	_, ok := p.sessions["j:body-sess"]
	p.mu.Unlock()
	if !ok {
		t.Fatal("expected session tracked under the body jsonPath-derived key")
	}
}

func TestSessionKey_FallbackToHash(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 1.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
		"sessionKey": map[string]interface{}{"header": "", "jsonPath": "", "fallbackToHash": true},
	})
	body, _ := json.Marshal(map[string]interface{}{
		"messages": []map[string]string{{"role": "system", "content": "you are a helpful bot"}, {"role": "user", "content": "hi"}},
	})
	rc := reqCtx(map[string][]string{"authorization": {"Bearer tok-1"}}, body)
	p.OnRequestBody(context.Background(), rc, nil)
	p.mu.Lock()
	n := len(p.sessions)
	var gotHashKey bool
	for k := range p.sessions {
		if len(k) > 2 && k[:2] == "f:" {
			gotHashKey = true
		}
	}
	p.mu.Unlock()
	if n != 1 || !gotHashKey {
		t.Fatalf("expected exactly one hash-derived session, got %d sessions, hashKey=%v", n, gotHashKey)
	}
}

func TestSessionKey_Unidentified_SharesOneBucket(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 2.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
		"sessionKey": map[string]interface{}{"header": "", "jsonPath": "", "fallbackToHash": false},
	})
	rc1 := reqCtx(nil, chatBody(t, "hi"))
	rc2 := reqCtx(nil, chatBody(t, "there"))
	p.OnRequestBody(context.Background(), rc1, nil)
	a := p.OnRequestBody(context.Background(), rc2, nil)
	// two distinct callers, but both unidentified -> share the same bucket,
	// so the 2nd call already trips maxCalls=2 only after this 2nd; a 3rd
	// call (from either) must be blocked, proving they share state.
	if _, blocked := isBlocked(a); blocked {
		t.Fatal("2nd call should still be within budget")
	}
	a3 := p.OnRequestBody(context.Background(), rc1, nil)
	if _, blocked := isBlocked(a3); !blocked {
		t.Fatal("3rd call across unidentified callers should share budget and be blocked")
	}
}

// ─── idle window / TTL ───────────────────────────────────────────────────────

func TestWindowSeconds_ResetsStateAfterIdle(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 1.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
		"windowSeconds": 1.0,
	})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, chatBody(t, "hi"))
	p.OnRequestBody(context.Background(), rc, nil)
	if _, blocked := isBlocked(p.OnRequestBody(context.Background(), rc, nil)); !blocked {
		t.Fatal("2nd call within the window should be blocked")
	}
	time.Sleep(1100 * time.Millisecond)
	a := p.OnRequestBody(context.Background(), rc, nil)
	if _, blocked := isBlocked(a); blocked {
		t.Fatalf("call after the idle window should start a fresh session, got %#v", a)
	}
}

// ─── eviction bound ──────────────────────────────────────────────────────────

func TestEviction_BoundsSessionMap(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 100000.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
		"windowSeconds": 3600.0,
	})
	for i := 0; i < maxTrackedSessions+500; i++ {
		rc := reqCtx(map[string][]string{"x-agent-session-id": {fmt.Sprintf("s-%d", i)}}, chatBody(t, "hi"))
		p.OnRequestBody(context.Background(), rc, nil)
	}
	p.mu.Lock()
	n := len(p.sessions)
	p.mu.Unlock()
	if n > maxTrackedSessions {
		t.Fatalf("session map grew past the cap: %d > %d", n, maxTrackedSessions)
	}
}

// ─── concurrency ─────────────────────────────────────────────────────────────

func TestConcurrentRequests_NoRace(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 1000.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
	})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rc := reqCtx(map[string][]string{"x-agent-session-id": {fmt.Sprintf("s-%d", i%5)}}, chatBody(t, "hi"))
			for j := 0; j < 20; j++ {
				p.OnRequestBody(context.Background(), rc, nil)
			}
		}(i)
	}
	wg.Wait()
}

// ─── malformed / edge-case bodies ────────────────────────────────────────────

func TestNonJSONBody_StillCountsAsACall(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{
		"maxCalls": 1.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0,
	})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, []byte("not json"))
	p.OnRequestBody(context.Background(), rc, nil)
	a := p.OnRequestBody(context.Background(), rc, nil)
	if _, blocked := isBlocked(a); !blocked {
		t.Fatalf("expected 2nd call on non-JSON body to still trip maxCalls, got %#v", a)
	}
}

func TestEmptyBody_NoPanic(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"maxCalls": 5.0, "maxTokens": 0.0, "maxDurationSeconds": 0.0, "maxConsecutiveIdenticalToolCalls": 0.0})
	rc := reqCtx(map[string][]string{"x-agent-session-id": {"s1"}}, nil)
	a := p.OnRequestBody(context.Background(), rc, nil)
	if _, blocked := isBlocked(a); blocked {
		t.Fatal("empty body first call should not be blocked")
	}
}
