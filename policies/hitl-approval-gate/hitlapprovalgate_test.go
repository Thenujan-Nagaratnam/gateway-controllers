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

package hitlapprovalgate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const testSecret = "test-approver-secret-01"

func reqCtx(headers map[string][]string, body []byte) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Headers:       policy.NewHeaders(headers),
		Body:          &policy.Body{Content: body, Present: true, EndOfStream: true},
	}
}

func mustPolicy(t *testing.T, extra map[string]interface{}) *HitlApprovalGatePolicy {
	t.Helper()
	params := map[string]interface{}{
		"highRiskTools":  []interface{}{"issue_refund", "delete_*"},
		"approverSecret": testSecret,
	}
	for k, v := range extra {
		params[k] = v
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*HitlApprovalGatePolicy)
}

func toolBody(t *testing.T, name string, args map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call",
		"params": map[string]interface{}{"name": name, "arguments": args},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func decisionBody(t *testing.T, approvalID, decision, approver, reason string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"approvalDecision": map[string]interface{}{
			"approvalId": approvalID, "decision": decision, "approver": approver, "reason": reason,
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func asImmediate(t *testing.T, a policy.RequestAction) policy.ImmediateResponse {
	t.Helper()
	ir, ok := a.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %#v", a)
	}
	return ir
}

func asForwarded(t *testing.T, a policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	m, ok := a.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %#v", a)
	}
	return m
}

func approvalIDFrom(t *testing.T, ir policy.ImmediateResponse) string {
	t.Helper()
	var parsed map[string]interface{}
	if err := json.Unmarshal(ir.Body, &parsed); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	msg, ok := parsed["message"].(map[string]interface{})
	if !ok {
		t.Fatalf("no message in body: %s", ir.Body)
	}
	id, _ := msg["approvalId"].(string)
	if id == "" {
		t.Fatalf("no approvalId in body: %s", ir.Body)
	}
	return id
}

// ─── GetPolicy validation ────────────────────────────────────────────────────

func TestGetPolicy_RequiresHighRiskTools(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"approverSecret": testSecret})
	if err == nil {
		t.Fatal("expected error when highRiskTools is missing")
	}
}

func TestGetPolicy_RequiresApproverSecret(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"highRiskTools": []interface{}{"x"}})
	if err == nil {
		t.Fatal("expected error when approverSecret is missing")
	}
}

func TestGetPolicy_ApproverSecretTooShort(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"highRiskTools": []interface{}{"x"}, "approverSecret": "short",
	})
	if err == nil {
		t.Fatal("expected error for a too-short approverSecret")
	}
}

func TestGetPolicy_InvalidNotifyUrl(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"highRiskTools": []interface{}{"x"}, "approverSecret": testSecret, "notifyUrl": "not-a-url",
	}); err == nil {
		t.Fatal("expected error for an invalid notifyUrl")
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"highRiskTools": []interface{}{"x"}, "approverSecret": testSecret, "notifyUrl": "ftp://evil.example/x",
	}); err == nil {
		t.Fatal("expected error for a non-http(s) notifyUrl scheme")
	}
}

func TestGetPolicy_InvalidExpirySeconds(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"highRiskTools": []interface{}{"x"}, "approverSecret": testSecret, "expirySeconds": 1.0,
	}); err == nil {
		t.Fatal("expected error for expirySeconds below the floor")
	}
}

func TestGetPolicy_EmptyHighRiskEntry(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"highRiskTools": []interface{}{"ok", ""}, "approverSecret": testSecret,
	}); err == nil {
		t.Fatal("expected error for an empty highRiskTools entry")
	}
}

// ─── low-risk / non-tool traffic passes straight through ────────────────────

func TestLowRiskTool_Passthrough(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx(nil, toolBody(t, "search", map[string]interface{}{"q": "x"}))
	a := p.OnRequestBody(context.Background(), rc, nil)
	asForwarded(t, a)
}

func TestNoToolName_Passthrough(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx(nil, []byte(`{"messages":[{"role":"user","content":"hi"}]}`))
	a := p.OnRequestBody(context.Background(), rc, nil)
	asForwarded(t, a)
}

// ─── glob matching ────────────────────────────────────────────────────────────

func TestHighRiskGlob_Matches(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx(nil, toolBody(t, "delete_database", map[string]interface{}{"id": "1"}))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	if ir.StatusCode != 403 {
		t.Fatalf("expected 403 pending, got %d", ir.StatusCode)
	}
}

// ─── full pending -> decision -> approved retry flow ────────────────────────

func TestFullFlow_ApprovedRetryForwards(t *testing.T) {
	p := mustPolicy(t, nil)
	args := map[string]interface{}{"amount": 500}
	call := reqCtx(nil, toolBody(t, "issue_refund", args))

	pendingIR := asImmediate(t, p.OnRequestBody(context.Background(), call, nil))
	if pendingIR.StatusCode != 403 {
		t.Fatalf("expected 403 pending, got %d", pendingIR.StatusCode)
	}
	id := approvalIDFrom(t, pendingIR)

	decisionRC := reqCtx(map[string][]string{"x-approver-secret": {testSecret}}, decisionBody(t, id, "approve", "alice", "looks fine"))
	decIR := asImmediate(t, p.OnRequestBody(context.Background(), decisionRC, nil))
	if decIR.StatusCode != 200 {
		t.Fatalf("expected 200 recording the decision, got %d: %s", decIR.StatusCode, decIR.Body)
	}

	retryRC := reqCtx(map[string][]string{"x-approval-token": {id}}, toolBody(t, "issue_refund", args))
	mods := asForwarded(t, p.OnRequestBody(context.Background(), retryRC, nil))
	if mods.HeadersToSet["x-hitl-approved"] != "true" {
		t.Fatalf("expected x-hitl-approved header on the forwarded call, got %#v", mods.HeadersToSet)
	}
}

func TestFullFlow_ApprovalTokenIsSingleUse(t *testing.T) {
	p := mustPolicy(t, nil)
	args := map[string]interface{}{"amount": 500}
	call := reqCtx(nil, toolBody(t, "issue_refund", args))
	pendingIR := asImmediate(t, p.OnRequestBody(context.Background(), call, nil))
	id := approvalIDFrom(t, pendingIR)

	decisionRC := reqCtx(map[string][]string{"x-approver-secret": {testSecret}}, decisionBody(t, id, "approve", "alice", ""))
	p.OnRequestBody(context.Background(), decisionRC, nil)

	retryRC := reqCtx(map[string][]string{"x-approval-token": {id}}, toolBody(t, "issue_refund", args))
	asForwarded(t, p.OnRequestBody(context.Background(), retryRC, nil)) // 1st use: forwarded

	secondTry := asImmediate(t, p.OnRequestBody(context.Background(), retryRC, nil)) // token already consumed
	if secondTry.StatusCode != 403 {
		t.Fatalf("expected a re-used token to require approval again, got %d", secondTry.StatusCode)
	}
}

func TestFullFlow_DeniedBlocksPermanently(t *testing.T) {
	p := mustPolicy(t, nil)
	args := map[string]interface{}{"amount": 99999}
	call := reqCtx(nil, toolBody(t, "issue_refund", args))
	pendingIR := asImmediate(t, p.OnRequestBody(context.Background(), call, nil))
	id := approvalIDFrom(t, pendingIR)

	decisionRC := reqCtx(map[string][]string{"x-approver-secret": {testSecret}}, decisionBody(t, id, "deny", "bob", "too large"))
	decIR := asImmediate(t, p.OnRequestBody(context.Background(), decisionRC, nil))
	if decIR.StatusCode != 200 {
		t.Fatalf("recording a denial should still 200, got %d", decIR.StatusCode)
	}

	retryRC := reqCtx(map[string][]string{"x-approval-token": {id}}, toolBody(t, "issue_refund", args))
	deniedIR := asImmediate(t, p.OnRequestBody(context.Background(), retryRC, nil))
	if deniedIR.StatusCode != 403 {
		t.Fatalf("expected 403 for a denied approval, got %d", deniedIR.StatusCode)
	}
	var parsed map[string]interface{}
	json.Unmarshal(deniedIR.Body, &parsed)
	msg := parsed["message"].(map[string]interface{})
	if msg["action"] != "APPROVAL_DENIED" {
		t.Fatalf("expected APPROVAL_DENIED action, got %v", msg["action"])
	}
}

func TestApprovalScopedToExactArgs_MismatchReprompts(t *testing.T) {
	p := mustPolicy(t, nil)
	approvedArgs := map[string]interface{}{"amount": 10}
	call := reqCtx(nil, toolBody(t, "issue_refund", approvedArgs))
	pendingIR := asImmediate(t, p.OnRequestBody(context.Background(), call, nil))
	id := approvalIDFrom(t, pendingIR)

	decisionRC := reqCtx(map[string][]string{"x-approver-secret": {testSecret}}, decisionBody(t, id, "approve", "alice", ""))
	p.OnRequestBody(context.Background(), decisionRC, nil)

	// Same token, but different arguments than what was actually approved.
	differentArgs := map[string]interface{}{"amount": 99999}
	retryRC := reqCtx(map[string][]string{"x-approval-token": {id}}, toolBody(t, "issue_refund", differentArgs))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), retryRC, nil))
	if ir.StatusCode != 403 {
		t.Fatalf("an approval must not cover a call with different arguments, got %d", ir.StatusCode)
	}
	var parsed map[string]interface{}
	json.Unmarshal(ir.Body, &parsed)
	msg := parsed["message"].(map[string]interface{})
	if msg["action"] != "PENDING_APPROVAL" {
		t.Fatalf("mismatched args should re-prompt as a fresh pending approval, got %v", msg["action"])
	}
}

// ─── approver secret enforcement ─────────────────────────────────────────────

func TestDecision_WrongSecretRejected(t *testing.T) {
	p := mustPolicy(t, nil)
	call := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"amount": 1}))
	pendingIR := asImmediate(t, p.OnRequestBody(context.Background(), call, nil))
	id := approvalIDFrom(t, pendingIR)

	decisionRC := reqCtx(map[string][]string{"x-approver-secret": {"totally-wrong-secret-value"}}, decisionBody(t, id, "approve", "eve", ""))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), decisionRC, nil))
	if ir.StatusCode != 403 {
		t.Fatalf("expected 403 for a wrong approver secret, got %d", ir.StatusCode)
	}
}

func TestDecision_MissingSecretRejected(t *testing.T) {
	p := mustPolicy(t, nil)
	call := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"amount": 1}))
	pendingIR := asImmediate(t, p.OnRequestBody(context.Background(), call, nil))
	id := approvalIDFrom(t, pendingIR)

	decisionRC := reqCtx(nil, decisionBody(t, id, "approve", "eve", ""))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), decisionRC, nil))
	if ir.StatusCode != 403 {
		t.Fatalf("expected 403 when no approver secret header is sent, got %d", ir.StatusCode)
	}
}

func TestDecision_OriginalAgentCannotSelfApprove(t *testing.T) {
	// The original caller only ever learns the approvalId, never the
	// approverSecret - simulate it trying to self-approve anyway.
	p := mustPolicy(t, nil)
	call := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"amount": 1}))
	pendingIR := asImmediate(t, p.OnRequestBody(context.Background(), call, nil))
	id := approvalIDFrom(t, pendingIR)

	fakeDecisionRC := reqCtx(map[string][]string{"x-approver-secret": {id}}, decisionBody(t, id, "approve", "attacker", ""))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), fakeDecisionRC, nil))
	if ir.StatusCode != 403 {
		t.Fatalf("approvalId must never itself satisfy the approver secret check, got %d", ir.StatusCode)
	}
}

func TestDecision_InvalidPayloadShape(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx(map[string][]string{"x-approver-secret": {testSecret}}, decisionBody(t, "some-id", "maybe", "alice", ""))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	if ir.StatusCode != 400 {
		t.Fatalf("expected 400 for an invalid decision value, got %d", ir.StatusCode)
	}
}

func TestDecision_UnknownApprovalId(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx(map[string][]string{"x-approver-secret": {testSecret}}, decisionBody(t, "nonexistent-id", "approve", "alice", ""))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	if ir.StatusCode != 200 {
		t.Fatalf("recording a decision for an unknown id should still 200 (no enumeration signal), got %d", ir.StatusCode)
	}
}

// ─── expiry ───────────────────────────────────────────────────────────────────

func TestExpiredApproval_RepromptsInsteadOfForwarding(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"expirySeconds": 30.0})
	// Shrink the just-created record's expiry directly to simulate elapsed time
	// without sleeping 30s in a unit test.
	call := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"amount": 1}))
	pendingIR := asImmediate(t, p.OnRequestBody(context.Background(), call, nil))
	id := approvalIDFrom(t, pendingIR)

	decisionRC := reqCtx(map[string][]string{"x-approver-secret": {testSecret}}, decisionBody(t, id, "approve", "alice", ""))
	p.OnRequestBody(context.Background(), decisionRC, nil)

	p.mu.Lock()
	p.pending[id].expiresAt = time.Now().Add(-time.Second)
	p.mu.Unlock()

	retryRC := reqCtx(map[string][]string{"x-approval-token": {id}}, toolBody(t, "issue_refund", map[string]interface{}{"amount": 1}))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), retryRC, nil))
	if ir.StatusCode != 403 {
		t.Fatalf("expired approval should require a fresh request, got %d", ir.StatusCode)
	}
	var parsed map[string]interface{}
	json.Unmarshal(ir.Body, &parsed)
	msg := parsed["message"].(map[string]interface{})
	if msg["action"] != "PENDING_APPROVAL" {
		t.Fatalf("expired approval should re-mint a pending approval, got %v", msg["action"])
	}
}

// ─── notify webhook (best-effort) ────────────────────────────────────────────

func TestNotify_PostsPayloadAndDoesNotBlockOnFailure(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["approvalId"] == nil || body["tool"] != "issue_refund" {
			t.Errorf("unexpected notify payload: %#v", body)
		}
		if _, hasArgs := body["arguments"]; hasArgs {
			t.Errorf("arguments should not be included by default: %#v", body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := mustPolicy(t, map[string]interface{}{"notifyUrl": srv.URL})
	rc := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"amount": 1}))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	if ir.StatusCode != 403 {
		t.Fatalf("expected 403 pending even with notify configured, got %d", ir.StatusCode)
	}

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&received) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&received) == 0 {
		t.Fatal("expected the notify webhook to have been called")
	}
}

func TestNotify_UnreachableWebhookStillReturnsPending(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"notifyUrl": "http://127.0.0.1:1/unreachable"})
	rc := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"amount": 1}))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	if ir.StatusCode != 403 {
		t.Fatalf("an unreachable notify webhook must not block the pending response, got %d", ir.StatusCode)
	}
}

func TestIncludeArguments_AddsArgsToNotifyPayload(t *testing.T) {
	var gotArgs int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["arguments"]; ok {
			atomic.StoreInt32(&gotArgs, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := mustPolicy(t, map[string]interface{}{"notifyUrl": srv.URL, "includeArguments": true})
	rc := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"amount": 1}))
	p.OnRequestBody(context.Background(), rc, nil)

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&gotArgs) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&gotArgs) == 0 {
		t.Fatal("expected arguments in the notify payload when includeArguments is true")
	}
}

// ─── eviction bound ──────────────────────────────────────────────────────────

func TestEviction_BoundsPendingMap(t *testing.T) {
	p := mustPolicy(t, nil)
	for i := 0; i < maxTrackedApprovals+50; i++ {
		rc := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"i": i}))
		p.OnRequestBody(context.Background(), rc, nil)
	}
	p.mu.Lock()
	n := len(p.pending)
	p.mu.Unlock()
	if n > maxTrackedApprovals {
		t.Fatalf("pending map grew past the cap: %d > %d", n, maxTrackedApprovals)
	}
}

// ─── concurrency ─────────────────────────────────────────────────────────────

func TestConcurrentRequests_NoRace(t *testing.T) {
	p := mustPolicy(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rc := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"i": fmt.Sprintf("%d", i)}))
			p.OnRequestBody(context.Background(), rc, nil)
		}(i)
	}
	wg.Wait()
}

// ─── malformed body ───────────────────────────────────────────────────────────

func TestNonJSONBody_Passthrough(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx(nil, []byte("not json"))
	asForwarded(t, p.OnRequestBody(context.Background(), rc, nil))
}
