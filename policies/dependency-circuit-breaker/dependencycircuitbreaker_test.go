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

package dependencycircuitbreaker

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func mustPolicy(t *testing.T, extra map[string]interface{}) *DependencyCircuitBreakerPolicy {
	t.Helper()
	params := map[string]interface{}{}
	for k, v := range extra {
		params[k] = v
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*DependencyCircuitBreakerPolicy)
}

func toolCallBody(t *testing.T, name string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call",
		"params": map[string]interface{}{"name": name, "arguments": map[string]interface{}{}},
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

func respCtxFrom(rc *policy.RequestContext, status int, body []byte) *policy.ResponseContext {
	return &policy.ResponseContext{
		SharedContext:  rc.SharedContext,
		ResponseStatus: status,
		ResponseBody:   &policy.Body{Content: body, Present: true, EndOfStream: true},
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

var okBody, _ = json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "result": map[string]interface{}{"content": "ok"}})
var errBody, _ = json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "error": map[string]interface{}{"code": -32000, "message": "boom"}})

// callSuccess/callFailure run one request+response cycle through the policy,
// exercising OnRequestBody then OnResponseBody as the gateway would.
func callThrough(t *testing.T, p *DependencyCircuitBreakerPolicy, tool string, respStatus int, respBody []byte) (policy.RequestAction, policy.ResponseAction) {
	t.Helper()
	rc := reqCtx(toolCallBody(t, tool))
	ra := p.OnRequestBody(context.Background(), rc, nil)
	if _, blocked := ra.(policy.ImmediateResponse); blocked {
		return ra, nil
	}
	sa := p.OnResponseBody(context.Background(), respCtxFrom(rc, respStatus, respBody), nil)
	return ra, sa
}

// ─── GetPolicy validation ────────────────────────────────────────────────────

func TestGetPolicy_Defaults(t *testing.T) {
	p := mustPolicy(t, nil)
	if p.cfg.failureThreshold != 5 || p.cfg.openDurationSeconds != 30 || p.cfg.halfOpenMaxTrials != 1 {
		t.Fatalf("unexpected defaults: %+v", p.cfg)
	}
}

func TestGetPolicy_InvalidFailureThreshold(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"failureThreshold": 0.0}); err == nil {
		t.Fatal("expected error for failureThreshold < 1")
	}
}

func TestGetPolicy_InvalidOpenDuration(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"openDurationSeconds": 0.0}); err == nil {
		t.Fatal("expected error for openDurationSeconds <= 0")
	}
}

func TestGetPolicy_InvalidErrorStatusCodes(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"errorStatusCodes": "not-an-array"}); err == nil {
		t.Fatal("expected error for non-array errorStatusCodes")
	}
}

// ─── non-tool-call passthrough ───────────────────────────────────────────────

func TestNonToolCall_PassesThrough(t *testing.T) {
	p := mustPolicy(t, nil)
	body, _ := json.Marshal(map[string]interface{}{"messages": []map[string]string{{"role": "user", "content": "hi"}}})
	ra := p.OnRequestBody(context.Background(), reqCtx(body), nil)
	asUpstream(t, ra)
	if len(p.circuits) != 0 {
		t.Fatalf("expected no circuit created for a non-tool-call request, got %d", len(p.circuits))
	}
}

// ─── closed state: successes never trip the breaker ─────────────────────────

func TestClosedState_RepeatedSuccessNeverTrips(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 3.0})
	for i := 0; i < 10; i++ {
		ra, sa := callThrough(t, p, "search", 200, okBody)
		asUpstream(t, ra)
		dm := asDownstream(t, sa)
		if dm.HeadersToSet["x-circuit-breaker-state"] != stateClosed {
			t.Fatalf("iteration %d: expected closed, got %+v", i, dm.HeadersToSet)
		}
	}
}

// ─── closed -> open after failureThreshold consecutive failures ─────────────

func TestClosedToOpen_AfterThreshold(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 3.0})
	for i := 0; i < 2; i++ {
		ra, sa := callThrough(t, p, "flaky", 500, nil)
		asUpstream(t, ra)
		dm := asDownstream(t, sa)
		if dm.HeadersToSet["x-circuit-breaker-state"] != stateClosed {
			t.Fatalf("iteration %d: expected still closed before threshold, got %+v", i, dm.HeadersToSet)
		}
	}
	// third consecutive failure trips it
	ra, sa := callThrough(t, p, "flaky", 500, nil)
	asUpstream(t, ra)
	dm := asDownstream(t, sa)
	if dm.HeadersToSet["x-circuit-breaker-state"] != stateOpen {
		t.Fatalf("expected open after threshold failures, got %+v", dm.HeadersToSet)
	}

	// next call is short-circuited - never reaches the backend
	rc := reqCtx(toolCallBody(t, "flaky"))
	ra2 := p.OnRequestBody(context.Background(), rc, nil)
	ir := asImmediate(t, ra2)
	if ir.StatusCode != openStatus {
		t.Fatalf("expected %d, got %d", openStatus, ir.StatusCode)
	}
	if ir.Headers["Retry-After"] == "" {
		t.Fatal("expected a Retry-After header on the short-circuit response")
	}
}

// ─── a success resets the failure counter (doesn't need to be consecutive-only across tools) ───

func TestFailureCounter_ResetsOnSuccess(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 3.0})
	ra, sa := callThrough(t, p, "search", 500, nil)
	asUpstream(t, ra)
	asDownstream(t, sa)
	ra, sa = callThrough(t, p, "search", 500, nil)
	asUpstream(t, ra)
	asDownstream(t, sa)
	// a success in between should reset the counter
	ra, sa = callThrough(t, p, "search", 200, okBody)
	asUpstream(t, ra)
	asDownstream(t, sa)
	// two more failures should NOT trip it (counter was reset)
	for i := 0; i < 2; i++ {
		ra, sa = callThrough(t, p, "search", 500, nil)
		asUpstream(t, ra)
		dm := asDownstream(t, sa)
		if dm.HeadersToSet["x-circuit-breaker-state"] != stateClosed {
			t.Fatalf("expected still closed (counter should have reset), got %+v", dm.HeadersToSet)
		}
	}
}

// ─── independent breakers per tool name ──────────────────────────────────────

func TestBreakersAreIndependentPerTool(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 1.0})
	ra, sa := callThrough(t, p, "toolA", 500, nil)
	asUpstream(t, ra)
	dm := asDownstream(t, sa)
	if dm.HeadersToSet["x-circuit-breaker-state"] != stateOpen {
		t.Fatalf("expected toolA open, got %+v", dm.HeadersToSet)
	}
	// toolB is unaffected
	raB, saB := callThrough(t, p, "toolB", 200, okBody)
	asUpstream(t, raB)
	dmB := asDownstream(t, saB)
	if dmB.HeadersToSet["x-circuit-breaker-state"] != stateClosed {
		t.Fatalf("expected toolB unaffected (closed), got %+v", dmB.HeadersToSet)
	}
}

// ─── half-open: successful trial closes the breaker ─────────────────────────

func TestHalfOpen_SuccessfulTrialCloses(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 1.0, "openDurationSeconds": 0.01})
	ra, sa := callThrough(t, p, "flaky", 500, nil)
	asUpstream(t, ra)
	asDownstream(t, sa)
	// confirm open
	p.mu.Lock()
	if p.circuits["flaky"].status != stateOpen {
		t.Fatalf("expected open before cooldown, got %s", p.circuits["flaky"].status)
	}
	p.mu.Unlock()

	time.Sleep(20 * time.Millisecond) // let openDurationSeconds elapse

	ra2, sa2 := callThrough(t, p, "flaky", 200, okBody)
	asUpstream(t, ra2) // the half-open trial is allowed through, not short-circuited
	dm2 := asDownstream(t, sa2)
	if dm2.HeadersToSet["x-circuit-breaker-state"] != stateClosed {
		t.Fatalf("expected closed after a successful half-open trial, got %+v", dm2.HeadersToSet)
	}
}

// ─── half-open: failed trial reopens the breaker ─────────────────────────────

func TestHalfOpen_FailedTrialReopens(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 1.0, "openDurationSeconds": 0.01})
	ra, sa := callThrough(t, p, "flaky", 500, nil)
	asUpstream(t, ra)
	asDownstream(t, sa)

	time.Sleep(20 * time.Millisecond)

	ra2, sa2 := callThrough(t, p, "flaky", 500, nil)
	asUpstream(t, ra2)
	dm2 := asDownstream(t, sa2)
	if dm2.HeadersToSet["x-circuit-breaker-state"] != stateOpen {
		t.Fatalf("expected re-opened after a failed half-open trial, got %+v", dm2.HeadersToSet)
	}
	if _, hit := dm2.AnalyticsMetadata["isGuardrailHit"]; !hit {
		t.Fatal("expected isGuardrailHit on a half-open trial that reopens the breaker")
	}
}

// ─── half-open: extra calls beyond halfOpenMaxTrials are short-circuited ────

func TestHalfOpen_ExtraCallsShortCircuited(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 1.0, "openDurationSeconds": 0.01, "halfOpenMaxTrials": 1.0})
	ra, sa := callThrough(t, p, "flaky", 500, nil)
	asUpstream(t, ra)
	asDownstream(t, sa)

	time.Sleep(20 * time.Millisecond)

	// first call after cooldown is the trial - held open (no response yet)
	rc := reqCtx(toolCallBody(t, "flaky"))
	raTrial := p.OnRequestBody(context.Background(), rc, nil)
	asUpstream(t, raTrial)

	// a second concurrent call for the same tool must be short-circuited
	rc2 := reqCtx(toolCallBody(t, "flaky"))
	raSecond := p.OnRequestBody(context.Background(), rc2, nil)
	asImmediate(t, raSecond)
}

// ─── errorDetectionJsonPath: JSON-RPC error with HTTP 200 counts as failure ──

func TestErrorDetectionJsonPath_HTTP200WithRPCError(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 1.0})
	ra, sa := callThrough(t, p, "flaky", 200, errBody)
	asUpstream(t, ra)
	dm := asDownstream(t, sa)
	if dm.HeadersToSet["x-circuit-breaker-state"] != stateOpen {
		t.Fatalf("expected open on a 200 response carrying a JSON-RPC error, got %+v", dm.HeadersToSet)
	}
}

func TestErrorDetectionJsonPath_Disabled(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 1.0, "errorDetectionJsonPath": ""})
	ra, sa := callThrough(t, p, "flaky", 200, errBody)
	asUpstream(t, ra)
	dm := asDownstream(t, sa)
	if dm.HeadersToSet["x-circuit-breaker-state"] != stateClosed {
		t.Fatalf("expected closed when body-based error detection is disabled, got %+v", dm.HeadersToSet)
	}
}

// ─── custom errorStatusCodes ──────────────────────────────────────────────────

func TestCustomErrorStatusCodes(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 1.0, "errorStatusCodes": []interface{}{429.0}})
	ra, sa := callThrough(t, p, "flaky", 429, nil)
	asUpstream(t, ra)
	dm := asDownstream(t, sa)
	if dm.HeadersToSet["x-circuit-breaker-state"] != stateOpen {
		t.Fatalf("expected open on a configured custom error status, got %+v", dm.HeadersToSet)
	}
	// 500 is no longer in the (overridden) list, so it must NOT count as a failure
	p2 := mustPolicy(t, map[string]interface{}{"failureThreshold": 1.0, "errorStatusCodes": []interface{}{429.0}, "errorDetectionJsonPath": ""})
	ra2, sa2 := callThrough(t, p2, "flaky2", 500, nil)
	asUpstream(t, ra2)
	dm2 := asDownstream(t, sa2)
	if dm2.HeadersToSet["x-circuit-breaker-state"] != stateClosed {
		t.Fatalf("expected 500 to be ignored when errorStatusCodes doesn't include it, got %+v", dm2.HeadersToSet)
	}
}

// ─── custom toolNameJsonPath ──────────────────────────────────────────────────

func TestCustomToolNameJsonPath(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"toolNameJsonPath": "$.tool", "failureThreshold": 1.0})
	body, _ := json.Marshal(map[string]interface{}{"tool": "search"})
	rc := reqCtx(body)
	ra := p.OnRequestBody(context.Background(), rc, nil)
	asUpstream(t, ra)
	if _, ok := p.circuits["search"]; !ok {
		t.Fatal("expected a circuit created via the custom toolNameJsonPath")
	}
}

// ─── showAssessment adds detail to the short-circuit envelope only when enabled ───

func TestShowAssessment_OnShortCircuit(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"failureThreshold": 1.0, "showAssessment": true})
	ra, sa := callThrough(t, p, "flaky", 500, nil)
	asUpstream(t, ra)
	asDownstream(t, sa)

	rc := reqCtx(toolCallBody(t, "flaky"))
	ir := asImmediate(t, p.OnRequestBody(context.Background(), rc, nil))
	var envelope map[string]interface{}
	if err := json.Unmarshal(ir.Body, &envelope); err != nil {
		t.Fatalf("block body not valid JSON: %v", err)
	}
	message, _ := envelope["message"].(map[string]interface{})
	if _, ok := message["assessments"]; !ok {
		t.Fatal("expected assessments when showAssessment=true")
	}
}

// ─── response for an untracked call (no tool identified) is a no-op ─────────

func TestUntrackedResponse_NoOp(t *testing.T) {
	p := mustPolicy(t, nil)
	respCtx := &policy.ResponseContext{
		SharedContext:  &policy.SharedContext{},
		ResponseStatus: 500,
		ResponseBody:   &policy.Body{Content: nil, Present: false},
	}
	sa := p.OnResponseBody(context.Background(), respCtx, nil)
	dm := asDownstream(t, sa)
	if dm.HeadersToSet != nil {
		t.Fatalf("expected no headers set for an untracked response, got %+v", dm.HeadersToSet)
	}
}

// ─── bounded map: eviction keeps the tracked-tool count within the cap ──────

func TestEviction_BoundsTrackedTools(t *testing.T) {
	p := mustPolicy(t, nil)
	for i := 0; i < maxTrackedTools+50; i++ {
		rc := reqCtx(toolCallBody(t, fmt.Sprintf("tool-%d", i)))
		p.OnRequestBody(context.Background(), rc, nil)
	}
	if len(p.circuits) > maxTrackedTools {
		t.Fatalf("expected at most %d tracked tools, got %d", maxTrackedTools, len(p.circuits))
	}
}
