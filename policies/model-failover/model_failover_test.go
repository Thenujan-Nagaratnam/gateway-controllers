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

package modelfailover

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// twoGroupParams builds a valid params map with two fully independent target groups: gpt-4o
// (with one fallback, gpt-4o-mini) and claude-3-5-sonnet (with one fallback, claude-3-haiku),
// on entirely different upstreamDefinitions — the shared fixture most tests below start from.
func twoGroupParams() map[string]interface{} {
	return map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o", "upstreamDefinition": "primary",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o-mini", "upstreamDefinition": "fallback-1"},
				},
			},
			map[string]interface{}{
				"model": "claude-3-5-sonnet", "upstreamDefinition": "anthropic-primary",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "claude-3-haiku", "upstreamDefinition": "anthropic-fallback-1"},
				},
			},
		},
		"statusCodes": []interface{}{500, 502, 503},
	}
}

func twoGroupPolicy() *Policy {
	return &Policy{
		routeName: "POST|/chat/completions|main.local",
		targets: []targetGroup{
			{
				model: "gpt-4o", upstreamDefinition: "primary",
				fallbacks: []fallbackTarget{{model: "gpt-4o-mini", upstreamDefinition: "fallback-1"}},
			},
			{
				model: "claude-3-5-sonnet", upstreamDefinition: "anthropic-primary",
				fallbacks: []fallbackTarget{{model: "claude-3-haiku", upstreamDefinition: "anthropic-fallback-1"}},
			},
		},
		targetByModel: map[string]int{"gpt-4o": 0, "claude-3-5-sonnet": 1},
		statusCodes:   map[int]struct{}{500: {}},
		suspend:       newMemorySuspendStore(),
	}
}

func TestGetPolicy_ValidConfig(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, twoGroupParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mfp, ok := p.(*Policy)
	if !ok {
		t.Fatalf("expected *Policy, got %T", p)
	}
	if len(mfp.targets) != 2 || mfp.targets[0].model != "gpt-4o" || mfp.targets[1].model != "claude-3-5-sonnet" {
		t.Errorf("unexpected targets: %#v", mfp.targets)
	}
	if len(mfp.targets[0].fallbacks) != 1 || mfp.targets[0].fallbacks[0].model != "gpt-4o-mini" {
		t.Errorf("unexpected targets[0].fallbacks: %#v", mfp.targets[0].fallbacks)
	}
	if _, ok := mfp.statusCodes[500]; !ok {
		t.Error("expected 500 in statusCodes")
	}
	if mfp.targetByModel["gpt-4o"] != 0 || mfp.targetByModel["claude-3-5-sonnet"] != 1 {
		t.Errorf("unexpected targetByModel: %#v", mfp.targetByModel)
	}
}

func TestGetPolicy_StoresRouteNameForSyntheticAggregateUpstreamNames(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{RouteName: "POST|/mf/chat/completions|main.local"}, twoGroupParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mfp := p.(*Policy)
	if mfp.routeName != "POST|/mf/chat/completions|main.local" {
		t.Errorf("expected route name to be retained, got %q", mfp.routeName)
	}
}

func TestGetPolicy_TargetWithNoFallbacksIsLegal(t *testing.T) {
	params := map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o", "upstreamDefinition": "primary"}},
		"statusCodes": []interface{}{500},
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mfp := p.(*Policy)
	if len(mfp.targets) != 1 || len(mfp.targets[0].fallbacks) != 0 {
		t.Errorf("expected one target with zero fallbacks, got: %#v", mfp.targets)
	}
}

func TestGetPolicy_TargetUpstreamDefinitionIsOptional(t *testing.T) {
	params := map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o"}}, // upstreamDefinition omitted - defaults to main
		"statusCodes": []interface{}{500},
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("expected no error when a target omits upstreamDefinition (defaults to main), got: %v", err)
	}
	mfp, ok := p.(*Policy)
	if !ok {
		t.Fatalf("expected *Policy, got %T", p)
	}
	if mfp.targets[0].upstreamDefinition != "" {
		t.Errorf("expected empty upstreamDefinition (main) to be preserved as-is, got %q", mfp.targets[0].upstreamDefinition)
	}
}

func TestGetPolicy_RejectsDuplicateTargetModel(t *testing.T) {
	params := map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "gpt-4o", "upstreamDefinition": "primary"},
			map[string]interface{}{"model": "gpt-4o", "upstreamDefinition": "fallback-1"},
		},
		"statusCodes": []interface{}{500},
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Error("expected an error for two targets declaring the same dispatch model name")
	}
}

func TestOnRequestBody_UnmatchedModelPassesThroughUntouched(t *testing.T) {
	p := twoGroupPolicy()
	rctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Body:          &policy.Body{Content: []byte(`{"model":"llama-3-70b","messages":[]}`), Present: true},
	}

	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.UpstreamName != nil {
		t.Errorf("expected no UpstreamName override for an unmatched model, got %q", *mods.UpstreamName)
	}
	if mods.Body != nil {
		t.Errorf("expected no body mutation at all for an unmatched model — send as-is — got %s", mods.Body)
	}
	if rctx.SharedContext.Metadata != nil {
		t.Error("expected no group-selection metadata stashed when nothing matched")
	}
}

func TestOnRequestBody_NoSuspendUsesGroupsOwnPrimary(t *testing.T) {
	p := twoGroupPolicy()
	rctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Body:          &policy.Body{Content: []byte(`{"model":"gpt-4o","messages":[]}`), Present: true},
	}

	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.UpstreamName == nil || *mods.UpstreamName != policy.RetrySourceUpstreamName(p.routeName, "gpt-4o") {
		t.Fatalf("expected UpstreamName to point at the gpt-4o group's own aggregate, got %v", mods.UpstreamName)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(mods.Body, &decoded); err != nil {
		t.Fatalf("mutated body is not valid JSON: %v", err)
	}
	if decoded["model"] != "gpt-4o" {
		t.Errorf("expected model rewritten to the primary target's name, got %v", decoded["model"])
	}
	if rctx.SharedContext.Metadata[metaGroupModelKey] != "gpt-4o" {
		t.Errorf("expected group-model metadata stashed as 'gpt-4o', got %v", rctx.SharedContext.Metadata[metaGroupModelKey])
	}
	if rctx.SharedContext.Metadata[metaStartIndexKey] != 0 {
		t.Errorf("expected start-index metadata stashed as 0, got %v", rctx.SharedContext.Metadata[metaStartIndexKey])
	}
}

// A zero-fallback target group has no aggregate cluster: gateway-controller's translator
// only builds one when len(target.Fallbacks) > 0. Regression test for a confirmed-live bug
// where OnRequestBody unconditionally routed every idx==0 match (including zero-fallback
// groups) through policy.RetrySourceUpstreamName, pointing UpstreamName at a cluster that
// was never created and producing a 503 with no such cluster.
func TestOnRequestBody_ZeroFallbackGroupRoutesDirectlyNotViaAggregate(t *testing.T) {
	p := &Policy{
		routeName:     "POST|/chat/completions|main.local",
		targets:       []targetGroup{{model: "gpt-4o", upstreamDefinition: "primary"}},
		targetByModel: map[string]int{"gpt-4o": 0},
		statusCodes:   map[int]struct{}{500: {}},
		suspend:       newMemorySuspendStore(),
	}
	rctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Body:          &policy.Body{Content: []byte(`{"model":"gpt-4o","messages":[]}`), Present: true},
	}

	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.UpstreamName == nil || *mods.UpstreamName != "primary" {
		t.Fatalf("expected UpstreamName to point directly at the target's own upstreamDefinition %q (no aggregate cluster exists for a zero-fallback group), got %v", "primary", mods.UpstreamName)
	}
}

// A target with an empty upstreamDefinition defaults to the API's own main upstream — the
// same backend used with no model-failover configured at all. UpstreamName must be left
// entirely UNSET (not set to "" or any literal): main isn't registered under the
// UpstreamDefinitionClusterPrefix scheme resolveUpstreamRedirect requires, so the only
// correct way to reach it is to fall through to the kernel's own existing
// default-upstream-cluster mechanism, which only activates when no policy sets UpstreamName.
func TestOnRequestBody_EmptyUpstreamDefinitionLeavesUpstreamNameUnset(t *testing.T) {
	p := &Policy{
		routeName:     "POST|/chat/completions|main.local",
		targets:       []targetGroup{{model: "gpt-4o", upstreamDefinition: ""}}, // main, zero fallbacks
		targetByModel: map[string]int{"gpt-4o": 0},
		statusCodes:   map[int]struct{}{500: {}},
		suspend:       newMemorySuspendStore(),
	}
	rctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Body:          &policy.Body{Content: []byte(`{"model":"gpt-4o","messages":[]}`), Present: true},
	}

	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.UpstreamName != nil {
		t.Fatalf("expected UpstreamName to be left unset (nil) so the kernel's default-upstream-cluster mechanism applies, got %q", *mods.UpstreamName)
	}
	// The model rewrite must still happen even though the destination defaults to main.
	var decoded map[string]interface{}
	if err := json.Unmarshal(mods.Body, &decoded); err != nil {
		t.Fatalf("mutated body is not valid JSON: %v", err)
	}
	if decoded["model"] != "gpt-4o" {
		t.Errorf("expected model unchanged (gpt-4o is both the dispatch key and the model sent), got %v", decoded["model"])
	}
}

// A skip-ahead fallback with an empty upstreamDefinition (main) must ALSO leave UpstreamName
// unset — the same rule applies regardless of whether it's the group's own zero-fallback
// primary or a fallback reached via suspend-driven skip-ahead.
func TestOnRequestBody_SkipAheadToEmptyUpstreamDefinitionLeavesUpstreamNameUnset(t *testing.T) {
	p := &Policy{
		routeName: "POST|/chat/completions|main.local",
		targets: []targetGroup{{
			model: "gpt-4o", upstreamDefinition: "primary",
			fallbacks: []fallbackTarget{{model: "gpt-4o-mini", upstreamDefinition: ""}}, // main
		}},
		targetByModel:   map[string]int{"gpt-4o": 0},
		statusCodes:     map[int]struct{}{500: {}},
		suspendDuration: time.Minute,
		suspend:         newMemorySuspendStore(),
	}
	shared := &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"}
	p.suspend.Suspend(context.Background(), suspendKey(shared, "gpt-4o", 0), time.Minute)

	rctx := &policy.RequestContext{
		SharedContext: shared,
		Body:          &policy.Body{Content: []byte(`{"model":"gpt-4o","messages":[]}`), Present: true},
	}
	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.UpstreamName != nil {
		t.Fatalf("expected UpstreamName to be left unset (nil) for a skip-ahead to main, got %q", *mods.UpstreamName)
	}
}

func TestOnRequestBody_SuspendedPrimarySkipsAhead(t *testing.T) {
	p := twoGroupPolicy()
	p.suspendDuration = time.Minute // firstAvailableIndexInGroup short-circuits to 0 when disabled
	shared := &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"}
	p.suspend.Suspend(context.Background(), suspendKey(shared, "gpt-4o", 0), time.Minute)

	rctx := &policy.RequestContext{
		SharedContext: shared,
		Body:          &policy.Body{Content: []byte(`{"model":"gpt-4o","messages":[]}`), Present: true},
	}

	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods := action.(policy.UpstreamRequestModifications)
	if mods.UpstreamName == nil || *mods.UpstreamName != "fallback-1" {
		t.Fatalf("expected UpstreamName override directly to the fallback's own upstreamDefinition, got %v", mods.UpstreamName)
	}
	var decoded map[string]interface{}
	json.Unmarshal(mods.Body, &decoded)
	if decoded["model"] != "gpt-4o-mini" {
		t.Errorf("expected model rewritten to the skipped-to fallback's name, got %v", decoded["model"])
	}
	if shared.Metadata[metaStartIndexKey] != 1 {
		t.Errorf("expected start-index metadata stashed as 1, got %v", shared.Metadata[metaStartIndexKey])
	}

	// The OTHER group (claude) must be completely unaffected by gpt-4o's suspend.
	rctx2 := &policy.RequestContext{
		SharedContext: &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"},
		Body:          &policy.Body{Content: []byte(`{"model":"claude-3-5-sonnet","messages":[]}`), Present: true},
	}
	action2 := p.OnRequestBody(context.Background(), rctx2, nil)
	mods2 := action2.(policy.UpstreamRequestModifications)
	if mods2.UpstreamName == nil || *mods2.UpstreamName != policy.RetrySourceUpstreamName(p.routeName, "claude-3-5-sonnet") {
		t.Errorf("expected claude's own group to be entirely unaffected by gpt-4o's suspend, got UpstreamName %v", mods2.UpstreamName)
	}
}

// TestRetrySourceUpstreamName_IsRouteScoped is a light regression check that this policy's
// own call site still gets route-scoped, distinct names out of the SDK's canonical formula —
// the formula itself is exercised in full by the SDK's own tests (Task 1), not duplicated here.
func TestRetrySourceUpstreamName_IsRouteScoped(t *testing.T) {
	a := policy.RetrySourceUpstreamName("POST|/chat/completions|main.local", "gpt-4o")
	b := policy.RetrySourceUpstreamName("POST|/embeddings|main.local", "gpt-4o")
	if a == b {
		t.Fatalf("expected same model on different routes to get distinct synthetic upstream names, got %q", a)
	}
	if got := policy.RetrySourceUpstreamName("", "gpt-4o"); got != "__retry_source_target__gpt-4o" {
		t.Fatalf("empty route name should preserve the SDK's documented empty-routeKey formula, got %q", got)
	}
}

func TestOnRequestBody_NullBodyFailsOpenInsteadOfPanicking(t *testing.T) {
	p := twoGroupPolicy()
	rctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Body:          &policy.Body{Content: []byte(`null`), Present: true},
	}
	// encoding/json decodes the literal "null" into a nil map with no error - this must not
	// panic on a nil-map write.
	action := p.OnRequestBody(context.Background(), rctx, nil)
	if _, ok := action.(policy.UpstreamRequestModifications); !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
}

// TestSuspendKey_ScopedPerAPIOperationGroupAndIndex locks in that suspend state never leaks
// across APIs, operations, target groups, or indices within a group.
func TestSuspendKey_ScopedPerAPIOperationGroupAndIndex(t *testing.T) {
	opA := &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"}
	opB := &policy.SharedContext{APIId: "api-1", OperationPath: "/embeddings"}
	opC := &policy.SharedContext{APIId: "api-2", OperationPath: "/chat/completions"}

	keyA0 := suspendKey(opA, "gpt-4o", 0)
	keyA1 := suspendKey(opA, "gpt-4o", 1)
	keyAOther := suspendKey(opA, "claude-3-5-sonnet", 0)
	keyB0 := suspendKey(opB, "gpt-4o", 0)
	keyC0 := suspendKey(opC, "gpt-4o", 0)

	seen := map[string]bool{}
	for _, k := range []string{keyA0, keyA1, keyAOther, keyB0, keyC0} {
		if seen[k] {
			t.Fatalf("suspendKey produced a colliding key %q across distinct inputs", k)
		}
		seen[k] = true
	}

	store := newMemorySuspendStore()
	ctx := context.Background()
	store.Suspend(ctx, keyA0, time.Minute)

	if !store.IsSuspended(ctx, keyA0) {
		t.Error("expected keyA0 to be suspended after Suspend()")
	}
	if store.IsSuspended(ctx, keyA1) {
		t.Error("suspending index 0 must not affect index 1 within the same group")
	}
	if store.IsSuspended(ctx, keyAOther) {
		t.Error("suspending one target group must not affect a different target group on the same operation")
	}
	if store.IsSuspended(ctx, keyB0) {
		t.Error("suspending an operation must not affect a different operation on the same API")
	}
	if store.IsSuspended(ctx, keyC0) {
		t.Error("suspending an API must not affect the same operation path on a different API")
	}
}

// TestOnUpstreamAttemptRequest_RewritesModelPerAttempt locks in the actual kernel
// mechanism (SharedContext is NEVER populated on UpstreamAttemptContext by
// UpstreamExternalProcessorServer — confirmed by reading that server's own Process()
// implementation, and live: a real e2e run silently never rewrote a fallback attempt's body
// until this was fixed): the group is recovered from actx.Body's own BASELINE "model" value
// (which OnRequestBody set to group.model, and Envoy replays unchanged across every attempt —
// see this function's own doc comment), not from any shared context.
func TestOnUpstreamAttemptRequest_RewritesModelPerAttempt(t *testing.T) {
	p := twoGroupPolicy()
	actx := &policy.UpstreamAttemptContext{
		AttemptCount: 2,
		Body:         &policy.Body{Content: []byte(`{"model":"gpt-4o","messages":[]}`), Present: true},
	}
	action := p.OnUpstreamAttemptRequest(context.Background(), actx)
	mods, ok := action.(policy.UpstreamAttemptRequestModifications)
	if !ok || mods.Body == nil {
		t.Fatalf("expected a body mutation, got %#v", action)
	}
	var decoded map[string]interface{}
	json.Unmarshal(mods.Body, &decoded)
	if decoded["model"] != "gpt-4o-mini" {
		t.Errorf("expected attempt 2 to inject the gpt-4o group's fallback name, got %v", decoded["model"])
	}
}

func TestOnUpstreamAttemptRequest_UsesSelectedGroupNotJustAnyGroup(t *testing.T) {
	p := twoGroupPolicy()
	actx := &policy.UpstreamAttemptContext{
		AttemptCount: 2,
		Body:         &policy.Body{Content: []byte(`{"model":"claude-3-5-sonnet","messages":[]}`), Present: true},
	}
	action := p.OnUpstreamAttemptRequest(context.Background(), actx)
	mods := action.(policy.UpstreamAttemptRequestModifications)
	var decoded map[string]interface{}
	json.Unmarshal(mods.Body, &decoded)
	if decoded["model"] != "claude-3-haiku" {
		t.Errorf("expected attempt 2 to inject the CLAUDE group's own fallback name, got %v", decoded["model"])
	}
}

func TestOnUpstreamAttemptRequest_UnknownBaselineModelFailsOpen(t *testing.T) {
	p := twoGroupPolicy()
	actx := &policy.UpstreamAttemptContext{
		AttemptCount: 2,
		Body:         &policy.Body{Content: []byte(`{}`), Present: true}, // no "model" field at all
	}
	action := p.OnUpstreamAttemptRequest(context.Background(), actx)
	mods, ok := action.(policy.UpstreamAttemptRequestModifications)
	if !ok || mods.Body != nil {
		t.Errorf("expected a no-op when the baseline body's model doesn't match any known group, got %#v", action)
	}
}

func TestOnUpstreamAttemptRequest_AttemptBeyondChainFailsOpen(t *testing.T) {
	p := twoGroupPolicy()
	actx := &policy.UpstreamAttemptContext{AttemptCount: 5, Body: &policy.Body{Content: []byte(`{"model":"gpt-4o"}`), Present: true}}
	action := p.OnUpstreamAttemptRequest(context.Background(), actx)
	mods, ok := action.(policy.UpstreamAttemptRequestModifications)
	if !ok || mods.Body != nil {
		t.Errorf("expected a no-op (nil Body) when AttemptCount exceeds the selected group's own chain length, got %#v", action)
	}
}

func TestOnUpstreamAttemptRequest_NilBodyFailsOpen(t *testing.T) {
	p := twoGroupPolicy()
	actx := &policy.UpstreamAttemptContext{AttemptCount: 1, Body: nil} // cluster wasn't body-buffered for some reason
	action := p.OnUpstreamAttemptRequest(context.Background(), actx)
	mods, ok := action.(policy.UpstreamAttemptRequestModifications)
	if !ok || mods.Body != nil {
		t.Errorf("expected a no-op when actx.Body is nil, got %#v", action)
	}
}

func TestOnResponseHeaders_SequentialAttributionSuspendsRangeWhenStartIndexIsZero(t *testing.T) {
	p := twoGroupPolicy()
	p.suspendDuration = time.Minute
	shared := &policy.SharedContext{
		APIId: "api-1", OperationPath: "/chat/completions",
		Metadata: map[string]interface{}{metaGroupModelKey: "gpt-4o", metaStartIndexKey: 0},
	}
	rhctx := &policy.ResponseHeaderContext{
		SharedContext:   shared,
		ResponseHeaders: policy.NewHeaders(map[string][]string{"x-envoy-attempt-count": {"2"}}),
	}

	p.OnResponseHeaders(context.Background(), rhctx, nil)

	if !p.suspend.IsSuspended(context.Background(), suspendKey(shared, "gpt-4o", 0)) {
		t.Error("expected index 0 to be suspended after a final attempt count of 2 (it must have failed to trigger attempt 2)")
	}
	if p.suspend.IsSuspended(context.Background(), suspendKey(shared, "gpt-4o", 1)) {
		t.Error("index 1 (the one that actually responded) must not be marked suspended")
	}
}

// TestOnResponseHeaders_SkipAheadAttributionSuspendsOnlyTheRedirectedIndex is the regression
// test for the misattribution bug a review caught: when OnRequestBody already skipped ahead
// (startIndex != 0), every attempt this request made was against that ONE index's own single
// upstream — never a sequential walk from 0 — so a final attempt count > 1 must suspend only
// that index, never re-suspend index 0 (which this request never even touched).
func TestOnResponseHeaders_SkipAheadAttributionSuspendsOnlyTheRedirectedIndex(t *testing.T) {
	p := twoGroupPolicy()
	p.suspendDuration = time.Minute
	shared := &policy.SharedContext{
		APIId: "api-1", OperationPath: "/chat/completions",
		// This request started at index 1 (skip-ahead) - see OnRequestBody's own stash.
		Metadata: map[string]interface{}{metaGroupModelKey: "gpt-4o", metaStartIndexKey: 1},
	}
	rhctx := &policy.ResponseHeaderContext{
		SharedContext:   shared,
		ResponseHeaders: policy.NewHeaders(map[string][]string{"x-envoy-attempt-count": {"2"}}),
	}

	p.OnResponseHeaders(context.Background(), rhctx, nil)

	if p.suspend.IsSuspended(context.Background(), suspendKey(shared, "gpt-4o", 0)) {
		t.Error("index 0 was never even attempted this request (it was already suspended, hence the skip-ahead) - must not be re-suspended")
	}
	if !p.suspend.IsSuspended(context.Background(), suspendKey(shared, "gpt-4o", 1)) {
		t.Error("expected index 1 (the redirected-to target, whose own retry also failed) to be suspended")
	}
}

func TestOnResponseHeaders_SkipAheadSuccessSuspendsNothing(t *testing.T) {
	p := twoGroupPolicy()
	p.suspendDuration = time.Minute
	shared := &policy.SharedContext{
		APIId: "api-1", OperationPath: "/chat/completions",
		Metadata: map[string]interface{}{metaGroupModelKey: "gpt-4o", metaStartIndexKey: 1},
	}
	rhctx := &policy.ResponseHeaderContext{
		SharedContext:   shared,
		ResponseHeaders: policy.NewHeaders(map[string][]string{"x-envoy-attempt-count": {"1"}}),
	}

	p.OnResponseHeaders(context.Background(), rhctx, nil)

	if p.suspend.IsSuspended(context.Background(), suspendKey(shared, "gpt-4o", 1)) {
		t.Error("the skip-ahead target succeeding on its first try must not be suspended")
	}
}

func TestOnResponseHeaders_NoGroupSelectedIsNoOp(t *testing.T) {
	p := twoGroupPolicy()
	p.suspendDuration = time.Minute
	shared := &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"} // no metadata - unmatched passthrough
	rhctx := &policy.ResponseHeaderContext{
		SharedContext:   shared,
		ResponseHeaders: policy.NewHeaders(map[string][]string{"x-envoy-attempt-count": {"2"}}),
	}

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected DownstreamResponseHeaderModifications, got %T", action)
	}
	if p.suspend.IsSuspended(context.Background(), suspendKey(shared, "gpt-4o", 0)) {
		t.Error("nothing should be suspended when no group was ever selected for this request")
	}
}

func TestOnResponseHeaders_AttemptCountOneSuspendsNothing(t *testing.T) {
	p := twoGroupPolicy()
	p.suspendDuration = time.Minute
	shared := &policy.SharedContext{
		APIId: "api-1", OperationPath: "/chat/completions",
		Metadata: map[string]interface{}{metaGroupModelKey: "gpt-4o", metaStartIndexKey: 0},
	}
	rhctx := &policy.ResponseHeaderContext{SharedContext: shared, ResponseHeaders: policy.NewHeaders(map[string][]string{"x-envoy-attempt-count": {"1"}})}

	p.OnResponseHeaders(context.Background(), rhctx, nil)

	if p.suspend.IsSuspended(context.Background(), suspendKey(shared, "gpt-4o", 0)) {
		t.Error("a first-attempt success must not suspend the primary")
	}
}

func TestOnResponseHeaders_SuspendDisabledIsNoOp(t *testing.T) {
	p := twoGroupPolicy()
	p.suspendDuration = 0
	shared := &policy.SharedContext{
		APIId: "api-1", OperationPath: "/chat/completions",
		Metadata: map[string]interface{}{metaGroupModelKey: "gpt-4o", metaStartIndexKey: 0},
	}
	rhctx := &policy.ResponseHeaderContext{SharedContext: shared, ResponseHeaders: policy.NewHeaders(map[string][]string{"x-envoy-attempt-count": {"2"}})}

	p.OnResponseHeaders(context.Background(), rhctx, nil)

	if p.suspend.IsSuspended(context.Background(), suspendKey(shared, "gpt-4o", 0)) {
		t.Error("suspendDuration == 0 must disable suspend tracking entirely, even with a multi-attempt response")
	}
}
