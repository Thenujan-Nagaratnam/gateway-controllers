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

func TestGetPolicy_ValidConfig(t *testing.T) {
	params := map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"name": "gpt-4o", "upstreamDefinition": "primary"},
			map[string]interface{}{"name": "gpt-4o-mini", "upstreamDefinition": "fallback-1"},
		},
		"statusCodes": []interface{}{500, 502, 503},
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mfp, ok := p.(*Policy)
	if !ok {
		t.Fatalf("expected *Policy, got %T", p)
	}
	if len(mfp.models) != 2 || mfp.models[0].name != "gpt-4o" {
		t.Errorf("unexpected models: %#v", mfp.models)
	}
	if _, ok := mfp.statusCodes[500]; !ok {
		t.Error("expected 500 in statusCodes")
	}
}

func TestGetPolicy_RejectsSingleModel(t *testing.T) {
	params := map[string]interface{}{
		"models":      []interface{}{map[string]interface{}{"name": "gpt-4o", "upstreamDefinition": "primary"}},
		"statusCodes": []interface{}{500},
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Error("expected an error for a single-target models list")
	}
}

func TestOnRequestBody_NoSuspendUsesModelsZero(t *testing.T) {
	p := &Policy{
		models:      []modelTarget{{name: "gpt-4o", upstreamDefinition: "primary"}, {name: "gpt-4o-mini", upstreamDefinition: "fallback-1"}},
		statusCodes: map[int]struct{}{500: {}},
		suspend:     newMemorySuspendStore(), // add this small constructor in the same package — see Step 3
	}
	rctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Body:          &policy.Body{Content: []byte(`{"model":"whatever-the-client-sent","messages":[]}`), Present: true},
	}

	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.UpstreamName != nil {
		t.Errorf("expected no UpstreamName override when nothing is suspended, got %q", *mods.UpstreamName)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(mods.Body, &decoded); err != nil {
		t.Fatalf("mutated body is not valid JSON: %v", err)
	}
	if decoded["model"] != "gpt-4o" {
		t.Errorf("expected model rewritten to the primary target's name, got %v", decoded["model"])
	}
}

func TestOnRequestBody_SuspendedPrimarySkipsAhead(t *testing.T) {
	p := &Policy{
		models:      []modelTarget{{name: "gpt-4o", upstreamDefinition: "primary"}, {name: "gpt-4o-mini", upstreamDefinition: "fallback-1"}},
		statusCodes: map[int]struct{}{500: {}},
		// suspendDuration must be non-zero here — firstAvailableTarget
		// intentionally short-circuits to index 0 (fail toward primary) when
		// suspend tracking is disabled (suspendDuration == 0). This test's
		// whole point is exercising the enabled skip-ahead path.
		suspendDuration: time.Minute,
		suspend:         newMemorySuspendStore(),
	}
	p.suspend.Suspend(context.Background(), suspendKey(&policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"}, 0), time.Minute)

	rctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"},
		Body:          &policy.Body{Content: []byte(`{"model":"x","messages":[]}`), Present: true},
	}

	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods := action.(policy.UpstreamRequestModifications)
	if mods.UpstreamName == nil || *mods.UpstreamName != "fallback-1" {
		t.Fatalf("expected UpstreamName override to the first non-suspended target, got %v", mods.UpstreamName)
	}
	var decoded map[string]interface{}
	json.Unmarshal(mods.Body, &decoded)
	if decoded["model"] != "gpt-4o-mini" {
		t.Errorf("expected model rewritten to the skipped-to target's name, got %v", decoded["model"])
	}
}

// TestSuspendKey_ScopedPerAPIOperationAndIndex locks in that suspend state
// never leaks across APIs, operations, or target indices: suspending target
// 0 on one operation must not affect target 0 on a different operation, nor
// target 1 on the same operation.
func TestSuspendKey_ScopedPerAPIOperationAndIndex(t *testing.T) {
	opA := &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"}
	opB := &policy.SharedContext{APIId: "api-1", OperationPath: "/embeddings"}
	opC := &policy.SharedContext{APIId: "api-2", OperationPath: "/chat/completions"}

	keyA0 := suspendKey(opA, 0)
	keyA1 := suspendKey(opA, 1)
	keyB0 := suspendKey(opB, 0)
	keyC0 := suspendKey(opC, 0)

	seen := map[string]bool{}
	for _, k := range []string{keyA0, keyA1, keyB0, keyC0} {
		if seen[k] {
			t.Fatalf("suspendKey produced a colliding key %q across distinct (api, operation, index) inputs", k)
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
		t.Error("suspending target 0 must not affect target 1 on the same operation")
	}
	if store.IsSuspended(ctx, keyB0) {
		t.Error("suspending an operation must not affect a different operation on the same API")
	}
	if store.IsSuspended(ctx, keyC0) {
		t.Error("suspending an API must not affect the same operation path on a different API")
	}
}

func TestOnUpstreamAttemptRequestHeaders_RewritesModelPerAttempt(t *testing.T) {
	p := &Policy{models: []modelTarget{{name: "gpt-4o", upstreamDefinition: "primary"}, {name: "gpt-4o-mini", upstreamDefinition: "fallback-1"}}}

	actx := &policy.UpstreamAttemptContext{
		AttemptCount: 2,
		Body:         &policy.Body{Content: []byte(`{"model":"gpt-4o","messages":[]}`), Present: true},
	}
	action := p.OnUpstreamAttemptRequestHeaders(context.Background(), actx)
	mods, ok := action.(policy.UpstreamAttemptHeaderModifications)
	if !ok || mods.Body == nil {
		t.Fatalf("expected a body mutation, got %#v", action)
	}
	var decoded map[string]interface{}
	json.Unmarshal(mods.Body, &decoded)
	if decoded["model"] != "gpt-4o-mini" {
		t.Errorf("expected attempt 2 to inject models[1].name, got %v", decoded["model"])
	}
}

func TestOnUpstreamAttemptRequestHeaders_AttemptBeyondModelsListFailsOpen(t *testing.T) {
	p := &Policy{models: []modelTarget{{name: "a", upstreamDefinition: "x"}, {name: "b", upstreamDefinition: "y"}}}
	actx := &policy.UpstreamAttemptContext{AttemptCount: 5, Body: &policy.Body{Content: []byte(`{}`), Present: true}}
	action := p.OnUpstreamAttemptRequestHeaders(context.Background(), actx)
	mods, ok := action.(policy.UpstreamAttemptHeaderModifications)
	if !ok || mods.Body != nil {
		t.Errorf("expected a no-op (nil Body) when AttemptCount exceeds len(models), got %#v", action)
	}
}

func TestOnUpstreamAttemptRequestHeaders_NilBodyFailsOpen(t *testing.T) {
	p := &Policy{models: []modelTarget{{name: "a", upstreamDefinition: "x"}, {name: "b", upstreamDefinition: "y"}}}
	actx := &policy.UpstreamAttemptContext{AttemptCount: 1, Body: nil} // cluster wasn't body-buffered for some reason
	action := p.OnUpstreamAttemptRequestHeaders(context.Background(), actx)
	mods, ok := action.(policy.UpstreamAttemptHeaderModifications)
	if !ok || mods.Body != nil {
		t.Errorf("expected a no-op when actx.Body is nil, got %#v", action)
	}
}

func TestOnResponseHeaders_FinalAttemptCountTwoSuspendsTargetZero(t *testing.T) {
	store := newMemorySuspendStore()
	p := &Policy{
		models:          []modelTarget{{name: "a", upstreamDefinition: "primary"}, {name: "b", upstreamDefinition: "fallback-1"}},
		suspend:         store,
		suspendDuration: time.Minute,
	}
	shared := &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"}
	rhctx := &policy.ResponseHeaderContext{
		SharedContext:   shared,
		ResponseHeaders: policy.NewHeaders(map[string][]string{"x-envoy-attempt-count": {"2"}}),
	}

	p.OnResponseHeaders(context.Background(), rhctx, nil)

	if !store.IsSuspended(context.Background(), suspendKey(shared, 0)) {
		t.Error("expected target index 0 to be suspended after a final attempt count of 2 (it must have failed to trigger attempt 2)")
	}
	if store.IsSuspended(context.Background(), suspendKey(shared, 1)) {
		t.Error("target index 1 (the one that actually responded) must not be marked suspended")
	}
}

func TestOnResponseHeaders_AttemptCountOneSuspendsNothing(t *testing.T) {
	store := newMemorySuspendStore()
	p := &Policy{models: []modelTarget{{name: "a", upstreamDefinition: "primary"}, {name: "b", upstreamDefinition: "fallback-1"}}, suspend: store, suspendDuration: time.Minute}
	shared := &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"}
	rhctx := &policy.ResponseHeaderContext{SharedContext: shared, ResponseHeaders: policy.NewHeaders(map[string][]string{"x-envoy-attempt-count": {"1"}})}

	p.OnResponseHeaders(context.Background(), rhctx, nil)

	if store.IsSuspended(context.Background(), suspendKey(shared, 0)) {
		t.Error("a first-attempt success must not suspend the primary")
	}
}

func TestOnResponseHeaders_SuspendDisabledIsNoOp(t *testing.T) {
	store := newMemorySuspendStore()
	p := &Policy{models: []modelTarget{{name: "a", upstreamDefinition: "primary"}, {name: "b", upstreamDefinition: "fallback-1"}}, suspend: store, suspendDuration: 0}
	shared := &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"}
	rhctx := &policy.ResponseHeaderContext{SharedContext: shared, ResponseHeaders: policy.NewHeaders(map[string][]string{"x-envoy-attempt-count": {"2"}})}

	p.OnResponseHeaders(context.Background(), rhctx, nil)

	if store.IsSuspended(context.Background(), suspendKey(shared, 0)) {
		t.Error("suspendDuration == 0 must disable suspend tracking entirely, even with a multi-attempt response")
	}
}
