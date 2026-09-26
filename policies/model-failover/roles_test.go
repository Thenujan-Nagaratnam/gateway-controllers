/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package modelfailover

import (
	"context"
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// pipeline wires a front and a dispatch instance of one chain to a private
// registry, standing in for the two hops Envoy connects.
type pipeline struct {
	front, dispatch *Policy
	plans           *planRegistry
	health          *healthRegistry
	clock           *fakeClock
}

func newPipeline(t *testing.T, mutate func(map[string]interface{})) *pipeline {
	t.Helper()
	clock := newFakeClock()
	plans := newPlanRegistry(clock.now)
	health := newHealthRegistry(clock.now)
	build := func(role Role) *Policy {
		p := baseParams(role)
		p[paramInternalTargetNative] = []interface{}{true, false}
		if mutate != nil {
			mutate(p)
		}
		cfg, err := parseConfig(p)
		if err != nil {
			t.Fatalf("parseConfig(%s): %v", role, err)
		}
		return newPolicy(cfg, plans, health, clock.now)
	}
	return &pipeline{front: build(RoleFront), dispatch: build(RoleDispatch), plans: plans, health: health, clock: clock}
}

// startRequest runs the front request phase and returns the front shared
// context and the plan nonce it forwarded.
func (pl *pipeline) startRequest(t *testing.T, clientHeaders map[string][]string) (*policy.SharedContext, string, policy.UpstreamRequestHeaderModifications) {
	t.Helper()
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	act := pl.front.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{SharedContext: shared, Headers: policy.NewHeaders(clientHeaders)}, nil)
	mods, ok := act.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("front request: expected modifications, got %T", act)
	}
	return shared, mods.HeadersToSet[headerPlan], mods
}

// attempt runs one dispatch-hop request/response and returns the selected
// upstream and the response modifications Envoy would see.
func (pl *pipeline) attempt(t *testing.T, nonce string, status int, respHeaders map[string][]string) (string, policy.ResponseHeaderAction) {
	t.Helper()
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	reqAct := pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: shared,
		Headers:       policy.NewHeaders(map[string][]string{headerPlan: {nonce}, headerChain: {pl.dispatch.cfg.ChainID}}),
	}, nil)
	reqMods, ok := reqAct.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		return "", nil
	}
	respAct := pl.dispatch.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{
		SharedContext:   shared,
		ResponseStatus:  status,
		ResponseHeaders: policy.NewHeaders(respHeaders),
	}, nil)
	return *reqMods.UpstreamName, respAct
}

func respMods(t *testing.T, act policy.ResponseHeaderAction) policy.DownstreamResponseHeaderModifications {
	t.Helper()
	m, ok := act.(policy.DownstreamResponseHeaderModifications)
	if !ok {
		t.Fatalf("expected response modifications, got %T", act)
	}
	return m
}

func TestClassify(t *testing.T) {
	on := FailoverOn{StatusCodes: toSet([]int{429, 503}), ConnectFailure: true, Reset: true, Timeout: true}
	cases := []struct {
		name   string
		on     FailoverOn
		status int
		flags  string
		class  OutcomeClass
		reason string
	}{
		{"2xx success", on, 200, "", OutcomeSuccess, ""},
		{"429 eligible", on, 429, "", OutcomeEligibleFailure, "status_429"},
		{"503 eligible", on, 503, "", OutcomeEligibleFailure, "status_503"},
		{"502 not configured passes through", on, 502, "", OutcomeNonEligible, ""},
		{"504 not configured passes through", on, 504, "", OutcomeNonEligible, ""},
		{"400 non-eligible", on, 400, "", OutcomeNonEligible, ""},
		{"connect failure", on, 503, "UF", OutcomeEligibleFailure, reasonConnectFailure},
		{"retry-exhausted connect", on, 503, "UF,URX", OutcomeEligibleFailure, reasonConnectFailure},
		{"reset", on, 503, "UC", OutcomeEligibleFailure, reasonReset},
		{"upstream timeout", on, 504, "UT", OutcomeEligibleFailure, reasonTimeout},
		{"connect failure disabled", FailoverOn{StatusCodes: on.StatusCodes, Reset: true, Timeout: true}, 503, "UF", OutcomeNonEligible, reasonConnectFailure},
		{"unknown flag falls back to status", on, 503, "NR", OutcomeEligibleFailure, "status_503"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := classify(c.on, c.status, c.flags)
			if o.Class != c.class || o.Reason != c.reason {
				t.Fatalf("classify(%d,%q) = %+v, want %s/%s", c.status, c.flags, o, c.class, c.reason)
			}
		})
	}
}

func TestOrderedFailoverAcrossHops(t *testing.T) {
	pl := newPipeline(t, nil)
	_, nonce, _ := pl.startRequest(t, nil)

	up, act := pl.attempt(t, nonce, 429, nil)
	if up != "failover-t0" {
		t.Fatalf("first attempt must go to t0, got %s", up)
	}
	if got := respMods(t, act).HeadersToSet[headerRetry]; got != "status_429" {
		t.Fatalf("429 must be tagged for retry, got %q", got)
	}

	up, act = pl.attempt(t, nonce, 200, nil)
	if up != "failover-t1" {
		t.Fatalf("second attempt must go to t1, got %s", up)
	}
	if _, tagged := respMods(t, act).HeadersToSet[headerRetry]; tagged {
		t.Fatal("a 2xx must not be tagged")
	}
}

func TestNonEligibleResponseIsNotTagged(t *testing.T) {
	pl := newPipeline(t, func(p map[string]interface{}) {
		p["failoverOn"] = map[string]interface{}{"statusCodes": []interface{}{float64(429)}}
	})
	_, nonce, _ := pl.startRequest(t, nil)
	_, act := pl.attempt(t, nonce, 503, nil)
	m := respMods(t, act)
	if _, tagged := m.HeadersToSet[headerRetry]; tagged {
		t.Fatal("503 must not be tagged when only 429 is configured")
	}
	if len(m.HeadersToRemove) != 1 || m.HeadersToRemove[0] != headerUpstreamFailure {
		t.Fatalf("dispatch must always strip %s, got %v", headerUpstreamFailure, m.HeadersToRemove)
	}
}

func TestTransportFailureFromLocalReplyFlags(t *testing.T) {
	pl := newPipeline(t, nil)
	_, nonce, _ := pl.startRequest(t, nil)
	_, act := pl.attempt(t, nonce, 503, map[string][]string{headerUpstreamFailure: {"UF"}})
	if got := respMods(t, act).HeadersToSet[headerRetry]; got != reasonConnectFailure {
		t.Fatalf("connect failure must be tagged %q, got %q", reasonConnectFailure, got)
	}
}

func TestDispatchSetsRoutingAndHopHeaders(t *testing.T) {
	pl := newPipeline(t, nil)
	_, nonce, _ := pl.startRequest(t, nil)
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	act := pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: shared,
		Headers:       policy.NewHeaders(map[string][]string{headerPlan: {nonce}}),
	}, nil)
	m := act.(policy.UpstreamRequestHeaderModifications)
	if m.HeadersToSet[headerHop] != "s3cret" {
		t.Errorf("dispatch must set the hop secret header")
	}
	if shared.Metadata[selectedProviderKey] != "failover-t0" {
		t.Errorf("selected_provider must name the per-target upstream, got %v", shared.Metadata[selectedProviderKey])
	}
	removed := map[string]bool{}
	for _, h := range m.HeadersToRemove {
		removed[h] = true
	}
	if !removed[headerPlan] {
		t.Errorf("dispatch must strip the plan header before the provider hop: %v", m.HeadersToRemove)
	}
	if removed[headerChain] {
		t.Errorf("dispatch must keep the chain header so the dispatch route re-matches after a path rewrite")
	}
}

func TestDispatchRejectsForgedOrMismatchedPlan(t *testing.T) {
	pl := newPipeline(t, nil)
	for name, nonce := range map[string]string{"forged": "00112233445566778899aabbccddeeff", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			act := pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
				SharedContext: &policy.SharedContext{},
				Headers:       policy.NewHeaders(map[string][]string{headerPlan: {nonce}}),
			}, nil)
			ir, ok := act.(policy.ImmediateResponse)
			if !ok || ir.StatusCode != 500 {
				t.Fatalf("expected immediate 500, got %#v", act)
			}
			if _, tagged := ir.Headers[headerRetry]; tagged {
				t.Fatal("a rejected plan must never be retried")
			}
		})
	}
}

func TestDispatchPastEndOfPlanMarksExhausted(t *testing.T) {
	pl := newPipeline(t, nil)
	_, nonce, _ := pl.startRequest(t, nil)
	pl.attempt(t, nonce, 429, nil)
	pl.attempt(t, nonce, 429, nil)
	act := pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Headers:       policy.NewHeaders(map[string][]string{headerPlan: {nonce}}),
	}, nil)
	ir, ok := act.(policy.ImmediateResponse)
	if !ok || ir.Headers[headerExhausted] != "true" {
		t.Fatalf("expected exhausted marker, got %#v", act)
	}
}

func TestDispatchRewritesModelForNativeTargetsOnly(t *testing.T) {
	pl := newPipeline(t, nil)
	_, nonce, _ := pl.startRequest(t, nil)
	body := []byte(`{"model":"client-model","messages":[{"role":"user","content":"hi"}],"temperature":0.2}`)

	run := func() policy.RequestAction {
		shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
		pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
			SharedContext: shared,
			Headers:       policy.NewHeaders(map[string][]string{headerPlan: {nonce}}),
		}, nil)
		act := pl.dispatch.OnRequestBody(context.Background(), &policy.RequestContext{
			SharedContext: shared,
			Body:          &policy.Body{Content: body, Present: true, EndOfStream: true},
		}, nil)
		pl.dispatch.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{SharedContext: shared, ResponseStatus: 503}, nil)
		return act
	}

	native := run().(policy.UpstreamRequestModifications)
	var got map[string]json.RawMessage
	if err := json.Unmarshal(native.Body, &got); err != nil {
		t.Fatalf("rewritten body is not JSON: %v", err)
	}
	if string(got["model"]) != `"gpt-4o"` || string(got["temperature"]) != `0.2` || string(got["messages"]) != `[{"role":"user","content":"hi"}]` {
		t.Fatalf("model must be replaced and other members preserved: %s", native.Body)
	}

	if transformer := run().(policy.UpstreamRequestModifications); transformer.Body != nil {
		t.Fatal("a transformer target's body must be left to its transformer")
	}
}

func TestFrontStripsClientSuppliedInternalHeaders(t *testing.T) {
	pl := newPipeline(t, nil)
	_, nonce, mods := pl.startRequest(t, map[string][]string{
		headerPlan:            {"forged"},
		headerHop:             {"guess"},
		headerRetry:           {"x"},
		headerUpstreamFailure: {"UF"},
		"authorization":       {"Bearer k"},
	})
	if nonce == "forged" || len(nonce) != 32 {
		t.Fatalf("front must overwrite a client-supplied plan header, got %q", nonce)
	}
	removed := map[string]bool{}
	for _, h := range mods.HeadersToRemove {
		removed[h] = true
	}
	if !removed[headerHop] || !removed[headerRetry] || !removed[headerUpstreamFailure] || removed["authorization"] || removed[headerPlan] {
		t.Fatalf("unexpected removals: %v", mods.HeadersToRemove)
	}
}

func TestFrontResponseStripsInternalHeadersAndClosesPlan(t *testing.T) {
	pl := newPipeline(t, nil)
	shared, _, _ := pl.startRequest(t, nil)
	act := pl.front.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{SharedContext: shared, ResponseStatus: 503}, nil)
	m := respMods(t, act)
	want := map[string]bool{headerRetry: true, headerExhausted: true, headerUpstreamFailure: true}
	for _, h := range m.HeadersToRemove {
		delete(want, h)
	}
	if len(want) != 0 {
		t.Fatalf("front response must strip %v", want)
	}
	if m.HeadersToSet != nil {
		t.Fatal("front must not alter a non-eligible response")
	}
	if pl.plans.size() != 0 {
		t.Fatal("front response must close the plan")
	}
}

func TestModePerRole(t *testing.T) {
	pl := newPipeline(t, nil)
	if pl.front.Mode().RequestBodyMode != policy.BodyModeSkip {
		t.Error("front role must not buffer the request body")
	}
	if pl.dispatch.Mode().RequestBodyMode != policy.BodyModeBuffer {
		t.Error("dispatch role with a native target must buffer the request body")
	}
	allTransformer := newPipeline(t, func(p map[string]interface{}) {
		p[paramInternalTargetNative] = []interface{}{false, false}
	})
	if allTransformer.dispatch.Mode().RequestBodyMode != policy.BodyModeSkip {
		t.Error("dispatch role without native targets needs no body")
	}
}
