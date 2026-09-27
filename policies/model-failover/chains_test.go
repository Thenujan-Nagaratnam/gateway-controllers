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
	"net/http"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// twoChains is gpt-4o → [openai-b gpt-4o, anthropic claude] and
// gpt-4.1 → [openai-a gpt-4.1-mini, anthropic claude]; claude is shared.
func twoChains(p map[string]interface{}) {
	p["chains"] = []interface{}{
		map[string]interface{}{
			"primary": map[string]interface{}{"provider": "openai-a", "model": "gpt-4o"},
			"fallbacks": []interface{}{
				map[string]interface{}{"provider": "openai-b", "model": "gpt-4o"},
				map[string]interface{}{"provider": "anthropic", "model": "claude-sonnet-4-5"},
			},
		},
		map[string]interface{}{
			"primary": map[string]interface{}{"provider": "openai-a", "model": "gpt-4.1"},
			"fallbacks": []interface{}{
				map[string]interface{}{"provider": "openai-a", "model": "gpt-4.1-mini"},
				map[string]interface{}{"provider": "anthropic", "model": "claude-sonnet-4-5"},
			},
		},
	}
	p[paramInternalTargetNative] = native(true, true, false, true, true)
	p["suspendAfterConsecutiveFailures"] = float64(1)
}

func TestChainsFlattenIntoDistinctTargets(t *testing.T) {
	p := baseParams(RoleFront)
	twoChains(p)
	cfg, err := parseConfig(p)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	var got []string
	for _, tg := range cfg.Targets {
		got = append(got, tg.Provider+"/"+tg.Model)
	}
	want := []string{"openai-a/gpt-4o", "openai-b/gpt-4o", "anthropic/claude-sonnet-4-5", "openai-a/gpt-4.1", "openai-a/gpt-4.1-mini", "openai-a/"}
	if len(got) != len(want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("targets = %v, want %v", got, want)
		}
	}
	if c := cfg.Chains["gpt-4.1"]; len(c) != 3 || c[0] != 3 || c[1] != 4 || c[2] != 2 {
		t.Fatalf("gpt-4.1 chain = %v, want [3 4 2] (claude shared)", c)
	}
	if cfg.PassThrough != 5 || cfg.longestChain() != 3 {
		t.Fatalf("pass-through %d, longest %d", cfg.PassThrough, cfg.longestChain())
	}
}

func TestAuthoredPrimaryProviderIsRejected(t *testing.T) {
	p := map[string]interface{}{"chains": oneChain(
		map[string]interface{}{"provider": "openai-a", "model": "gpt-4o"},
		map[string]interface{}{"model": "gpt-4o-mini"},
	)}
	if err := ValidateAuthoredParams(p); err == nil {
		t.Fatal("a provider on the primary must be rejected in authored params")
	}
}

// walk sends a request for model and answers its attempts with statuses in
// turn, returning the (provider/model) of every attempt.
func (pl *pipeline) walk(t *testing.T, model string, statuses ...int) []string {
	t.Helper()
	shared, nonce, _ := pl.startRequestFor(t, nil, model)
	var tried []string
	for _, st := range statuses {
		disp := &policy.SharedContext{Metadata: map[string]interface{}{}}
		act := pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{SharedContext: disp, Headers: policy.NewHeaders(map[string][]string{headerPlan: {nonce}})}, nil)
		if _, ok := act.(policy.UpstreamRequestHeaderModifications); !ok {
			break
		}
		a, _ := currentAttempt(disp)
		tg := pl.dispatch.cfg.Targets[a.targetIdx]
		tried = append(tried, tg.Provider+"/"+tg.Model)
		resp := pl.dispatch.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{SharedContext: disp, ResponseStatus: st}, nil)
		if respMods(t, resp).HeadersToSet[headerRetry] == "" {
			break
		}
	}
	pl.finish(t, shared, statuses[len(tried)-1], nil)
	return tried
}

func TestEachModelWalksItsOwnChain(t *testing.T) {
	pl := newPipeline(t, twoChains)
	if got := pl.walk(t, "gpt-4o", 429, 200); len(got) != 2 || got[1] != "openai-b/gpt-4o" {
		t.Fatalf("gpt-4o must fall back along its own chain, tried %v", got)
	}
	if got := pl.walk(t, "gpt-4.1", 429, 200); len(got) != 2 || got[0] != "openai-a/gpt-4.1" || got[1] != "openai-a/gpt-4.1-mini" {
		t.Fatalf("gpt-4.1 must fall back along its own chain, tried %v", got)
	}
}

func TestSharedTargetHealthSpansChains(t *testing.T) {
	pl := newPipeline(t, twoChains)
	// Fail all of gpt-4o's chain once (threshold 1): claude is suspended too.
	pl.walk(t, "gpt-4o", 503, 503, 503)
	if got := pl.walk(t, "gpt-4.1", 503, 503, 200); len(got) != 2 {
		t.Fatalf("claude, suspended through gpt-4o's chain, must be skipped in gpt-4.1's, tried %v", got)
	}
}

func TestUnmatchedModelPassesThroughUnchanged(t *testing.T) {
	pl := newPipeline(t, twoChains)
	shared, nonce, _ := pl.startRequestFor(t, nil, "gpt-4o-mini")
	disp := &policy.SharedContext{Metadata: map[string]interface{}{}}
	m := pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{SharedContext: disp, Headers: policy.NewHeaders(map[string][]string{headerPlan: {nonce}})}, nil).(policy.UpstreamRequestHeaderModifications)
	if m.UpstreamName == nil || *m.UpstreamName != "failover-tp" {
		t.Fatalf("pass-through must route to the pass-through target, got %v", m.UpstreamName)
	}
	body, _ := json.Marshal(map[string]interface{}{"model": "gpt-4o-mini"})
	if out := pl.dispatch.OnRequestBody(context.Background(), &policy.RequestContext{SharedContext: disp, Body: &policy.Body{Content: body, Present: true}}, nil).(policy.UpstreamRequestModifications); out.Body != nil {
		t.Fatalf("pass-through must not rewrite the model, got %s", out.Body)
	}
	resp := respMods(t, pl.dispatch.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{SharedContext: disp, ResponseStatus: 503}, nil))
	if resp.HeadersToSet[headerRetry] != "" {
		t.Fatal("a pass-through failure must not be tagged for retry")
	}
	final := respMods(t, pl.front.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{SharedContext: shared, ResponseStatus: 503}, nil))
	if final.HeadersToSet != nil {
		t.Fatal("the front passes a pass-through reply as it is")
	}
	for i := range pl.front.cfg.Targets {
		if pl.health.state(pl.front.cfg, i) != StateHealthy {
			t.Fatal("pass-through must not affect health")
		}
	}
}

func TestUnreadableBodyPassesThrough(t *testing.T) {
	pl := newPipeline(t, twoChains)
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	nonce := pl.front.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{SharedContext: shared, Headers: policy.NewHeaders(nil)}, nil).(policy.UpstreamRequestHeaderModifications).HeadersToSet[headerPlan]
	pl.front.OnRequestBody(context.Background(), &policy.RequestContext{SharedContext: shared, Body: &policy.Body{Content: []byte("not json"), Present: true}}, nil)
	if !pl.plans.peek(nonce).isPassThrough() {
		t.Fatal("a body with no readable model must pass through")
	}
}

func TestPassThroughTimeoutIsNotRetried(t *testing.T) {
	pl := newPipeline(t, twoChains)
	_, nonce, _ := pl.startRequestFor(t, nil, "unknown")
	hdr := policy.NewHeaders(map[string][]string{headerPlan: {nonce}})
	pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}}, Headers: hdr}, nil)
	// Envoy abandoned the attempt on its per-attempt timeout and retried.
	act := pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}}, Headers: hdr}, nil)
	ir, ok := act.(policy.ImmediateResponse)
	if !ok || ir.StatusCode != http.StatusGatewayTimeout || ir.Headers[headerExhausted] != "" {
		t.Fatalf("expected an untagged 504, got %#v", act)
	}
}
