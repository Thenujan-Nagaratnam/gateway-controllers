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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func lifecycleParams(p map[string]interface{}) {
	p["suspendAfterConsecutiveFailures"] = float64(2)
	p["suspendDuration"] = "5s"
	p["recoverAfterSuccessfulProbes"] = float64(1)
}

// finish runs the front response phase for a request.
func (pl *pipeline) finish(t *testing.T, shared *policy.SharedContext, status int, headers map[string][]string) policy.ResponseHeaderAction {
	t.Helper()
	return pl.front.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{
		SharedContext:   shared,
		ResponseStatus:  status,
		ResponseHeaders: policy.NewHeaders(headers),
	}, nil)
}

// failPrimaryTwice runs two requests whose primary returns 503 and whose
// fallback succeeds.
func (pl *pipeline) failPrimaryTwice(t *testing.T) {
	t.Helper()
	for i := 0; i < 2; i++ {
		shared, nonce, _ := pl.startRequest(t, nil)
		pl.attempt(t, nonce, 503, nil)
		pl.attempt(t, nonce, 200, nil)
		pl.finish(t, shared, 200, nil)
	}
}

func TestSuspendedPrimaryIsSkipped(t *testing.T) {
	pl := newPipeline(t, lifecycleParams)
	pl.failPrimaryTwice(t)

	_, nonce, _ := pl.startRequest(t, nil)
	up, _ := pl.attempt(t, nonce, 200, nil)
	if up != "failover-t1" {
		t.Fatalf("the suspended primary must be skipped; first attempt went to %s", up)
	}
}

func TestAllSuspendedAnswersImmediately(t *testing.T) {
	pl := newPipeline(t, lifecycleParams)
	for i := 0; i < 2; i++ {
		shared, nonce, _ := pl.startRequest(t, nil)
		pl.attempt(t, nonce, 503, nil)
		_, act := pl.attempt(t, nonce, 503, nil)
		pl.finish(t, shared, 503, map[string][]string{headerRetry: {respMods(t, act).HeadersToSet[headerRetry]}})
	}
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	pl.front.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{SharedContext: shared, Headers: policy.NewHeaders(nil)}, nil)
	act := pl.frontBody(shared, "gpt-4o")
	ir, ok := act.(policy.ImmediateResponse)
	if !ok || ir.StatusCode != 503 || !bytes.Equal(ir.Body, exhaustionBody) {
		t.Fatalf("expected the exhaustion response without contacting any target, got %#v", act)
	}
	if pl.plans.size() != 0 {
		t.Fatal("no plan may be created when every target is suspended")
	}
}

func TestProbeRecoversPrimary(t *testing.T) {
	pl := newPipeline(t, lifecycleParams)
	pl.failPrimaryTwice(t)
	pl.clock.advance(5 * time.Second)

	shared, nonce, _ := pl.startRequest(t, nil)
	if up, _ := pl.attempt(t, nonce, 200, nil); up != "failover-t0" {
		t.Fatalf("after the suspension the primary must get a probe, got %s", up)
	}
	pl.finish(t, shared, 200, nil)
	if pl.health.state(pl.front.cfg, 0) != StateHealthy {
		t.Fatal("one successful probe (recoverAfterSuccessfulProbes=1) must recover the primary")
	}
}

func TestUnusedProbeSlotIsReleasedOnClose(t *testing.T) {
	pl := newPipeline(t, func(p map[string]interface{}) {
		lifecycleParams(p)
		setTargets(p, []interface{}{
			map[string]interface{}{"provider": "openai-a", "model": "gpt-4o"},
			map[string]interface{}{"provider": "anthropic", "model": "claude-sonnet-4-5"},
		})
	})
	// Suspend t1 (the fallback) by failing both targets twice.
	for i := 0; i < 2; i++ {
		shared, nonce, _ := pl.startRequest(t, nil)
		pl.attempt(t, nonce, 503, nil)
		pl.attempt(t, nonce, 503, nil)
		pl.finish(t, shared, 503, map[string][]string{headerRetry: {"status_503"}})
	}
	pl.clock.advance(5 * time.Second)
	// Both targets are probes now; the first answers, so t1's probe is never used.
	shared, nonce, _ := pl.startRequest(t, nil)
	pl.attempt(t, nonce, 200, nil)
	pl.finish(t, shared, 200, nil)

	_, probes, _ := pl.health.admit(pl.front.cfg, chainOf(pl.front.cfg))
	if !probes[1] {
		t.Fatal("t1's unused probe slot must have been released when the plan closed")
	}
}

func TestTimeoutInferredWhenNextAttemptArrives(t *testing.T) {
	pl := newPipeline(t, lifecycleParams)
	for i := 0; i < 2; i++ {
		shared, nonce, _ := pl.startRequest(t, nil)
		// Attempt 1 is sent but never answers: Envoy's per-try timeout fires.
		pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
			SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
			Headers:       policy.NewHeaders(map[string][]string{headerPlan: {nonce}}),
		}, nil)
		pl.attempt(t, nonce, 200, nil)
		pl.finish(t, shared, 200, nil)
	}
	if pl.health.state(pl.front.cfg, 0) != StateSuspended {
		t.Fatal("two inferred timeouts must suspend the primary")
	}
}

func TestFinalTimeoutBecomesExhaustion(t *testing.T) {
	pl := newPipeline(t, nil)
	shared, nonce, _ := pl.startRequest(t, nil)
	pl.attempt(t, nonce, 503, nil)
	// Attempt 2 is sent and then abandoned by Envoy, which answers 504.
	pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Headers:       policy.NewHeaders(map[string][]string{headerPlan: {nonce}}),
	}, nil)
	act := pl.finish(t, shared, 504, nil)
	if ir, ok := act.(policy.ImmediateResponse); !ok || ir.StatusCode != 503 {
		t.Fatalf("a final per-attempt timeout must become the exhaustion response, got %#v", act)
	}
}

func TestFinalTimeoutPassesThroughWhenTimeoutsDoNotFailOver(t *testing.T) {
	pl := newPipeline(t, func(p map[string]interface{}) {
		p["failoverOn"] = map[string]interface{}{"timeout": false}
	})
	shared, nonce, _ := pl.startRequest(t, nil)
	pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Headers:       policy.NewHeaders(map[string][]string{headerPlan: {nonce}}),
	}, nil)
	act := pl.finish(t, shared, 504, nil)
	if _, ok := act.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("the 504 must reach the client unchanged, got %#v", act)
	}
	if pl.health.state(pl.front.cfg, 0) != StateHealthy {
		t.Fatal("a timeout that is not a failover condition must not count against the target")
	}
}

func TestExhaustionReplacesTaggedOrExhaustedFinalResponse(t *testing.T) {
	for name, headers := range map[string]map[string][]string{
		"final attempt tagged":    {headerRetry: {"status_429"}},
		"plan ran out of targets": {headerExhausted: {"true"}},
	} {
		t.Run(name, func(t *testing.T) {
			pl := newPipeline(t, nil)
			shared, nonce, _ := pl.startRequest(t, nil)
			pl.attempt(t, nonce, 429, nil)
			act := pl.finish(t, shared, 429, headers)
			ir, ok := act.(policy.ImmediateResponse)
			if !ok || ir.StatusCode != 503 || !bytes.Equal(ir.Body, exhaustionBody) {
				t.Fatalf("expected the fixed exhaustion response, got %#v", act)
			}
			for k := range ir.Headers {
				if strings.HasPrefix(k, headerPrefix) {
					t.Fatalf("exhaustion response leaks internal header %s", k)
				}
			}
		})
	}
}

func TestLogsNeverContainSecretsOrBodies(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	pl := newPipeline(t, lifecycleParams)
	shared, nonce, _ := pl.startRequest(t, map[string][]string{"authorization": {"Bearer sk-client-secret"}})
	pl.attempt(t, nonce, 503, map[string][]string{"x-api-key": {"sk-provider"}})
	pl.attempt(t, nonce, 200, nil)
	pl.finish(t, shared, 200, nil)
	pl.failPrimaryTwice(t)

	out := buf.String()
	for _, secret := range []string{"s3cret", "sk-client-secret", "sk-provider", nonce} {
		if strings.Contains(out, secret) {
			t.Fatalf("log output contains %q:\n%s", secret, out)
		}
	}
	for _, event := range []string{"model_failover.attempt_failed", "model_failover.served", "model_failover.target_suspended"} {
		if !strings.Contains(out, event) {
			t.Fatalf("expected event %s in:\n%s", event, out)
		}
	}
}

// modelOf runs one provider-mode dispatch attempt and returns the model the
// attempt's request body was rewritten to, then answers it with status.
func (pl *pipeline) modelOf(t *testing.T, nonce string, status int) string {
	t.Helper()
	shared := &policy.SharedContext{Metadata: map[string]interface{}{}}
	pl.dispatch.OnRequestHeaders(context.Background(), &policy.RequestHeaderContext{
		SharedContext: shared, Headers: policy.NewHeaders(map[string][]string{headerPlan: {nonce}}),
	}, nil)
	act := pl.dispatch.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: shared,
		Body:          &policy.Body{Content: []byte(`{"model":"client","messages":[]}`), Present: true, EndOfStream: true},
	}, nil).(policy.UpstreamRequestModifications)
	pl.dispatch.OnResponseHeaders(context.Background(), &policy.ResponseHeaderContext{SharedContext: shared, ResponseStatus: status}, nil)
	var body struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(act.Body, &body)
	return body.Model
}

func TestProviderModeSuspendsAndRecoversAModel(t *testing.T) {
	pl := newPipeline(t, func(p map[string]interface{}) {
		lifecycleParams(p)
		p[paramInternalRouteToTarget] = false
		p[paramInternalTargetNative] = native(true, true)
		setTargets(p, []interface{}{
			map[string]interface{}{"provider": "openai", "model": "gpt-4o"},
			map[string]interface{}{"provider": "openai", "model": "gpt-4o-mini"},
		})
	})
	for i := 0; i < 2; i++ {
		shared, nonce, _ := pl.startRequest(t, nil)
		if m := pl.modelOf(t, nonce, 429); m != "gpt-4o" {
			t.Fatalf("attempt 1 must use gpt-4o, got %q", m)
		}
		if m := pl.modelOf(t, nonce, 200); m != "gpt-4o-mini" {
			t.Fatalf("attempt 2 must use gpt-4o-mini, got %q", m)
		}
		pl.finish(t, shared, 200, nil)
	}
	shared, nonce, _ := pl.startRequest(t, nil)
	if m := pl.modelOf(t, nonce, 200); m != "gpt-4o-mini" {
		t.Fatalf("a suspended gpt-4o must be skipped, first attempt used %q", m)
	}
	pl.finish(t, shared, 200, nil)

	pl.clock.advance(5 * time.Second)
	shared, nonce, _ = pl.startRequest(t, nil)
	if m := pl.modelOf(t, nonce, 200); m != "gpt-4o" {
		t.Fatalf("after the suspension a probe must go to gpt-4o, got %q", m)
	}
	pl.finish(t, shared, 200, nil)
	if pl.health.state(pl.front.cfg, 0) != StateHealthy {
		t.Fatal("a successful probe (recoverAfterSuccessfulProbes=1) recovers the model")
	}
}
