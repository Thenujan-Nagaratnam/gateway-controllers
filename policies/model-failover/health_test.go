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
	"testing"
	"time"
)

func healthCfg(t *testing.T, mutate func(map[string]interface{})) *Config {
	t.Helper()
	p := baseParams(RoleFront)
	p["suspendAfterConsecutiveFailures"] = float64(2)
	p["suspendDuration"] = "5s"
	p["recoverAfterSuccessfulProbes"] = float64(2)
	if mutate != nil {
		mutate(p)
	}
	cfg, err := parseConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

var (
	fail    = Outcome{Class: OutcomeEligibleFailure, Reason: "status_503"}
	success = Outcome{Class: OutcomeSuccess}
	client4 = Outcome{Class: OutcomeNonEligible}
)

func probe(o Outcome) Outcome { o.Probe = true; return o }

func TestHealthSuspendsAfterConsecutiveFailures(t *testing.T) {
	clock := newFakeClock()
	r := newHealthRegistry(clock.now)
	cfg := healthCfg(t, nil)

	if tr := r.record(cfg, 0, fail); tr != nil {
		t.Fatalf("first failure must not suspend: %+v", tr)
	}
	tr := r.record(cfg, 0, fail)
	if tr == nil || tr.To != StateSuspended || tr.Failures != 2 || !tr.Until.Equal(clock.now().Add(5*time.Second)) {
		t.Fatalf("second consecutive failure must suspend for 5s: %+v", tr)
	}
	if r.state(cfg, 1) != StateHealthy {
		t.Fatal("another target's health must be unaffected")
	}
}

func TestHealthSuccessAndNonEligibleResetTheCount(t *testing.T) {
	for name, reset := range map[string]Outcome{"success": success, "non-eligible 4xx": client4} {
		t.Run(name, func(t *testing.T) {
			r := newHealthRegistry(newFakeClock().now)
			cfg := healthCfg(t, nil)
			r.record(cfg, 0, fail)
			r.record(cfg, 0, reset)
			if tr := r.record(cfg, 0, fail); tr != nil {
				t.Fatal("the count must restart after a healthy response")
			}
		})
	}
}

func TestHealthAdmitSkipsSuspendedThenProbes(t *testing.T) {
	clock := newFakeClock()
	r := newHealthRegistry(clock.now)
	cfg := healthCfg(t, nil)
	r.record(cfg, 0, fail)
	r.record(cfg, 0, fail)

	targets, probes, _ := r.admit(cfg)
	if len(targets) != 1 || targets[0] != 1 || len(probes) != 0 {
		t.Fatalf("suspended t0 must be skipped: targets=%v probes=%v", targets, probes)
	}

	clock.advance(5 * time.Second)
	targets, probes, trs := r.admit(cfg)
	if len(targets) != 2 || !probes[0] || len(trs) != 1 || trs[0].To != StateProbing {
		t.Fatalf("after the suspension t0 must be admitted as a probe: targets=%v probes=%v trs=%v", targets, probes, trs)
	}
	// probeConcurrency defaults to 1: a second request cannot probe too.
	targets, probes, _ = r.admit(cfg)
	if len(targets) != 1 || targets[0] != 1 || len(probes) != 0 {
		t.Fatalf("only one probe may be in flight: targets=%v probes=%v", targets, probes)
	}
}

func TestHealthRecoversAfterRequiredProbeSuccesses(t *testing.T) {
	clock := newFakeClock()
	r := newHealthRegistry(clock.now)
	cfg := healthCfg(t, nil)
	r.record(cfg, 0, fail)
	r.record(cfg, 0, fail)
	clock.advance(5 * time.Second)

	r.admit(cfg)
	if tr := r.record(cfg, 0, probe(success)); tr != nil {
		t.Fatalf("one probe success of two must not recover: %+v", tr)
	}
	r.admit(cfg)
	tr := r.record(cfg, 0, probe(success))
	if tr == nil || tr.To != StateHealthy || tr.ProbeSuccesses != 2 {
		t.Fatalf("second probe success must recover: %+v", tr)
	}
	if targets, probes, _ := r.admit(cfg); len(targets) != 2 || len(probes) != 0 {
		t.Fatalf("a recovered target takes normal traffic: targets=%v probes=%v", targets, probes)
	}
}

func TestHealthFailedProbeSuspendsAgain(t *testing.T) {
	clock := newFakeClock()
	r := newHealthRegistry(clock.now)
	cfg := healthCfg(t, nil)
	r.record(cfg, 0, fail)
	r.record(cfg, 0, fail)
	clock.advance(5 * time.Second)
	r.admit(cfg)
	tr := r.record(cfg, 0, probe(fail))
	if tr == nil || tr.From != StateProbing || tr.To != StateSuspended || !tr.Until.Equal(clock.now().Add(5*time.Second)) {
		t.Fatalf("a failed probe must start a new suspension: %+v", tr)
	}
}

func TestHealthReleaseFreesAnUnusedProbeSlot(t *testing.T) {
	clock := newFakeClock()
	r := newHealthRegistry(clock.now)
	cfg := healthCfg(t, nil)
	r.record(cfg, 0, fail)
	r.record(cfg, 0, fail)
	clock.advance(5 * time.Second)
	r.admit(cfg)
	r.release(cfg, 0)
	if _, probes, _ := r.admit(cfg); !probes[0] {
		t.Fatal("a released slot must be available to the next request")
	}
}

func TestHealthIgnoresLateOutcomes(t *testing.T) {
	clock := newFakeClock()
	r := newHealthRegistry(clock.now)
	cfg := healthCfg(t, nil)
	r.record(cfg, 0, fail)
	r.record(cfg, 0, fail)
	// A request admitted before the suspension finishes successfully.
	if tr := r.record(cfg, 0, success); tr != nil || r.state(cfg, 0) != StateSuspended {
		t.Fatal("a late non-probe outcome must not end a suspension")
	}
}

func TestHealthStateSurvivesReorderButNotModelChange(t *testing.T) {
	r := newHealthRegistry(newFakeClock().now)
	cfg := healthCfg(t, nil)
	r.record(cfg, 0, fail)
	r.record(cfg, 0, fail)

	reordered := healthCfg(t, func(p map[string]interface{}) {
		ts := p["targets"].([]interface{})
		p["targets"] = []interface{}{ts[1], ts[0]}
	})
	if r.state(reordered, 1) != StateSuspended {
		t.Fatal("the same (provider, model) keeps its state when it moves in the chain")
	}
	changed := healthCfg(t, func(p map[string]interface{}) {
		p["targets"] = []interface{}{
			map[string]interface{}{"provider": "openai-a", "model": "gpt-4.1"},
			p["targets"].([]interface{})[1],
		}
	})
	if r.state(changed, 0) != StateHealthy {
		t.Fatal("a changed model starts healthy")
	}
}
