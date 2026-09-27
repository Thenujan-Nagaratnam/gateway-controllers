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
	"fmt"
	"strings"
	"testing"
	"time"
)

func baseParams(role Role) map[string]interface{} {
	p := map[string]interface{}{
		"chains": oneChain(
			map[string]interface{}{"provider": "openai-a", "model": "gpt-4o"},
			map[string]interface{}{"provider": "anthropic", "model": "claude-sonnet-4-5"},
		),
		paramInternalRole:    string(role),
		paramInternalChainID: "proxy-1:POST|/chat/completions",
	}
	if role == RoleDispatch {
		p[paramInternalHopSecret] = "s3cret"
	}
	return p
}

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := parseConfig(baseParams(RoleFront))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.PerAttemptTimeout != 30*time.Second || cfg.SuspendDuration != 30*time.Second {
		t.Errorf("duration defaults: got %s / %s", cfg.PerAttemptTimeout, cfg.SuspendDuration)
	}
	if cfg.SuspendAfterConsecutiveFailures != 3 || cfg.ProbeConcurrency != 1 || cfg.RecoverAfterSuccessfulProbes != 2 {
		t.Errorf("int defaults: got %+v", cfg)
	}
	for _, c := range []int{429, 500, 502, 503, 504} {
		if !cfg.FailoverOn.StatusCodes[c] {
			t.Errorf("default status code %d missing", c)
		}
	}
	if !cfg.FailoverOn.ConnectFailure || !cfg.FailoverOn.Reset || !cfg.FailoverOn.Timeout {
		t.Errorf("transport defaults must be true: %+v", cfg.FailoverOn)
	}
	if cfg.Targets[0].ID != "t0" || cfg.Targets[1].ID != "t1" || cfg.Targets[1].UpstreamName() != "failover-t1" {
		t.Errorf("derived target ids: %+v", cfg.Targets)
	}
}

func TestParseConfigExplicitValues(t *testing.T) {
	p := baseParams(RoleDispatch)
	p["failoverOn"] = map[string]interface{}{"statusCodes": []interface{}{float64(429)}, "timeout": false}
	p["perAttemptTimeout"] = "2s"
	p["suspendAfterConsecutiveFailures"] = float64(5)
	p[paramInternalTargetIDs] = []interface{}{"t0", "t1", "tp"}
	p[paramInternalTargetNative] = native(true, false)
	cfg, err := parseConfig(p)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.FailoverOn.StatusCodes[503] || !cfg.FailoverOn.StatusCodes[429] {
		t.Errorf("explicit statusCodes must replace defaults: %v", cfg.FailoverOn.StatusCodes)
	}
	if cfg.FailoverOn.Timeout || !cfg.FailoverOn.ConnectFailure {
		t.Errorf("explicit timeout=false must not affect other toggles: %+v", cfg.FailoverOn)
	}
	if cfg.PerAttemptTimeout != 2*time.Second || cfg.SuspendAfterConsecutiveFailures != 5 {
		t.Errorf("explicit values: %+v", cfg)
	}
	if cfg.Targets[1].Native || cfg.HopSecret != "s3cret" {
		t.Errorf("internal keys: %+v", cfg)
	}
}

func TestParseConfigRejects(t *testing.T) {
	cases := map[string]func(map[string]interface{}){
		"no chains":          func(p map[string]interface{}) { delete(p, "chains") },
		"old targets":        func(p map[string]interface{}) { p["targets"] = getTargets(p) },
		"empty chains":       func(p map[string]interface{}) { p["chains"] = []interface{}{} },
		"no fallbacks":       func(p map[string]interface{}) { setTargets(p, getTargets(p)[:1]) },
		"too many fallbacks": func(p map[string]interface{}) { setTargets(p, manyTargets(11)) },
		"too many chains": func(p map[string]interface{}) {
			var chains []interface{}
			for i := 0; i < 21; i++ {
				chains = append(chains, oneChain(map[string]interface{}{"model": fmt.Sprint("p", i)}, map[string]interface{}{"model": "f"})...)
			}
			p["chains"] = chains
		},
		"too many distinct targets": func(p map[string]interface{}) {
			var chains []interface{}
			for i := 0; i < 6; i++ {
				ts := manyTargets(10)
				for _, t := range ts {
					t.(map[string]interface{})["provider"] = fmt.Sprint("p", i)
				}
				chains = append(chains, oneChain(ts...)...)
			}
			p["chains"] = chains
		},
		"duplicate primary": func(p map[string]interface{}) {
			p["chains"] = append(p["chains"].([]interface{}), p["chains"].([]interface{})[0])
		},
		"repeat within a chain": func(p map[string]interface{}) {
			setTargets(p, append(getTargets(p), getTargets(p)[0]))
		},
		"missing model": func(p map[string]interface{}) {
			setTargets(p, []interface{}{map[string]interface{}{"provider": "x"}, map[string]interface{}{"model": "m"}})
		},
		"model too long": func(p map[string]interface{}) {
			setTargets(p, []interface{}{map[string]interface{}{"provider": "x", "model": strings.Repeat("m", 257)}, map[string]interface{}{"model": "m"}})
		},
		"status 404": func(p map[string]interface{}) {
			p["failoverOn"] = map[string]interface{}{"statusCodes": []interface{}{float64(404)}}
		},
		"duplicate status": func(p map[string]interface{}) {
			p["failoverOn"] = map[string]interface{}{"statusCodes": []interface{}{float64(503), float64(503)}}
		},
		"timeout zero":       func(p map[string]interface{}) { p["perAttemptTimeout"] = "0s" },
		"timeout too long":   func(p map[string]interface{}) { p["perAttemptTimeout"] = "301s" },
		"timeout bad unit":   func(p map[string]interface{}) { p["perAttemptTimeout"] = "30h" },
		"threshold zero":     func(p map[string]interface{}) { p["suspendAfterConsecutiveFailures"] = float64(0) },
		"probes too high":    func(p map[string]interface{}) { p["probeConcurrency"] = float64(11) },
		"recover zero":       func(p map[string]interface{}) { p["recoverAfterSuccessfulProbes"] = float64(0) },
		"suspend too long":   func(p map[string]interface{}) { p["suspendDuration"] = "61m" },
		"missing role":       func(p map[string]interface{}) { delete(p, paramInternalRole) },
		"missing chain":      func(p map[string]interface{}) { delete(p, paramInternalChainID) },
		"target id mismatch": func(p map[string]interface{}) { p[paramInternalTargetIDs] = []interface{}{"t0"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := baseParams(RoleFront)
			mutate(p)
			if _, err := parseConfig(p); err == nil {
				t.Fatalf("expected an error")
			}
		})
	}
}

func TestParseConfigDispatchNeedsHopSecret(t *testing.T) {
	p := baseParams(RoleDispatch)
	delete(p, paramInternalHopSecret)
	if _, err := parseConfig(p); err == nil {
		t.Fatal("dispatch role without hop secret must be rejected")
	}
}

func TestValidateAuthoredParamsRejectsInternalKeys(t *testing.T) {
	p := map[string]interface{}{
		"chains":          oneChain(map[string]interface{}{"model": "m"}, map[string]interface{}{"provider": "a", "model": "n"}),
		paramInternalRole: "front",
	}
	if err := ValidateAuthoredParams(p); err == nil {
		t.Fatal("authored _-prefixed key must be rejected")
	}
	delete(p, paramInternalRole)
	if err := ValidateAuthoredParams(p); err != nil {
		t.Fatalf("valid authored params rejected: %v", err)
	}
}

// oneChain turns an ordered target list into a single chain: the first entry
// is the primary, the rest its fallbacks.
func oneChain(targets ...interface{}) []interface{} {
	return []interface{}{map[string]interface{}{"primary": targets[0], "fallbacks": append([]interface{}{}, targets[1:]...)}}
}

// setTargets replaces the params' chains with one chain over targets.
func setTargets(p map[string]interface{}, targets []interface{}) {
	p["chains"] = oneChain(targets...)
}

// getTargets returns the first chain's primary and fallbacks, in order.
func getTargets(p map[string]interface{}) []interface{} {
	c := p["chains"].([]interface{})[0].(map[string]interface{})
	return append([]interface{}{c["primary"]}, c["fallbacks"].([]interface{})...)
}

// native builds _targetNative for the listed targets plus the pass-through
// target, which is always native.
func native(flags ...bool) []interface{} {
	out := make([]interface{}, 0, len(flags)+1)
	for _, f := range flags {
		out = append(out, f)
	}
	return append(out, true)
}

// chainOf is the first chain's target indices.
func chainOf(cfg *Config) []int {
	return cfg.Chains[cfg.Targets[0].Model]
}

func manyTargets(n int) []interface{} {
	out := make([]interface{}, n)
	for i := range out {
		out[i] = map[string]interface{}{"provider": "p", "model": "m" + string(rune('a'+i))}
	}
	return out
}
