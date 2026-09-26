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
	"strings"
	"testing"
	"time"
)

func baseParams(role Role) map[string]interface{} {
	p := map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"provider": "openai-a", "model": "gpt-4o"},
			map[string]interface{}{"provider": "anthropic", "model": "claude-sonnet-4-5"},
		},
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
	p[paramInternalTargetIDs] = []interface{}{"t0", "t1"}
	p[paramInternalTargetNative] = []interface{}{true, false}
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
		"no targets":       func(p map[string]interface{}) { delete(p, "targets") },
		"empty targets":    func(p map[string]interface{}) { p["targets"] = []interface{}{} },
		"too many targets": func(p map[string]interface{}) { p["targets"] = manyTargets(11) },
		"duplicate target": func(p map[string]interface{}) {
			p["targets"] = append(p["targets"].([]interface{}), p["targets"].([]interface{})[0])
		},
		"missing model": func(p map[string]interface{}) { p["targets"] = []interface{}{map[string]interface{}{"provider": "x"}} },
		"model too long": func(p map[string]interface{}) {
			p["targets"] = []interface{}{map[string]interface{}{"provider": "x", "model": strings.Repeat("m", 257)}}
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
		"targets":         []interface{}{map[string]interface{}{"provider": "a", "model": "m"}},
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

func manyTargets(n int) []interface{} {
	out := make([]interface{}, n)
	for i := range out {
		out[i] = map[string]interface{}{"provider": "p", "model": "m" + string(rune('a'+i))}
	}
	return out
}
