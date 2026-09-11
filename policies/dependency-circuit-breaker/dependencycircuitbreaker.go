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

// Package dependencycircuitbreaker is a per-tool-name closed/open/half-open
// circuit breaker for MCP tool calls (OWASP Agentic AI Top 10: ASI08 -
// Cascading Agent Failures). See policy-definition.yaml for the full
// behavior.
//
// State is kept in an in-process map guarded by a mutex, bounded by an
// absolute tracked-tool cap so a stream of distinct/spoofed tool names can't
// grow it without bound. This is correct for a single gateway-runtime
// replica; a shared store would be needed to coordinate breaker state across
// replicas, which the SDK does not yet provide (v0.2.0).
package dependencycircuitbreaker

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	breakerType = "DEPENDENCY_CIRCUIT_BREAKER"
	breakerName = "DependencyCircuitBreaker"
	openStatus  = 503

	stateClosed   = "closed"
	stateOpen     = "open"
	stateHalfOpen = "half_open"

	mdToolName = "dependency-circuit-breaker.toolName"
	mdTrial    = "dependency-circuit-breaker.trial"

	// maxTrackedTools bounds the in-process state map regardless of how many
	// distinct tool names are seen - a tool catalog is normally a small,
	// finite set, but a crafted/spoofed name stream must not be able to grow
	// this without bound.
	maxTrackedTools = 5000
)

type config struct {
	toolNamePath        string
	failureThreshold    int
	openDurationSeconds float64
	halfOpenMaxTrials   int
	errorStatusCodes    map[int]bool
	errorDetectionPath  string
	showAssessment      bool
}

// circuitState tracks one tool's breaker.
type circuitState struct {
	status              string
	consecutiveFailures int
	openedAt            time.Time
	halfOpenInFlight    int
	lastSeen            time.Time
}

// DependencyCircuitBreakerPolicy implements the v1alpha2 policy interface.
type DependencyCircuitBreakerPolicy struct {
	cfg config

	mu       sync.Mutex
	circuits map[string]*circuitState
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		toolNamePath:        "$.params.name",
		failureThreshold:    5,
		openDurationSeconds: 30,
		halfOpenMaxTrials:   1,
		errorStatusCodes:    map[int]bool{500: true, 502: true, 503: true, 504: true},
		errorDetectionPath:  "$.error",
	}

	strOpt(params, "toolNameJsonPath", &cfg.toolNamePath)

	if v, ok := params["failureThreshold"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 1 {
			return nil, wrap(fmt.Errorf("'failureThreshold' must be a number >= 1"))
		}
		cfg.failureThreshold = int(f)
	}
	if v, ok := params["openDurationSeconds"]; ok {
		f, err := toFloat(v)
		if err != nil || f <= 0 {
			return nil, wrap(fmt.Errorf("'openDurationSeconds' must be a number > 0"))
		}
		cfg.openDurationSeconds = f
	}
	if v, ok := params["halfOpenMaxTrials"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 1 {
			return nil, wrap(fmt.Errorf("'halfOpenMaxTrials' must be a number >= 1"))
		}
		cfg.halfOpenMaxTrials = int(f)
	}
	if raw, ok := params["errorStatusCodes"]; ok {
		list, ok := raw.([]interface{})
		if !ok {
			return nil, wrap(fmt.Errorf("'errorStatusCodes' must be an array of integers"))
		}
		cfg.errorStatusCodes = map[int]bool{}
		for _, e := range list {
			f, err := toFloat(e)
			if err != nil {
				return nil, wrap(fmt.Errorf("'errorStatusCodes' entries must be integers"))
			}
			cfg.errorStatusCodes[int(f)] = true
		}
	}
	if v, ok := params["errorDetectionJsonPath"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, wrap(fmt.Errorf("'errorDetectionJsonPath' must be a string"))
		}
		cfg.errorDetectionPath = s // "" explicitly disables body-based error detection
	}
	if err := boolParam(params, "showAssessment", &cfg.showAssessment); err != nil {
		return nil, wrap(err)
	}

	return &DependencyCircuitBreakerPolicy{cfg: cfg, circuits: map[string]*circuitState{}}, nil
}

// Mode buffers both bodies: the request body to identify the tool, the
// response body to (optionally) detect an application-level error.
func (p *DependencyCircuitBreakerPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// OnRequestBody identifies the target tool and either lets the call through
// (closed, or an allotted half-open trial) or short-circuits it (open).
func (p *DependencyCircuitBreakerPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	var root interface{}
	_ = json.Unmarshal(body, &root) // malformed/non-JSON body simply resolves no tool name below

	toolName, _ := valueAt(root, p.cfg.toolNamePath).(string)
	if toolName == "" {
		return policy.UpstreamRequestModifications{} // nothing to track for this call
	}

	now := time.Now()
	p.mu.Lock()
	st := p.circuits[toolName]
	if st == nil {
		st = &circuitState{status: stateClosed}
		p.circuits[toolName] = st
		p.evictLocked(now)
	}
	st.lastSeen = now

	switch st.status {
	case stateOpen:
		if now.Sub(st.openedAt).Seconds() >= p.cfg.openDurationSeconds {
			st.status = stateHalfOpen
			st.halfOpenInFlight = 0
		} else {
			remaining := p.cfg.openDurationSeconds - now.Sub(st.openedAt).Seconds()
			p.mu.Unlock()
			return p.shortCircuit(toolName, remaining)
		}
		fallthrough
	case stateHalfOpen:
		if st.halfOpenInFlight >= p.cfg.halfOpenMaxTrials {
			remaining := p.cfg.openDurationSeconds - now.Sub(st.openedAt).Seconds()
			if remaining < 1 {
				remaining = 1
			}
			p.mu.Unlock()
			return p.shortCircuit(toolName, remaining)
		}
		st.halfOpenInFlight++
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = map[string]interface{}{}
		}
		reqCtx.Metadata[mdTrial] = true
	default: // closed
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = map[string]interface{}{}
		}
	}
	reqCtx.Metadata[mdToolName] = toolName
	p.mu.Unlock()

	return policy.UpstreamRequestModifications{}
}

func (p *DependencyCircuitBreakerPolicy) shortCircuit(toolName string, remainingSeconds float64) policy.RequestAction {
	if remainingSeconds < 0 {
		remainingSeconds = 0
	}
	retryAfter := int(remainingSeconds + 0.999) // round up so callers never retry a hair too early
	msg := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": breakerName,
		"direction":            "REQUEST",
		"actionReason":         fmt.Sprintf("the circuit breaker for tool %q is open following repeated failures", toolName),
	}
	if p.cfg.showAssessment {
		msg["assessments"] = []string{fmt.Sprintf("tool=%s state=open retryAfterSeconds=%d", toolName, retryAfter)}
	}
	b, _ := json.Marshal(map[string]interface{}{"type": breakerType, "message": msg})
	return policy.ImmediateResponse{
		StatusCode: openStatus,
		Headers: map[string]string{
			"Content-Type":            "application/json",
			"Retry-After":             fmt.Sprintf("%d", retryAfter),
			"x-circuit-breaker-state": stateOpen,
			"x-circuit-breaker-tool":  toolName,
		},
		Body: b,
		AnalyticsMetadata: map[string]any{
			"isGuardrailHit": true, "guardrailName": breakerName, "direction": "REQUEST",
			"circuitBreakerTool": toolName, "circuitBreakerState": stateOpen,
		},
	}
}

// OnResponseBody records the call's outcome against the tool's breaker.
func (p *DependencyCircuitBreakerPolicy) OnResponseBody(_ context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	md := respCtx.Metadata
	toolName, _ := md[mdToolName].(string)
	if toolName == "" {
		return policy.DownstreamResponseModifications{} // this call was never tracked (no tool identified, or short-circuited)
	}
	wasTrial, _ := md[mdTrial].(bool)

	failed := p.cfg.errorStatusCodes[respCtx.ResponseStatus]
	if !failed && p.cfg.errorDetectionPath != "" {
		var body []byte
		if respCtx.ResponseBody != nil {
			body = respCtx.ResponseBody.Content
		}
		var root interface{}
		if err := json.Unmarshal(body, &root); err == nil {
			if v := valueAt(root, p.cfg.errorDetectionPath); v != nil && v != false {
				failed = true
			}
		}
	}

	p.mu.Lock()
	st := p.circuits[toolName]
	if st == nil {
		p.mu.Unlock()
		return policy.DownstreamResponseModifications{} // evicted between request and response phase - nothing to update
	}
	if wasTrial {
		st.halfOpenInFlight--
		if st.halfOpenInFlight < 0 {
			st.halfOpenInFlight = 0
		}
		if failed {
			st.status, st.openedAt, st.consecutiveFailures = stateOpen, time.Now(), p.cfg.failureThreshold
		} else {
			st.status, st.consecutiveFailures = stateClosed, 0
		}
	} else {
		if failed {
			st.consecutiveFailures++
			if st.consecutiveFailures >= p.cfg.failureThreshold {
				st.status, st.openedAt = stateOpen, time.Now()
			}
		} else {
			st.consecutiveFailures = 0
		}
	}
	newState := st.status
	p.mu.Unlock()

	headers := map[string]string{"x-circuit-breaker-tool": toolName, "x-circuit-breaker-state": newState}
	meta := map[string]any{"guardrailName": breakerName, "circuitBreakerTool": toolName, "circuitBreakerState": newState, "circuitBreakerFailed": failed}
	if newState == stateOpen && wasTrial {
		meta["isGuardrailHit"] = true // a half-open trial that failed re-opened the breaker
	}
	return policy.DownstreamResponseModifications{HeadersToSet: headers, AnalyticsMetadata: meta}
}

// evictLocked bounds the circuit map: drop the least-recently-seen entries
// once over the cap. Must be called with p.mu held.
func (p *DependencyCircuitBreakerPolicy) evictLocked(_ time.Time) {
	if len(p.circuits) <= maxTrackedTools {
		return
	}
	type kv struct {
		key      string
		lastSeen time.Time
	}
	all := make([]kv, 0, len(p.circuits))
	for k, st := range p.circuits {
		all = append(all, kv{k, st.lastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].lastSeen.Before(all[j].lastSeen) })
	excess := len(p.circuits) - maxTrackedTools
	for i := 0; i < excess && i < len(all); i++ {
		delete(p.circuits, all[i].key)
	}
}

// ─── minimal read-only JSONPath ───────────────────────────────────────────────

func valueAt(root interface{}, jsonPath string) interface{} {
	cur := root
	p := strings.TrimPrefix(strings.TrimPrefix(jsonPath, "$"), ".")
	if p == "" {
		return cur
	}
	for _, comp := range strings.Split(p, ".") {
		if comp == "" {
			continue
		}
		key, idx, hasIdx := comp, 0, false
		if o := strings.IndexByte(comp, '['); o >= 0 && strings.HasSuffix(comp, "]") {
			key = comp[:o]
			hasIdx = true
			in := comp[o+1 : len(comp)-1]
			n, neg := 0, false
			for _, c := range in {
				if c == '-' {
					neg = true
					continue
				}
				if c < '0' || c > '9' {
					n = 0
					break
				}
				n = n*10 + int(c-'0')
			}
			if neg {
				n = -n
			}
			idx = n
		}
		if key != "" {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return nil
			}
			cur = m[key]
		}
		if hasIdx {
			a, ok := cur.([]interface{})
			if !ok || len(a) == 0 {
				return nil
			}
			switch {
			case idx < 0:
				if -idx > len(a) {
					return nil
				}
				cur = a[len(a)+idx]
			case idx < len(a):
				cur = a[idx]
			default:
				return nil
			}
		}
	}
	return cur
}

// ─── param helpers ───────────────────────────────────────────────────────────

func wrap(err error) error { return fmt.Errorf("invalid params: %w", err) }

func strOpt(m map[string]interface{}, k string, dst *string) {
	if s, ok := m[k].(string); ok && s != "" {
		*dst = s
	}
}

func boolParam(m map[string]interface{}, k string, dst *bool) error {
	if v, ok := m[k]; ok {
		b, ok := v.(bool)
		if !ok {
			return fmt.Errorf("'%s' must be a boolean", k)
		}
		*dst = b
	}
	return nil
}

func toFloat(v interface{}) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case json.Number:
		return n.Float64()
	default:
		return 0, fmt.Errorf("not a number")
	}
}
