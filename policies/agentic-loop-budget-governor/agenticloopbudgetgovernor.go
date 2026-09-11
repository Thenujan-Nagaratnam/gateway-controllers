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

// Package agenticloopbudgetgovernor is a circuit-breaker for runaway agents
// (OWASP LLM10 Unbounded Consumption, Agentic T4 Resource Overload, LLM06
// Excessive Agency). It keeps per-session counters - call count, an estimated
// token count, wall-clock session duration, and consecutive identical tool
// calls (a common symptom of a stuck plan-act-observe loop) - and blocks or
// annotates once a configured ceiling is crossed.
//
// State is kept in an in-process map guarded by a mutex, bounded by an idle
// TTL (windowSeconds) and an absolute tracked-session cap so an attacker
// sending many distinct session identifiers can't grow it without bound.
// This is correct for a single gateway-runtime replica; a future version can
// move it to the SDK's shared store once one is available (v0.2.0 does not
// ship one).
package agenticloopbudgetgovernor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	governorType = "AGENTIC_LOOP_BUDGET_GOVERNOR"
	governorName = "AgenticLoopBudgetGovernor"
	breachStatus = 429

	actionBlock    = "block"
	actionAnnotate = "annotate"

	// maxTrackedSessions bounds the in-process state map regardless of
	// windowSeconds, so an attacker can't grow it unboundedly by minting a
	// fresh session identifier on every call.
	maxTrackedSessions = 20000
)

// ─── config ──────────────────────────────────────────────────────────────────

type sessionKeyConfig struct {
	header         string
	jsonPath       string
	fallbackToHash bool
}

type config struct {
	maxCalls                int
	maxTokens               int
	maxDurationSeconds      float64
	maxConsecutiveIdentical int
	windowSeconds           float64
	onBreach                string
	sessionKey              sessionKeyConfig
	toolNamePath            string
	argsPath                string
	showAssessment          bool
}

// sessionState tracks one agent session's cumulative usage.
type sessionState struct {
	firstSeen            time.Time
	lastSeen             time.Time
	calls                int
	tokens               int
	lastToolKey          string
	consecutiveIdentical int
}

// AgenticLoopBudgetGovernorPolicy implements the v1alpha2 policy interface.
type AgenticLoopBudgetGovernorPolicy struct {
	cfg config

	mu       sync.Mutex
	sessions map[string]*sessionState
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		maxCalls:                40,
		maxTokens:               200000,
		maxDurationSeconds:      900,
		maxConsecutiveIdentical: 3,
		windowSeconds:           1800,
		onBreach:                actionBlock,
		sessionKey: sessionKeyConfig{
			header:         "x-agent-session-id",
			jsonPath:       "$.session_id",
			fallbackToHash: true,
		},
		toolNamePath: "$.params.name",
		argsPath:     "$.params.arguments",
	}

	if v, ok := params["maxCalls"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 0 {
			return nil, wrap(fmt.Errorf("'maxCalls' must be a number >= 0"))
		}
		cfg.maxCalls = int(f)
	}
	if v, ok := params["maxTokens"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 0 {
			return nil, wrap(fmt.Errorf("'maxTokens' must be a number >= 0"))
		}
		cfg.maxTokens = int(f)
	}
	if v, ok := params["maxDurationSeconds"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 0 {
			return nil, wrap(fmt.Errorf("'maxDurationSeconds' must be a number >= 0"))
		}
		cfg.maxDurationSeconds = f
	}
	if v, ok := params["maxConsecutiveIdenticalToolCalls"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 0 {
			return nil, wrap(fmt.Errorf("'maxConsecutiveIdenticalToolCalls' must be a number >= 0"))
		}
		cfg.maxConsecutiveIdentical = int(f)
	}
	if v, ok := params["windowSeconds"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 1 {
			return nil, wrap(fmt.Errorf("'windowSeconds' must be a number >= 1"))
		}
		cfg.windowSeconds = f
	}
	if v, ok := params["onBreach"]; ok {
		s, _ := v.(string)
		if s != actionBlock && s != actionAnnotate {
			return nil, wrap(fmt.Errorf("'onBreach' must be block or annotate"))
		}
		cfg.onBreach = s
	}
	if err := boolParam(params, "showAssessment", &cfg.showAssessment); err != nil {
		return nil, wrap(err)
	}
	strOpt(params, "toolNameJsonPath", &cfg.toolNamePath)
	strOpt(params, "argumentsJsonPath", &cfg.argsPath)

	if raw, ok := params["sessionKey"]; ok {
		sk, ok := raw.(map[string]interface{})
		if !ok {
			return nil, wrap(fmt.Errorf("'sessionKey' must be an object"))
		}
		if v, ok := sk["header"]; ok {
			s, ok := v.(string)
			if !ok {
				return nil, wrap(fmt.Errorf("'sessionKey.header' must be a string"))
			}
			cfg.sessionKey.header = s // "" explicitly disables the header lookup
		}
		if v, ok := sk["jsonPath"]; ok {
			s, ok := v.(string)
			if !ok {
				return nil, wrap(fmt.Errorf("'sessionKey.jsonPath' must be a string"))
			}
			cfg.sessionKey.jsonPath = s
		}
		if err := boolParam(sk, "fallbackToHash", &cfg.sessionKey.fallbackToHash); err != nil {
			return nil, wrap(err)
		}
	}

	if cfg.maxCalls == 0 && cfg.maxTokens == 0 && cfg.maxDurationSeconds == 0 && cfg.maxConsecutiveIdentical == 0 {
		return nil, wrap(fmt.Errorf("at least one of maxCalls, maxTokens, maxDurationSeconds, maxConsecutiveIdenticalToolCalls must be greater than 0 - all zero disables the governor entirely"))
	}

	return &AgenticLoopBudgetGovernorPolicy{cfg: cfg, sessions: map[string]*sessionState{}}, nil
}

// Mode buffers the request body only; no response-phase inspection.
func (p *AgenticLoopBudgetGovernorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody updates the caller's session counters and enforces the
// configured ceilings.
func (p *AgenticLoopBudgetGovernorPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	var root interface{}
	_ = json.Unmarshal(body, &root) // best-effort; a non-JSON body still gets a call/token count

	sessKey := p.resolveSessionKey(reqCtx, root)
	toolName, toolKey := p.toolCallKey(root)
	now := time.Now()

	p.mu.Lock()
	st := p.sessions[sessKey]
	if st == nil || now.Sub(st.lastSeen).Seconds() > p.cfg.windowSeconds {
		st = &sessionState{firstSeen: now}
		p.sessions[sessKey] = st
		p.evictLocked(now)
	}
	st.lastSeen = now
	st.calls++
	st.tokens += estimateTokens(body)

	var breaches []string
	if p.cfg.maxCalls > 0 && st.calls > p.cfg.maxCalls {
		breaches = append(breaches, fmt.Sprintf("call count %d exceeds the session maximum of %d", st.calls, p.cfg.maxCalls))
	}
	if p.cfg.maxTokens > 0 && st.tokens > p.cfg.maxTokens {
		breaches = append(breaches, fmt.Sprintf("estimated token usage %d exceeds the session maximum of %d", st.tokens, p.cfg.maxTokens))
	}
	if dur := now.Sub(st.firstSeen).Seconds(); p.cfg.maxDurationSeconds > 0 && dur > p.cfg.maxDurationSeconds {
		breaches = append(breaches, fmt.Sprintf("session duration %.0fs exceeds the maximum of %.0fs", dur, p.cfg.maxDurationSeconds))
	}
	if toolKey != "" {
		if toolKey == st.lastToolKey {
			st.consecutiveIdentical++
		} else {
			st.lastToolKey = toolKey
			st.consecutiveIdentical = 1
		}
		if p.cfg.maxConsecutiveIdentical > 0 && st.consecutiveIdentical > p.cfg.maxConsecutiveIdentical {
			breaches = append(breaches, fmt.Sprintf("tool %q was called identically %d times in a row (limit %d) - possible stuck loop", toolName, st.consecutiveIdentical, p.cfg.maxConsecutiveIdentical))
		}
	}
	calls, tokens := st.calls, st.tokens
	p.mu.Unlock()

	if len(breaches) == 0 {
		if p.cfg.showAssessment {
			return policy.UpstreamRequestModifications{HeadersToSet: map[string]string{
				"x-loop-budget-calls":  strconv.Itoa(calls),
				"x-loop-budget-tokens": strconv.Itoa(tokens),
			}}
		}
		return policy.UpstreamRequestModifications{}
	}
	return p.breachAction(breaches)
}

func (p *AgenticLoopBudgetGovernorPolicy) breachAction(breaches []string) policy.RequestAction {
	if p.cfg.onBreach == actionAnnotate {
		return policy.UpstreamRequestModifications{
			HeadersToSet: map[string]string{
				"x-loop-budget":        "breach",
				"x-loop-budget-reason": breaches[0],
			},
			AnalyticsMetadata: map[string]any{
				"isGuardrailHit":     true,
				"guardrailName":      governorName,
				"direction":          "REQUEST",
				"loopBudgetBreaches": breaches,
			},
		}
	}
	msg := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": governorName,
		"direction":            "REQUEST",
		"actionReason":         "This session has exceeded its configured agent budget.",
	}
	if p.cfg.showAssessment {
		msg["assessments"] = breaches
	}
	b, _ := json.Marshal(map[string]interface{}{"type": governorType, "message": msg})
	return policy.ImmediateResponse{
		StatusCode: breachStatus,
		Headers:    map[string]string{"Content-Type": "application/json", "Retry-After": "60"},
		Body:       b,
		AnalyticsMetadata: map[string]any{
			"isGuardrailHit":     true,
			"guardrailName":      governorName,
			"direction":          "REQUEST",
			"loopBudgetBreaches": breaches,
		},
	}
}

// evictLocked bounds the session map: first drop anything past its own idle
// window, then - if still over the cap - drop the oldest entries by
// lastSeen. Must be called with p.mu held.
func (p *AgenticLoopBudgetGovernorPolicy) evictLocked(now time.Time) {
	if len(p.sessions) <= maxTrackedSessions {
		return
	}
	for k, st := range p.sessions {
		if now.Sub(st.lastSeen).Seconds() > p.cfg.windowSeconds {
			delete(p.sessions, k)
		}
	}
	if len(p.sessions) <= maxTrackedSessions {
		return
	}
	type kv struct {
		key      string
		lastSeen time.Time
	}
	all := make([]kv, 0, len(p.sessions))
	for k, st := range p.sessions {
		all = append(all, kv{k, st.lastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].lastSeen.Before(all[j].lastSeen) })
	excess := len(p.sessions) - maxTrackedSessions
	for i := 0; i < excess && i < len(all); i++ {
		delete(p.sessions, all[i].key)
	}
}

// ─── session identity ────────────────────────────────────────────────────────

// resolveSessionKey tries the configured header, then a body JSONPath, then
// (if enabled) a hash of the system prompt plus the caller's Authorization
// header. If none resolves, every such call shares one bucket rather than
// escaping budget enforcement entirely - an agent can't dodge the governor
// simply by omitting every session identifier.
func (p *AgenticLoopBudgetGovernorPolicy) resolveSessionKey(reqCtx *policy.RequestContext, root interface{}) string {
	if p.cfg.sessionKey.header != "" && reqCtx.Headers != nil {
		if vals := reqCtx.Headers.Get(p.cfg.sessionKey.header); len(vals) > 0 && strings.TrimSpace(vals[0]) != "" {
			return "h:" + vals[0]
		}
	}
	if p.cfg.sessionKey.jsonPath != "" {
		if s, ok := valueAt(root, p.cfg.sessionKey.jsonPath).(string); ok && s != "" {
			return "j:" + s
		}
	}
	if p.cfg.sessionKey.fallbackToHash {
		sys := firstSystemMessage(root)
		auth := ""
		if reqCtx.Headers != nil {
			if vals := reqCtx.Headers.Get("Authorization"); len(vals) > 0 {
				auth = vals[0]
			}
		}
		if sys != "" || auth != "" {
			sum := sha256.Sum256([]byte(sys + "\x00" + auth))
			return "f:" + hex.EncodeToString(sum[:])
		}
	}
	return "unidentified"
}

func firstSystemMessage(root interface{}) string {
	m, ok := root.(map[string]interface{})
	if !ok {
		return ""
	}
	if msgs, ok := m["messages"].([]interface{}); ok {
		for _, e := range msgs {
			em, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			if role, _ := em["role"].(string); strings.EqualFold(role, "system") {
				return stringifyContent(em["content"])
			}
		}
	}
	if s, ok := m["system"].(string); ok {
		return s
	}
	return ""
}

func stringifyContent(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []interface{}:
		var b strings.Builder
		for _, e := range t {
			if mm, ok := e.(map[string]interface{}); ok {
				if s, ok := mm["text"].(string); ok {
					b.WriteString(s)
					b.WriteByte('\n')
				}
			}
		}
		return b.String()
	default:
		return ""
	}
}

// toolCallKey returns the tool name and a canonical (name + arguments) key
// used to detect consecutive identical tool calls. encoding/json sorts map
// keys, so the marshaled arguments are a deterministic canonical form.
func (p *AgenticLoopBudgetGovernorPolicy) toolCallKey(root interface{}) (string, string) {
	name, _ := valueAt(root, p.cfg.toolNamePath).(string)
	if name == "" {
		return "", ""
	}
	args := valueAt(root, p.cfg.argsPath)
	canon, _ := json.Marshal(args)
	return name, name + "|" + string(canon)
}

// estimateTokens is a coarse chars/4 approximation - good enough for a
// budget ceiling, not meant to match a model's real tokenizer.
func estimateTokens(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	n := len(body) / 4
	if n < 1 {
		n = 1
	}
	return n
}

// ─── minimal JSONPath ────────────────────────────────────────────────────────

// valueAt resolves "$.a.b", "$.a[0].b", "$.a[-1]" against root.
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
