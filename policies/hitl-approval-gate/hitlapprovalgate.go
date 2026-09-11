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

// Package hitlapprovalgate is a human-in-the-loop approval checkpoint for
// high-risk agent tool calls (Agentic AI T2 Tool Misuse / T3 Privilege
// Compromise, OWASP LLM06 Excessive Agency). See policy-definition.yaml for
// the full three-step flow (pending -> decision -> approved retry).
package hitlapprovalgate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	gateType = "HITL_APPROVAL_GATE"
	gateName = "HitlApprovalGate"

	statusPending = "pending"
	statusApprove = "approve"
	statusDeny    = "deny"

	// maxTrackedApprovals bounds the in-process state map so a flood of
	// high-risk tool calls can't grow it without bound.
	maxTrackedApprovals = 20000

	notifyMaxRespBytes = 1 << 16
)

// ─── config ──────────────────────────────────────────────────────────────────

type config struct {
	highRisk             []string // literal names or '*'/'?' globs, matched case-sensitively
	approverSecret       string
	approverSecretHeader string
	approvalTokenHeader  string
	decisionMarkerPath   string
	toolNamePath         string
	argsPath             string
	expiry               time.Duration
	notifyURL            string
	notifyTimeout        time.Duration
	pendingStatus        int
	includeArguments     bool
}

type approvalRecord struct {
	id        string
	toolName  string
	argsHash  string
	status    string
	approver  string
	reason    string
	createdAt time.Time
	decidedAt time.Time
	expiresAt time.Time
}

// HitlApprovalGatePolicy implements the v1alpha2 policy interface.
type HitlApprovalGatePolicy struct {
	cfg    config
	client *http.Client

	mu      sync.Mutex
	pending map[string]*approvalRecord
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		approverSecretHeader: "x-approver-secret",
		approvalTokenHeader:  "x-approval-token",
		decisionMarkerPath:   "$.approvalDecision",
		toolNamePath:         "$.params.name",
		argsPath:             "$.params.arguments",
		expiry:               300 * time.Second,
		notifyTimeout:        5 * time.Second,
		pendingStatus:        403,
	}

	raw, ok := params["highRiskTools"].([]interface{})
	if !ok || len(raw) == 0 {
		return nil, wrap(fmt.Errorf("'highRiskTools' must be a non-empty array of tool names/globs"))
	}
	for _, e := range raw {
		s, ok := e.(string)
		if !ok || s == "" {
			return nil, wrap(fmt.Errorf("'highRiskTools' entries must be non-empty strings"))
		}
		cfg.highRisk = append(cfg.highRisk, s)
	}

	secret, ok := params["approverSecret"].(string)
	if !ok || len(secret) < 16 {
		return nil, wrap(fmt.Errorf("'approverSecret' is required and must be at least 16 characters - there is no default"))
	}
	cfg.approverSecret = secret

	strOpt(params, "approverSecretHeader", &cfg.approverSecretHeader)
	strOpt(params, "approvalTokenHeader", &cfg.approvalTokenHeader)
	strOpt(params, "decisionMarkerPath", &cfg.decisionMarkerPath)
	strOpt(params, "toolNameJsonPath", &cfg.toolNamePath)
	strOpt(params, "argumentsJsonPath", &cfg.argsPath)

	if v, ok := params["expirySeconds"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 30 {
			return nil, wrap(fmt.Errorf("'expirySeconds' must be a number >= 30"))
		}
		cfg.expiry = time.Duration(f * float64(time.Second))
	}
	if v, ok := params["notifyUrl"]; ok {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, wrap(fmt.Errorf("'notifyUrl' must be a non-empty string"))
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, wrap(fmt.Errorf("'notifyUrl' must be a valid http(s) URL"))
		}
		cfg.notifyURL = s
	}
	if v, ok := params["notifyTimeoutSeconds"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 1 {
			return nil, wrap(fmt.Errorf("'notifyTimeoutSeconds' must be a number >= 1"))
		}
		cfg.notifyTimeout = time.Duration(f * float64(time.Second))
	}
	if v, ok := params["pendingStatusCode"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 400 || f > 599 {
			return nil, wrap(fmt.Errorf("'pendingStatusCode' must be an HTTP status code in [400,599]"))
		}
		cfg.pendingStatus = int(f)
	}
	if err := boolParam(params, "includeArguments", &cfg.includeArguments); err != nil {
		return nil, wrap(err)
	}

	return &HitlApprovalGatePolicy{
		cfg:     cfg,
		client:  &http.Client{Timeout: cfg.notifyTimeout},
		pending: map[string]*approvalRecord{},
	}, nil
}

// Mode buffers the request body only; no response-phase inspection.
func (p *HitlApprovalGatePolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody dispatches to the decision path or the tool-call gate,
// depending on whether the body carries a decisionMarkerPath object.
func (p *HitlApprovalGatePolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	var root interface{}
	_ = json.Unmarshal(body, &root)

	if dec, ok := valueAt(root, p.cfg.decisionMarkerPath).(map[string]interface{}); ok {
		return p.handleDecision(reqCtx, dec)
	}
	return p.handleToolCall(reqCtx, root)
}

// ─── tool-call gating ────────────────────────────────────────────────────────

func (p *HitlApprovalGatePolicy) handleToolCall(reqCtx *policy.RequestContext, root interface{}) policy.RequestAction {
	name, _ := valueAt(root, p.cfg.toolNamePath).(string)
	if name == "" || !p.matchesHighRisk(name) {
		return policy.UpstreamRequestModifications{}
	}
	args := valueAt(root, p.cfg.argsPath)
	argsHash := hashArgs(name, args)

	if token := headerValue(reqCtx, p.cfg.approvalTokenHeader); token != "" {
		p.mu.Lock()
		rec := p.pending[token]
		now := time.Now()
		if rec != nil && rec.argsHash == argsHash && now.Before(rec.expiresAt) {
			switch rec.status {
			case statusApprove:
				delete(p.pending, token) // single-use: consume on the forwarded call
				p.mu.Unlock()
				return policy.UpstreamRequestModifications{
					HeadersToSet: map[string]string{"x-hitl-approved": "true", "x-hitl-approval-id": token},
					AnalyticsMetadata: map[string]any{
						"guardrailName": gateName, "hitlTool": name, "hitlApprovalId": token, "hitlDecision": "approved",
					},
				}
			case statusDeny:
				delete(p.pending, token) // single-use: a denial doesn't get retried with the same token
				p.mu.Unlock()
				return p.blockAction("APPROVAL_DENIED", "This action was reviewed and denied.", name, token, rec.expiresAt)
			default: // still pending
				p.mu.Unlock()
				return p.blockAction("PENDING_APPROVAL", "This action requires human approval and is still awaiting a decision.", name, token, rec.expiresAt)
			}
		}
		p.mu.Unlock()
		// Unknown, expired, or the call changed since approval was requested -
		// fall through and mint a fresh approval for what's actually being asked now.
	}

	id, err := newApprovalID()
	if err != nil {
		slog.Warn("HitlApprovalGate: failed to generate an approval id", "error", err.Error())
		return p.blockAction("PENDING_APPROVAL", "This action requires human approval.", name, "", time.Time{})
	}
	now := time.Now()
	rec := &approvalRecord{
		id: id, toolName: name, argsHash: argsHash, status: statusPending,
		createdAt: now, expiresAt: now.Add(p.cfg.expiry),
	}
	p.mu.Lock()
	p.pending[id] = rec
	p.evictLocked(now)
	p.mu.Unlock()

	if p.cfg.notifyURL != "" {
		go p.notify(rec, args) // best-effort, never blocks the pending response
	}

	return p.blockAction("PENDING_APPROVAL", "This action requires human approval before it can proceed.", name, id, rec.expiresAt)
}

func (p *HitlApprovalGatePolicy) matchesHighRisk(name string) bool {
	for _, pattern := range p.cfg.highRisk {
		if pattern == name {
			return true
		}
		if strings.ContainsAny(pattern, "*?") && globMatch(pattern, name) {
			return true
		}
	}
	return false
}

func (p *HitlApprovalGatePolicy) blockAction(action, reason, tool, approvalID string, expiresAt time.Time) policy.RequestAction {
	msg := map[string]interface{}{
		"action":               action,
		"interveningGuardrail": gateName,
		"direction":            "REQUEST",
		"actionReason":         reason,
		"tool":                 tool,
	}
	if approvalID != "" {
		msg["approvalId"] = approvalID
		msg["approvalTokenHeader"] = p.cfg.approvalTokenHeader
	}
	if !expiresAt.IsZero() {
		msg["expiresAt"] = expiresAt.UTC().Format(time.RFC3339)
	}
	b, _ := json.Marshal(map[string]interface{}{"type": gateType, "message": msg})
	return policy.ImmediateResponse{
		StatusCode: p.cfg.pendingStatus,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       b,
		AnalyticsMetadata: map[string]any{
			"isGuardrailHit": true, "guardrailName": gateName, "direction": "REQUEST",
			"hitlTool": tool, "hitlAction": action,
		},
	}
}

// ─── decision submission ─────────────────────────────────────────────────────

func (p *HitlApprovalGatePolicy) handleDecision(reqCtx *policy.RequestContext, dec map[string]interface{}) policy.RequestAction {
	presented := headerValue(reqCtx, p.cfg.approverSecretHeader)
	if !constantTimeEqual(presented, p.cfg.approverSecret) {
		// Generic, identical response whether the secret was missing or wrong -
		// never confirm/deny anything about the approvalId itself at this gate.
		return policy.ImmediateResponse{
			StatusCode: 403,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       mustJSON(map[string]interface{}{"type": gateType, "message": map[string]interface{}{"action": "DECISION_REJECTED", "interveningGuardrail": gateName, "actionReason": "unauthorized"}}),
		}
	}

	id, _ := dec["approvalId"].(string)
	decision, _ := dec["decision"].(string)
	approver, _ := dec["approver"].(string)
	reason, _ := dec["reason"].(string)
	if id == "" || (decision != statusApprove && decision != statusDeny) {
		return policy.ImmediateResponse{
			StatusCode: 400,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       mustJSON(map[string]interface{}{"type": gateType, "message": map[string]interface{}{"action": "DECISION_INVALID", "interveningGuardrail": gateName, "actionReason": "approvalId and decision (approve|deny) are required"}}),
		}
	}

	p.mu.Lock()
	rec := p.pending[id]
	found := rec != nil && time.Now().Before(rec.expiresAt)
	if found {
		rec.status = decision
		rec.approver = approver
		rec.reason = reason
		rec.decidedAt = time.Now()
	}
	p.mu.Unlock()

	status := "recorded"
	if !found {
		status = "not_found_or_expired"
	}
	return policy.ImmediateResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body: mustJSON(map[string]interface{}{"type": gateType, "message": map[string]interface{}{
			"action": "DECISION_" + strings.ToUpper(status), "interveningGuardrail": gateName, "approvalId": id, "decision": decision,
		}}),
		AnalyticsMetadata: map[string]any{"guardrailName": gateName, "hitlDecisionRecorded": found, "hitlApprovalId": id},
	}
}

// ─── notify (best-effort) ─────────────────────────────────────────────────────

func (p *HitlApprovalGatePolicy) notify(rec *approvalRecord, args interface{}) {
	payload := map[string]interface{}{
		"approvalId":  rec.id,
		"tool":        rec.toolName,
		"requestedAt": rec.createdAt.UTC().Format(time.RFC3339),
		"expiresAt":   rec.expiresAt.UTC().Format(time.RFC3339),
	}
	if p.cfg.includeArguments {
		payload["arguments"] = args
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, p.cfg.notifyURL, strings.NewReader(string(b)))
	if err != nil {
		slog.Warn("HitlApprovalGate: failed to build notify request", "error", err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		slog.Warn("HitlApprovalGate: notify webhook unreachable", "error", err.Error())
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, notifyMaxRespBytes))
	if resp.StatusCode >= 300 {
		slog.Warn("HitlApprovalGate: notify webhook returned a non-2xx status", "status", resp.StatusCode)
	}
}

// ─── state bounding ──────────────────────────────────────────────────────────

// evictLocked bounds the pending map: first drop anything past its own
// expiry, then - if still over the cap - drop the oldest by createdAt. Must
// be called with p.mu held.
func (p *HitlApprovalGatePolicy) evictLocked(now time.Time) {
	if len(p.pending) <= maxTrackedApprovals {
		return
	}
	for k, r := range p.pending {
		if now.After(r.expiresAt) {
			delete(p.pending, k)
		}
	}
	if len(p.pending) <= maxTrackedApprovals {
		return
	}
	type kv struct {
		key       string
		createdAt time.Time
	}
	all := make([]kv, 0, len(p.pending))
	for k, r := range p.pending {
		all = append(all, kv{k, r.createdAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].createdAt.Before(all[j].createdAt) })
	excess := len(p.pending) - maxTrackedApprovals
	for i := 0; i < excess && i < len(all); i++ {
		delete(p.pending, all[i].key)
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func newApprovalID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashArgs canonicalizes (tool name + arguments) into a comparable digest -
// encoding/json sorts map keys, so the marshaled form is deterministic.
func hashArgs(name string, args interface{}) string {
	canon, _ := json.Marshal(args)
	sum := sha256.Sum256([]byte(name + "\x00" + string(canon)))
	return hex.EncodeToString(sum[:])
}

func constantTimeEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func headerValue(reqCtx *policy.RequestContext, name string) string {
	if name == "" || reqCtx.Headers == nil {
		return ""
	}
	if vals := reqCtx.Headers.Get(name); len(vals) > 0 {
		return strings.TrimSpace(vals[0])
	}
	return ""
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// globMatch supports '*' (any run) and '?' (single char) against name.
func globMatch(pattern, name string) bool {
	return globMatchRec([]rune(pattern), []rune(name))
}

func globMatchRec(p, s []rune) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for len(p) > 0 && p[0] == '*' {
				p = p[1:]
			}
			if len(p) == 0 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globMatchRec(p, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			if len(s) == 0 || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return len(s) == 0
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
