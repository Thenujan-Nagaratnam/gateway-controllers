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

// Package mcptoolintegrityguard verifies the integrity of an MCP server's
// advertised tool catalog against operator-pinned hashes (OWASP Agentic AI
// Top 10: ASI04 - Agentic Supply Chain Compromise). See policy-definition.yaml
// for the full behavior.
package mcptoolintegrityguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	guardrailCode = 502
	guardrailType = "MCP_TOOL_INTEGRITY_GUARD"
	guardrailName = "McpToolIntegrityGuard"

	modeEnforce  = "enforce"
	modeDiscover = "discover"

	actionStrip    = "strip"
	actionBlock    = "block"
	actionAnnotate = "annotate"
	actionAllow    = "allow"
)

var hashRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

type config struct {
	pinnedTools    map[string]string // tool name -> lowercase hex sha256
	mode           string
	onMismatch     string
	onUnknownTool  string
	toolsPath      string
	showAssessment bool
	passthrough    bool
}

// McpToolIntegrityGuardPolicy implements the v1alpha2 policy interface.
type McpToolIntegrityGuardPolicy struct{ cfg config }

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		pinnedTools:   map[string]string{},
		mode:          modeEnforce,
		onMismatch:    actionStrip,
		onUnknownTool: actionStrip,
		toolsPath:     "$.result.tools",
	}

	if raw, ok := params["pinnedTools"]; ok && raw != nil {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, wrap(fmt.Errorf("'pinnedTools' must be an object mapping tool name to a SHA-256 hex digest"))
		}
		for name, v := range m {
			hash, ok := v.(string)
			if !ok || !hashRe.MatchString(hash) {
				return nil, wrap(fmt.Errorf("'pinnedTools[%q]' must be a 64-character hex SHA-256 digest", name))
			}
			cfg.pinnedTools[name] = strings.ToLower(hash)
		}
	}

	if err := enumParam(params, "mode", []string{modeEnforce, modeDiscover}, &cfg.mode); err != nil {
		return nil, wrap(err)
	}
	if err := enumParam(params, "onMismatch", []string{actionStrip, actionBlock, actionAnnotate, actionAllow}, &cfg.onMismatch); err != nil {
		return nil, wrap(err)
	}
	if err := enumParam(params, "onUnknownTool", []string{actionStrip, actionBlock, actionAnnotate, actionAllow}, &cfg.onUnknownTool); err != nil {
		return nil, wrap(err)
	}
	strOpt(params, "resultToolsJsonPath", &cfg.toolsPath)
	if err := boolParam(params, "showAssessment", &cfg.showAssessment); err != nil {
		return nil, wrap(err)
	}
	if err := boolParam(params, "passthroughOnError", &cfg.passthrough); err != nil {
		return nil, wrap(err)
	}

	return &McpToolIntegrityGuardPolicy{cfg: cfg}, nil
}

// Mode buffers the response body only - this policy never touches requests.
func (p *McpToolIntegrityGuardPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

type toolFinding struct {
	name     string
	category string // "unknown_tool" | "hash_mismatch"
	action   string
	hash     string
}

// OnResponseBody checks every entry in the MCP tools/list result against the
// pinned catalog and strips/blocks/annotates per configuration.
func (p *McpToolIntegrityGuardPolicy) OnResponseBody(_ context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	var body []byte
	if respCtx.ResponseBody != nil {
		body = respCtx.ResponseBody.Content
	}

	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		if p.cfg.passthrough {
			return policy.DownstreamResponseModifications{}
		}
		return p.block(nil, "The response could not be parsed to locate the tool catalog.")
	}

	val := valueAt(root, p.cfg.toolsPath)
	if val == nil {
		// Not a tools/list-shaped response (e.g. tools/call, initialize) -
		// nothing for this policy to check, leave it alone.
		return policy.DownstreamResponseModifications{}
	}
	toolsArr, ok := val.([]interface{})
	if !ok {
		if p.cfg.passthrough {
			return policy.DownstreamResponseModifications{}
		}
		return p.block(nil, "The configured tools path did not resolve to an array.")
	}

	var (
		// Initialized non-nil (not "var survivors []interface{}") so that a
		// response where every tool gets stripped still marshals "tools" as
		// [] rather than null - a null tools array breaks MCP clients and
		// panics a naive `.([]interface{})` re-read of the rewritten body.
		survivors  = make([]interface{}, 0, len(toolsArr))
		findings   []toolFinding
		discovered []toolFinding
		blocked    []toolFinding
	)

	for _, entry := range toolsArr {
		tool, ok := entry.(map[string]interface{})
		if !ok {
			survivors = append(survivors, entry) // can't evaluate a malformed entry, leave as-is
			continue
		}
		name, _ := tool["name"].(string)
		hash := canonicalHash(tool)

		pinned, known := p.cfg.pinnedTools[name]
		var category, action string
		switch {
		case !known:
			category, action = "unknown_tool", p.cfg.onUnknownTool
		case pinned != hash:
			category, action = "hash_mismatch", p.cfg.onMismatch
		default:
			survivors = append(survivors, entry)
			continue
		}

		f := toolFinding{name: name, category: category, action: action, hash: hash}

		if p.cfg.mode == modeDiscover {
			discovered = append(discovered, f)
			survivors = append(survivors, entry) // discover mode never strips/blocks
			continue
		}

		switch action {
		case actionBlock:
			blocked = append(blocked, f)
			survivors = append(survivors, entry) // irrelevant once we block the whole response
		case actionStrip:
			findings = append(findings, f) // omitted from survivors
		case actionAnnotate:
			findings = append(findings, f)
			survivors = append(survivors, entry)
		default: // allow
			survivors = append(survivors, entry)
		}
	}

	if len(blocked) > 0 {
		reason := fmt.Sprintf("%d tool(s) failed integrity verification and this policy is configured to block on that finding.", len(blocked))
		return p.block(blocked, reason)
	}

	if p.cfg.mode == modeDiscover {
		if len(discovered) == 0 {
			return policy.DownstreamResponseModifications{}
		}
		meta := map[string]any{"guardrailName": guardrailName, "mode": "discover", "discoveredTools": discoveredMeta(discovered)}
		return policy.DownstreamResponseModifications{
			HeadersToSet:      map[string]string{"x-mcp-tool-integrity": "discover"},
			AnalyticsMetadata: meta,
		}
	}

	if len(findings) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	newBody := body
	if !setAt(root, p.cfg.toolsPath, survivors) {
		if p.cfg.passthrough {
			return policy.DownstreamResponseModifications{}
		}
		return p.block(nil, "A tool catalog rewrite was required but the response structure could not be updated.")
	}
	marshaled, err := json.Marshal(root)
	if err != nil {
		if p.cfg.passthrough {
			return policy.DownstreamResponseModifications{}
		}
		return p.block(nil, "A tool catalog rewrite was required but the response could not be re-serialized.")
	}
	newBody = marshaled

	stripped, annotated := splitByAction(findings)
	headers := map[string]string{"Content-Type": "application/json", "x-mcp-tool-integrity": "violation"}
	if len(stripped) > 0 {
		headers["x-mcp-tool-integrity-stripped"] = strings.Join(names(stripped), ",")
	}
	if len(annotated) > 0 {
		headers["x-mcp-tool-integrity-annotated"] = strings.Join(names(annotated), ",")
	}
	meta := map[string]any{"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "RESPONSE"}
	if p.cfg.showAssessment {
		meta["assessments"] = assessmentStrings(findings)
	}
	return policy.DownstreamResponseModifications{
		Body:              newBody,
		HeadersToSet:      headers,
		AnalyticsMetadata: meta,
	}
}

func (p *McpToolIntegrityGuardPolicy) block(findings []toolFinding, reason string) policy.ResponseAction {
	sc := guardrailCode
	msg := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": guardrailName,
		"direction":            "RESPONSE",
		"actionReason":         reason,
	}
	if len(findings) > 0 {
		msg["tools"] = names(findings) // which tool(s) triggered the block - unconditional, unlike the detailed assessments below
	}
	if p.cfg.showAssessment && len(findings) > 0 {
		msg["assessments"] = assessmentStrings(findings)
	}
	b, _ := json.Marshal(map[string]interface{}{"type": guardrailType, "message": msg})
	return policy.DownstreamResponseModifications{
		StatusCode:   &sc,
		HeadersToSet: map[string]string{"Content-Type": "application/json"},
		Body:         b,
		AnalyticsMetadata: map[string]any{
			"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "RESPONSE",
			"blockedTools": names(findings),
		},
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func canonicalHash(tool map[string]interface{}) string {
	c := map[string]interface{}{
		"name":        tool["name"],
		"description": tool["description"],
		"inputSchema": tool["inputSchema"],
	}
	b, _ := json.Marshal(c) // encoding/json sorts map keys, so this is deterministic
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func splitByAction(findings []toolFinding) (stripped, annotated []toolFinding) {
	for _, f := range findings {
		if f.action == actionStrip {
			stripped = append(stripped, f)
		} else {
			annotated = append(annotated, f)
		}
	}
	return
}

func names(findings []toolFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.name)
	}
	return out
}

func assessmentStrings(findings []toolFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, fmt.Sprintf("%s: %s (computed sha256=%s, action=%s)", f.name, f.category, f.hash, f.action))
	}
	return out
}

func discoveredMeta(findings []toolFinding) map[string]string {
	out := make(map[string]string, len(findings))
	for _, f := range findings {
		out[f.name] = f.hash
	}
	return out
}

// ─── minimal JSONPath: read + in-place write ─────────────────────────────────

func valueAt(root interface{}, jsonPath string) interface{} {
	cur := root
	for _, comp := range pathComponents(jsonPath) {
		key, idx, hasIdx := splitComponent(comp)
		if key != "" {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return nil
			}
			cur = m[key]
		}
		if hasIdx {
			a, ok := cur.([]interface{})
			if !ok {
				return nil
			}
			realIdx := idx
			if realIdx < 0 {
				realIdx = len(a) + realIdx
			}
			if realIdx < 0 || realIdx >= len(a) {
				return nil
			}
			cur = a[realIdx]
		}
	}
	return cur
}

// setAt writes newValue at jsonPath by mutating the last container (map or
// slice element) in place. root must have been produced by json.Unmarshal
// into interface{} (so every object along the path is a mutable
// map[string]interface{}). Returns false if the path can't be resolved.
func setAt(root interface{}, jsonPath string, newValue interface{}) bool {
	comps := pathComponents(jsonPath)
	if len(comps) == 0 {
		return false // replacing the root itself isn't supported
	}
	cur := root
	for i, comp := range comps {
		key, idx, hasIdx := splitComponent(comp)
		last := i == len(comps)-1

		if key != "" {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return false
			}
			if last && !hasIdx {
				m[key] = newValue
				return true
			}
			cur = m[key]
		}
		if hasIdx {
			a, ok := cur.([]interface{})
			if !ok {
				return false
			}
			realIdx := idx
			if realIdx < 0 {
				realIdx = len(a) + realIdx
			}
			if realIdx < 0 || realIdx >= len(a) {
				return false
			}
			if last {
				a[realIdx] = newValue
				return true
			}
			cur = a[realIdx]
		}
	}
	return false
}

func pathComponents(jsonPath string) []string {
	p := strings.TrimPrefix(strings.TrimPrefix(jsonPath, "$"), ".")
	if p == "" {
		return nil
	}
	parts := strings.Split(p, ".")
	out := make([]string, 0, len(parts))
	for _, c := range parts {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

func splitComponent(comp string) (key string, idx int, hasIdx bool) {
	key = comp
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
	return
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

func enumParam(m map[string]interface{}, k string, allowed []string, dst *string) error {
	v, ok := m[k]
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("'%s' must be a string", k)
	}
	for _, a := range allowed {
		if s == a {
			*dst = s
			return nil
		}
	}
	return fmt.Errorf("'%s' must be one of %v", k, allowed)
}
