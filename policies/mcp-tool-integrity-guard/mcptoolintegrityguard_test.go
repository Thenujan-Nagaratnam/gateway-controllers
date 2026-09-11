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

package mcptoolintegrityguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func hashOf(t *testing.T, name, desc string, schema map[string]interface{}) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"name": name, "description": desc, "inputSchema": schema})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func toolsListBody(t *testing.T, tools []map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1,
		"result": map[string]interface{}{"tools": tools},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func tool(name, desc string, schema map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"name": name, "description": desc, "inputSchema": schema}
}

func respCtx(body []byte) *policy.ResponseContext {
	return &policy.ResponseContext{ResponseBody: &policy.Body{Content: body, Present: true, EndOfStream: true}}
}

func asDownstream(t *testing.T, a policy.ResponseAction) policy.DownstreamResponseModifications {
	t.Helper()
	m, ok := a.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %#v", a)
	}
	return m
}

func toolsFromBody(t *testing.T, body []byte) []interface{} {
	t.Helper()
	var root map[string]interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	result, ok := root["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("no result object in body: %s", body)
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatalf("no tools array in body: %s", body)
	}
	return tools
}

var basicSchema = map[string]interface{}{"type": "object", "properties": map[string]interface{}{"x": map[string]interface{}{"type": "string"}}}

// ─── GetPolicy validation ────────────────────────────────────────────────────

func TestGetPolicy_DefaultsAreValid(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	if pp.cfg.mode != modeEnforce || pp.cfg.onMismatch != actionStrip || pp.cfg.onUnknownTool != actionStrip {
		t.Fatalf("unexpected defaults: %+v", pp.cfg)
	}
}

func TestGetPolicy_InvalidPinnedToolsType(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"pinnedTools": "not-an-object"})
	if err == nil {
		t.Fatal("expected error for non-object pinnedTools")
	}
}

func TestGetPolicy_InvalidHashFormat(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"pinnedTools": map[string]interface{}{"search": "not-a-hash"},
	})
	if err == nil {
		t.Fatal("expected error for malformed hash")
	}
}

func TestGetPolicy_InvalidMode(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"mode": "sometimes"})
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestGetPolicy_InvalidOnMismatch(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"onMismatch": "shrug"})
	if err == nil {
		t.Fatal("expected error for invalid onMismatch")
	}
}

// ─── matching tool passes through unchanged ──────────────────────────────────

func TestMatchingTool_PassesThroughUnmodified(t *testing.T) {
	h := hashOf(t, "search", "web search", basicSchema)
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"pinnedTools": map[string]interface{}{"search": h},
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body := toolsListBody(t, []map[string]interface{}{tool("search", "web search", basicSchema)})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	if m.Body != nil {
		t.Fatalf("expected no body rewrite for a clean tools/list, got %s", m.Body)
	}
}

// ─── unknown tool: strip (default) ───────────────────────────────────────────

func TestUnknownTool_DefaultStrip(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body := toolsListBody(t, []map[string]interface{}{
		tool("search", "web search", basicSchema),
		tool("delete_all", "danger", basicSchema),
	})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	if m.Body == nil {
		t.Fatal("expected a body rewrite stripping the unpinned tools")
	}
	tools := toolsFromBody(t, m.Body)
	if len(tools) != 0 {
		t.Fatalf("expected all tools stripped (none pinned), got %d", len(tools))
	}
	if m.HeadersToSet["x-mcp-tool-integrity"] != "violation" {
		t.Fatalf("expected violation header, got %+v", m.HeadersToSet)
	}
}

// ─── hash mismatch: strip ────────────────────────────────────────────────────

func TestHashMismatch_Strip(t *testing.T) {
	pinned := hashOf(t, "search", "web search", basicSchema)
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"pinnedTools": map[string]interface{}{"search": pinned},
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	// Description drifted from what was pinned - "rug pull" scenario.
	body := toolsListBody(t, []map[string]interface{}{
		tool("search", "web search AND execute arbitrary shell commands", basicSchema),
	})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	tools := toolsFromBody(t, m.Body)
	if len(tools) != 0 {
		t.Fatalf("expected mismatched tool stripped, got %d tools remaining", len(tools))
	}
}

// ─── onMismatch=block fails the whole response ───────────────────────────────

func TestHashMismatch_Block(t *testing.T) {
	pinned := hashOf(t, "search", "web search", basicSchema)
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"pinnedTools": map[string]interface{}{"search": pinned},
		"onMismatch":  "block",
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body := toolsListBody(t, []map[string]interface{}{
		tool("search", "web search PLUS a backdoor", basicSchema),
	})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	if m.StatusCode == nil || *m.StatusCode != guardrailCode {
		t.Fatalf("expected status %d, got %+v", guardrailCode, m.StatusCode)
	}
	var envelope map[string]interface{}
	if err := json.Unmarshal(m.Body, &envelope); err != nil {
		t.Fatalf("block body not valid JSON: %v", err)
	}
	if envelope["type"] != guardrailType {
		t.Fatalf("unexpected envelope type: %v", envelope["type"])
	}
	message, _ := envelope["message"].(map[string]interface{})
	tools, _ := message["tools"].([]interface{})
	if len(tools) != 1 || tools[0] != "search" {
		t.Fatalf("expected the blocking envelope to name the offending tool unconditionally (not gated on showAssessment), got %+v", message["tools"])
	}
}

// ─── onUnknownTool=annotate keeps the tool but flags it ─────────────────────

func TestUnknownTool_Annotate(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"onUnknownTool": "annotate"})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body := toolsListBody(t, []map[string]interface{}{tool("search", "web search", basicSchema)})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	tools := toolsFromBody(t, m.Body)
	if len(tools) != 1 {
		t.Fatalf("expected the annotated tool to remain in the list, got %d", len(tools))
	}
	if m.HeadersToSet["x-mcp-tool-integrity-annotated"] != "search" {
		t.Fatalf("expected annotated header naming 'search', got %+v", m.HeadersToSet)
	}
}

// ─── onUnknownTool=allow is a silent no-op ───────────────────────────────────

func TestUnknownTool_Allow(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"onUnknownTool": "allow"})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body := toolsListBody(t, []map[string]interface{}{tool("search", "web search", basicSchema)})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	if m.Body != nil {
		t.Fatalf("expected no rewrite when onUnknownTool=allow, got %s", m.Body)
	}
}

// ─── mode=discover never strips/blocks, reports hashes via analytics ────────

func TestDiscoverMode_NeverModifiesBody(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"mode": "discover"})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body := toolsListBody(t, []map[string]interface{}{
		tool("search", "web search", basicSchema),
		tool("delete_all", "danger", basicSchema),
	})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	if m.Body != nil {
		t.Fatalf("discover mode must never rewrite the body, got %s", m.Body)
	}
	if m.HeadersToSet["x-mcp-tool-integrity"] != "discover" {
		t.Fatalf("expected discover header, got %+v", m.HeadersToSet)
	}
	discovered, ok := m.AnalyticsMetadata["discoveredTools"].(map[string]string)
	if !ok || len(discovered) != 2 {
		t.Fatalf("expected 2 discovered tool hashes, got %+v", m.AnalyticsMetadata["discoveredTools"])
	}
}

// ─── multiple tools: mixed outcomes in one response ──────────────────────────

func TestMixedOutcomes_OnlyOffendingToolsAffected(t *testing.T) {
	pinnedSearch := hashOf(t, "search", "web search", basicSchema)
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"pinnedTools": map[string]interface{}{"search": pinnedSearch},
	})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body := toolsListBody(t, []map[string]interface{}{
		tool("search", "web search", basicSchema),     // matches pin - keep
		tool("rogue_tool", "not pinned", basicSchema), // unknown - strip (default)
	})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	tools := toolsFromBody(t, m.Body)
	if len(tools) != 1 {
		t.Fatalf("expected exactly the pinned tool to survive, got %d", len(tools))
	}
	survivor := tools[0].(map[string]interface{})
	if survivor["name"] != "search" {
		t.Fatalf("expected 'search' to survive, got %v", survivor["name"])
	}
}

// ─── non tools/list response passes through untouched ───────────────────────

func TestNonToolsListResponse_PassesThrough(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1,
		"result": map[string]interface{}{"content": []map[string]string{{"type": "text", "text": "42"}}},
	})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	if m.Body != nil {
		t.Fatalf("expected no modification for a non tools/list response, got %s", m.Body)
	}
}

// ─── malformed JSON body ──────────────────────────────────────────────────────

func TestMalformedBody_BlocksByDefault(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	a := pp.OnResponseBody(context.Background(), respCtx([]byte("not json")), nil)
	m := asDownstream(t, a)
	if m.StatusCode == nil || *m.StatusCode != guardrailCode {
		t.Fatalf("expected block on malformed body, got %+v", m)
	}
}

func TestMalformedBody_PassthroughOnError(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"passthroughOnError": true})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	a := pp.OnResponseBody(context.Background(), respCtx([]byte("not json")), nil)
	m := asDownstream(t, a)
	if m.StatusCode != nil {
		t.Fatalf("expected passthrough on malformed body, got status %v", *m.StatusCode)
	}
}

// ─── showAssessment surfaces detail only when enabled ────────────────────────

func TestShowAssessment_AddsDetailToAnalytics(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"showAssessment": true})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body := toolsListBody(t, []map[string]interface{}{tool("search", "web search", basicSchema)})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	if _, ok := m.AnalyticsMetadata["assessments"]; !ok {
		t.Fatal("expected assessments in AnalyticsMetadata when showAssessment=true")
	}
}

func TestShowAssessment_OffByDefault(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body := toolsListBody(t, []map[string]interface{}{tool("search", "web search", basicSchema)})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	if _, ok := m.AnalyticsMetadata["assessments"]; ok {
		t.Fatal("did not expect assessments in AnalyticsMetadata by default")
	}
}

// ─── custom resultToolsJsonPath ──────────────────────────────────────────────

func TestCustomResultToolsJsonPath(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"resultToolsJsonPath": "$.tools"})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body, _ := json.Marshal(map[string]interface{}{
		"tools": []map[string]interface{}{tool("rogue", "unpinned", basicSchema)},
	})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	if m.Body == nil {
		t.Fatal("expected rewrite via the custom tools path")
	}
	var root map[string]interface{}
	if err := json.Unmarshal(m.Body, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tools := root["tools"].([]interface{})
	if len(tools) != 0 {
		t.Fatalf("expected the unpinned tool stripped via custom path, got %d", len(tools))
	}
}

// ─── unresolvable custom path ─────────────────────────────────────────────────

func TestToolsPathWrongType_BlocksByDefault(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"resultToolsJsonPath": "$.result.tools"})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	pp := p.(*McpToolIntegrityGuardPolicy)
	body, _ := json.Marshal(map[string]interface{}{
		"result": map[string]interface{}{"tools": "not-an-array"},
	})
	a := pp.OnResponseBody(context.Background(), respCtx(body), nil)
	m := asDownstream(t, a)
	if m.StatusCode == nil || *m.StatusCode != guardrailCode {
		t.Fatalf("expected block when tools path resolves to a non-array, got %+v", m)
	}
}
