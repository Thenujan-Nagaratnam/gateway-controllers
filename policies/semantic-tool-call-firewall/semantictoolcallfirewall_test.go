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

package semantictoolcallfirewall

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newP(t *testing.T, params map[string]interface{}) *SemanticToolCallFirewallPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*SemanticToolCallFirewallPolicy)
}

func mcpCall(tool string, args map[string]interface{}) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{"name": tool, "arguments": args},
	})
	return b
}

func run(p *SemanticToolCallFirewallPolicy, body []byte) policy.RequestAction {
	return p.OnRequestBody(context.Background(), &policy.RequestContext{Body: &policy.Body{Content: body, Present: true}}, nil)
}

func blocked(t *testing.T, a policy.RequestAction) policy.ImmediateResponse {
	t.Helper()
	ir, ok := a.(policy.ImmediateResponse)
	if !ok || ir.StatusCode != firewallErrorCode {
		t.Fatalf("expected 422 ImmediateResponse, got %T %+v", a, a)
	}
	return ir
}
func allowed(t *testing.T, a policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	m, ok := a.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", a)
	}
	return m
}

func rule(m map[string]interface{}) map[string]interface{} { return m }

// ─── GetPolicy validation ────────────────────────────────────────────────────

func TestGetPolicy_NoRulesAllowDefault_Error(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "would do nothing") {
		t.Fatalf("want no-rules error, got %v", err)
	}
}
func TestGetPolicy_DefaultBlock_NoRulesOK(t *testing.T) {
	newP(t, map[string]interface{}{"defaultAction": "block"})
}
func TestGetPolicy_BadOnViolation(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"onViolation": "sanitize", "defaultAction": "block"})
	if err == nil || !strings.Contains(err.Error(), "onViolation") {
		t.Fatalf("want onViolation error, got %v", err)
	}
}
func TestGetPolicy_RuleWithoutToolName(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"rules": []interface{}{map[string]interface{}{"sql": map[string]interface{}{}}}})
	if err == nil || !strings.Contains(err.Error(), "toolName") {
		t.Fatalf("want toolName error, got %v", err)
	}
}
func TestGetPolicy_RuleWithNoConstraints(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"rules": []interface{}{map[string]interface{}{"toolName": "x"}}})
	if err == nil || !strings.Contains(err.Error(), "no constraints") {
		t.Fatalf("want no-constraints error, got %v", err)
	}
}
func TestGetPolicy_BadDenyPattern(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"rules": []interface{}{
		map[string]interface{}{"toolName": "x", "strings": []interface{}{map[string]interface{}{"argPath": "$.a", "denyPatterns": []interface{}{"("}}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "denyPatterns") {
		t.Fatalf("want denyPatterns compile error, got %v", err)
	}
}

// ─── SQL ─────────────────────────────────────────────────────────────────────

func sqlPolicy(t *testing.T, sql map[string]interface{}) *SemanticToolCallFirewallPolicy {
	return newP(t, map[string]interface{}{"rules": []interface{}{
		map[string]interface{}{"toolName": "run_sql", "sql": sql},
	}})
}

func TestSQL_SelectAllowed(t *testing.T) {
	p := sqlPolicy(t, map[string]interface{}{})
	allowed(t, run(p, mcpCall("run_sql", map[string]interface{}{"query": "SELECT * FROM users WHERE id = 1"})))
}
func TestSQL_DropDenied_AllowlistMode(t *testing.T) {
	p := sqlPolicy(t, map[string]interface{}{})
	ir := blocked(t, run(p, mcpCall("run_sql", map[string]interface{}{"query": "DROP TABLE users"})))
	var env map[string]interface{}
	json.Unmarshal(ir.Body, &env)
	if env["type"] != firewallType || env["jsonrpc"] != "2.0" {
		t.Fatalf("envelope shape wrong: %s", ir.Body)
	}
	if env["message"].(map[string]interface{})["direction"] != "REQUEST" {
		t.Fatalf("wrong direction")
	}
}
func TestSQL_DenylistMode(t *testing.T) {
	p := sqlPolicy(t, map[string]interface{}{"denyStatements": []interface{}{"UPDATE", "DELETE"}})
	allowed(t, run(p, mcpCall("run_sql", map[string]interface{}{"query": "INSERT INTO t VALUES (1)"}))) // not denied
	blocked(t, run(p, mcpCall("run_sql", map[string]interface{}{"query": "DELETE FROM t WHERE id=1"})))
}
func TestSQL_StackedStatements(t *testing.T) {
	p := sqlPolicy(t, map[string]interface{}{})
	blocked(t, run(p, mcpCall("run_sql", map[string]interface{}{"query": "SELECT 1; DROP TABLE t"})))
}
func TestSQL_UpdateNeedsWhere(t *testing.T) {
	p := sqlPolicy(t, map[string]interface{}{"allowStatements": []interface{}{"SELECT", "UPDATE"}})
	blocked(t, run(p, mcpCall("run_sql", map[string]interface{}{"query": "UPDATE users SET admin = true"})))
	allowed(t, run(p, mcpCall("run_sql", map[string]interface{}{"query": "UPDATE users SET admin = true WHERE id = 5"})))
}
func TestSQL_LeadingCommentStripped(t *testing.T) {
	p := sqlPolicy(t, map[string]interface{}{})
	blocked(t, run(p, mcpCall("run_sql", map[string]interface{}{"query": "-- harmless\n/* x */ DROP TABLE t"})))
}

// ─── URL ─────────────────────────────────────────────────────────────────────

func urlPolicy(t *testing.T, u map[string]interface{}) *SemanticToolCallFirewallPolicy {
	return newP(t, map[string]interface{}{"rules": []interface{}{
		map[string]interface{}{"toolName": "http_request", "url": u},
	}})
}

func TestURL_HTTPSAllowed(t *testing.T) {
	p := urlPolicy(t, map[string]interface{}{})
	allowed(t, run(p, mcpCall("http_request", map[string]interface{}{"url": "https://api.example.com/v1/data"})))
}
func TestURL_HTTPBlockedByScheme(t *testing.T) {
	p := urlPolicy(t, map[string]interface{}{})
	blocked(t, run(p, mcpCall("http_request", map[string]interface{}{"url": "http://api.example.com/x"})))
}
func TestURL_MetadataIPBlocked(t *testing.T) {
	p := urlPolicy(t, map[string]interface{}{"allowedSchemes": []interface{}{"http", "https"}})
	blocked(t, run(p, mcpCall("http_request", map[string]interface{}{"url": "http://169.254.169.254/latest/meta-data/"})))
}
func TestURL_PrivateIPBlocked(t *testing.T) {
	p := urlPolicy(t, map[string]interface{}{"allowedSchemes": []interface{}{"http", "https"}})
	blocked(t, run(p, mcpCall("http_request", map[string]interface{}{"url": "https://10.1.2.3/internal"})))
	blocked(t, run(p, mcpCall("http_request", map[string]interface{}{"url": "https://127.0.0.1:8080/"})))
}
func TestURL_PublicIPAllowed(t *testing.T) {
	p := urlPolicy(t, map[string]interface{}{})
	allowed(t, run(p, mcpCall("http_request", map[string]interface{}{"url": "https://8.8.8.8/"})))
}
func TestURL_Userinfo(t *testing.T) {
	p := urlPolicy(t, map[string]interface{}{})
	blocked(t, run(p, mcpCall("http_request", map[string]interface{}{"url": "https://user:pw@api.example.com/x"})))
}
func TestURL_AllowHosts(t *testing.T) {
	p := urlPolicy(t, map[string]interface{}{"allowHosts": []interface{}{"api.example.com"}})
	allowed(t, run(p, mcpCall("http_request", map[string]interface{}{"url": "https://api.example.com/x"})))
	blocked(t, run(p, mcpCall("http_request", map[string]interface{}{"url": "https://evil.example/x"})))
}
func TestURL_DenyHosts(t *testing.T) {
	p := urlPolicy(t, map[string]interface{}{"denyHosts": []interface{}{"evil.example"}})
	blocked(t, run(p, mcpCall("http_request", map[string]interface{}{"url": "https://evil.example/x"})))
}

// ─── strings / recipients / numbers ─────────────────────────────────────────

func TestStrings_MaxLenAndDeny(t *testing.T) {
	p := newP(t, map[string]interface{}{"rules": []interface{}{map[string]interface{}{
		"toolName": "note", "strings": []interface{}{map[string]interface{}{
			"argPath": "$.text", "maxLength": 10.0, "denyPatterns": []interface{}{"(?i)password"},
		}},
	}}})
	blocked(t, run(p, mcpCall("note", map[string]interface{}{"text": "this is way too long"})))
	blocked(t, run(p, mcpCall("note", map[string]interface{}{"text": "PASSWORD"})))
	allowed(t, run(p, mcpCall("note", map[string]interface{}{"text": "short ok"})))
}
func TestRecipients_DomainAllowlist(t *testing.T) {
	p := newP(t, map[string]interface{}{"rules": []interface{}{map[string]interface{}{
		"toolName": "send_email", "recipients": map[string]interface{}{
			"argPaths": []interface{}{"$.to", "$.cc"}, "allowDomains": []interface{}{"acme.com"},
		},
	}}})
	allowed(t, run(p, mcpCall("send_email", map[string]interface{}{"to": "bob@acme.com"})))
	blocked(t, run(p, mcpCall("send_email", map[string]interface{}{"to": "attacker@evil.example"})))
	blocked(t, run(p, mcpCall("send_email", map[string]interface{}{"cc": []interface{}{"ok@acme.com", "x@evil.example"}})))
}
func TestNumbers_MaxCeiling(t *testing.T) {
	p := newP(t, map[string]interface{}{"rules": []interface{}{map[string]interface{}{
		"toolName": "issue_refund", "numbers": []interface{}{map[string]interface{}{"argPath": "$.amount", "max": 500.0}},
	}}})
	allowed(t, run(p, mcpCall("issue_refund", map[string]interface{}{"amount": 120.0})))
	blocked(t, run(p, mcpCall("issue_refund", map[string]interface{}{"amount": 999999.0})))
}

// ─── routing / defaults / actions ────────────────────────────────────────────

func TestGlobRule_ExactWins(t *testing.T) {
	p := newP(t, map[string]interface{}{"rules": []interface{}{
		map[string]interface{}{"toolName": "db_*", "sql": map[string]interface{}{"allowStatements": []interface{}{"SELECT"}}},
		map[string]interface{}{"toolName": "db_admin", "sql": map[string]interface{}{"allowStatements": []interface{}{"SELECT", "DROP"}}},
	}})
	allowed(t, run(p, mcpCall("db_admin", map[string]interface{}{"query": "DROP TABLE t"})))       // exact rule
	blocked(t, run(p, mcpCall("db_reader", map[string]interface{}{"query": "DROP TABLE t"})))       // glob rule
}
func TestDefaultActionBlock_UnknownTool(t *testing.T) {
	p := newP(t, map[string]interface{}{"defaultAction": "block", "rules": []interface{}{
		map[string]interface{}{"toolName": "safe_tool", "strings": []interface{}{map[string]interface{}{"argPath": "$.x", "maxLength": 5.0}}},
	}})
	blocked(t, run(p, mcpCall("unlisted_tool", map[string]interface{}{})))
	allowed(t, run(p, mcpCall("safe_tool", map[string]interface{}{"x": "hi"})))
}
func TestAnnotateMode(t *testing.T) {
	p := newP(t, map[string]interface{}{"onViolation": "annotate", "rules": []interface{}{
		map[string]interface{}{"toolName": "run_sql", "sql": map[string]interface{}{}},
	}})
	m := allowed(t, run(p, mcpCall("run_sql", map[string]interface{}{"query": "DROP TABLE t"})))
	if m.HeadersToSet["x-tool-firewall"] != "violation" || !strings.Contains(m.HeadersToSet["x-tool-firewall-rules"], "sql") {
		t.Fatalf("annotate headers wrong: %v", m.HeadersToSet)
	}
}
func TestNonJSON_ErrorThenPassthrough(t *testing.T) {
	p := newP(t, map[string]interface{}{"defaultAction": "block"})
	blocked(t, run(p, []byte("not json")))
	p2 := newP(t, map[string]interface{}{"defaultAction": "block", "passthroughOnError": true})
	allowed(t, run(p2, []byte("not json")))
}
func TestMissingToolName_ErrorThenPassthrough(t *testing.T) {
	p := newP(t, map[string]interface{}{"defaultAction": "block"})
	blocked(t, run(p, []byte(`{"jsonrpc":"2.0","method":"ping"}`)))
	p2 := newP(t, map[string]interface{}{"defaultAction": "block", "passthroughOnError": true})
	allowed(t, run(p2, []byte(`{"jsonrpc":"2.0","method":"ping"}`)))
}
func TestShowAssessment(t *testing.T) {
	p := newP(t, map[string]interface{}{"showAssessment": true, "rules": []interface{}{
		map[string]interface{}{"toolName": "run_sql", "sql": map[string]interface{}{}},
	}})
	ir := blocked(t, run(p, mcpCall("run_sql", map[string]interface{}{"query": "DROP TABLE t"})))
	var env map[string]interface{}
	json.Unmarshal(ir.Body, &env)
	if _, ok := env["message"].(map[string]interface{})["assessments"]; !ok {
		t.Fatalf("showAssessment=true should include assessments: %s", ir.Body)
	}
}

// ─── custom jsonPaths (non-MCP shape) ───────────────────────────────────────

func TestCustomJsonPaths_OpenAIToolCall(t *testing.T) {
	p := newP(t, map[string]interface{}{
		"toolNameJsonPath":  "$.tool",
		"argumentsJsonPath": "$.args",
		"rules": []interface{}{map[string]interface{}{"toolName": "run_sql", "sql": map[string]interface{}{}}},
	})
	body, _ := json.Marshal(map[string]interface{}{"tool": "run_sql", "args": map[string]interface{}{"query": "TRUNCATE t"}})
	blocked(t, run(p, body))
}
