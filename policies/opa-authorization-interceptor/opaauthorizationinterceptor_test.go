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

package opaauthorizationinterceptor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newP(t *testing.T, params map[string]interface{}) *OpaAuthorizationInterceptorPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*OpaAuthorizationInterceptorPolicy)
}

// opaServer returns a server that responds with the given decision value at $.result,
// plus a pointer to a call counter and the last input document it received.
func opaServer(t *testing.T, result interface{}) (*httptest.Server, *int32, *map[string]interface{}) {
	t.Helper()
	var calls int32
	var lastInput map[string]interface{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		var in struct {
			Input map[string]interface{} `json:"input"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		lastInput = in.Input
		json.NewEncoder(w).Encode(map[string]interface{}{"result": result})
	}))
	t.Cleanup(s.Close)
	return s, &calls, &lastInput
}

func mcpBody(tool string, args map[string]interface{}, model string) []byte {
	m := map[string]interface{}{"params": map[string]interface{}{"name": tool, "arguments": args}}
	if model != "" {
		m["model"] = model
	}
	b, _ := json.Marshal(m)
	return b
}

func onReq(p *OpaAuthorizationInterceptorPolicy, body []byte, headers map[string]string) policy.RequestAction {
	h := policy.NewHeaders(nil)
	for k, v := range headers {
		h.UnsafeInternalValues()[strings.ToLower(k)] = []string{v}
	}
	return p.OnRequestBody(context.Background(), &policy.RequestContext{
		SharedContext: &policy.SharedContext{APIName: "acme-api", APIVersion: "v1"},
		Body:          &policy.Body{Content: body, Present: true},
		Headers:       h,
		Method:        "POST",
		Path:          "/mcp",
	}, nil)
}

func denied(t *testing.T, a policy.RequestAction, code int) policy.ImmediateResponse {
	t.Helper()
	ir, ok := a.(policy.ImmediateResponse)
	if !ok || ir.StatusCode != code {
		t.Fatalf("expected %d ImmediateResponse, got %T %+v", code, a, a)
	}
	return ir
}
func allowedAct(t *testing.T, a policy.RequestAction) policy.UpstreamRequestModifications {
	t.Helper()
	m, ok := a.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", a)
	}
	return m
}

// ─── GetPolicy ───────────────────────────────────────────────────────────────

func TestGetPolicy_OpaUrlRequired(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "'opaUrl' is required") {
		t.Fatalf("want opaUrl required, got %v", err)
	}
}
func TestGetPolicy_OpaUrlScheme(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"opaUrl": "ftp://opa/x"})
	if err == nil || !strings.Contains(err.Error(), "http(s)") {
		t.Fatalf("want scheme error, got %v", err)
	}
}
func TestGetPolicy_BadOnDeny(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"opaUrl": "http://opa", "onDeny": "kill"})
	if err == nil || !strings.Contains(err.Error(), "onDeny") {
		t.Fatalf("want onDeny error, got %v", err)
	}
}
func TestGetPolicy_BadDenyStatus(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"opaUrl": "http://opa", "denyStatusCode": 200.0})
	if err == nil || !strings.Contains(err.Error(), "denyStatusCode") {
		t.Fatalf("want denyStatusCode error, got %v", err)
	}
}

// ─── allow / deny ────────────────────────────────────────────────────────────

func TestAllow_Bool(t *testing.T) {
	srv, calls, _ := opaServer(t, true)
	p := newP(t, map[string]interface{}{"opaUrl": srv.URL})
	m := allowedAct(t, onReq(p, mcpBody("run_sql", map[string]interface{}{"q": "SELECT 1"}, "gpt-4o"), nil))
	if m.HeadersToSet["x-opa-authz"] != "allow" {
		t.Fatalf("want allow header, got %v", m.HeadersToSet)
	}
	if *calls != 1 {
		t.Fatalf("expected 1 OPA call, got %d", *calls)
	}
}

func TestDeny_Bool_403(t *testing.T) {
	srv, _, _ := opaServer(t, false)
	p := newP(t, map[string]interface{}{"opaUrl": srv.URL})
	ir := denied(t, onReq(p, mcpBody("run_sql", nil, ""), nil), 403)
	var env map[string]interface{}
	json.Unmarshal(ir.Body, &env)
	if env["type"] != guardrailType || env["message"].(map[string]interface{})["direction"] != "REQUEST" {
		t.Fatalf("envelope wrong: %s", ir.Body)
	}
}

func TestDeny_CustomStatus(t *testing.T) {
	srv, _, _ := opaServer(t, false)
	p := newP(t, map[string]interface{}{"opaUrl": srv.URL, "denyStatusCode": 401.0})
	denied(t, onReq(p, mcpBody("x", nil, ""), nil), 401)
}

func TestDecision_ObjectAllow(t *testing.T) {
	srv, _, _ := opaServer(t, map[string]interface{}{"allow": true})
	p := newP(t, map[string]interface{}{"opaUrl": srv.URL})
	allowedAct(t, onReq(p, mcpBody("x", nil, ""), nil))
}

func TestDecision_ObjectDenyWithReason_ShowAssessment(t *testing.T) {
	srv, _, _ := opaServer(t, map[string]interface{}{"allow": false, "reason": "refund exceeds ceiling"})
	p := newP(t, map[string]interface{}{"opaUrl": srv.URL, "showAssessment": true})
	ir := denied(t, onReq(p, mcpBody("issue_refund", map[string]interface{}{"amount": 9999}, ""), nil), 403)
	var env map[string]interface{}
	json.Unmarshal(ir.Body, &env)
	as := env["message"].(map[string]interface{})["assessments"].([]interface{})
	if len(as) == 0 || !strings.Contains(as[0].(string), "refund exceeds ceiling") {
		t.Fatalf("assessment should carry the opa reason: %v", as)
	}
}

func TestDecision_RedactObligation(t *testing.T) {
	srv, _, _ := opaServer(t, map[string]interface{}{"allow": true, "redact": []interface{}{"$.params.arguments.ssn"}})
	p := newP(t, map[string]interface{}{"opaUrl": srv.URL})
	body, _ := json.Marshal(map[string]interface{}{"params": map[string]interface{}{"name": "lookup", "arguments": map[string]interface{}{"ssn": "123-45-6789", "id": "x"}}})
	m := allowedAct(t, onReq(p, body, nil))
	if m.Body == nil || m.HeadersToSet["x-opa-authz"] != "allow-redacted" {
		t.Fatalf("want redacted forward, got headers %v", m.HeadersToSet)
	}
	var out map[string]interface{}
	json.Unmarshal(m.Body, &out)
	ssn := out["params"].(map[string]interface{})["arguments"].(map[string]interface{})["ssn"]
	if ssn == "123-45-6789" {
		t.Fatalf("ssn not redacted: %v", ssn)
	}
}

// ─── failure modes ───────────────────────────────────────────────────────────

func TestOpaUnreachable_FailClosed(t *testing.T) {
	p := newP(t, map[string]interface{}{"opaUrl": "http://127.0.0.1:1/x", "timeoutSeconds": 1.0})
	denied(t, onReq(p, mcpBody("x", nil, ""), nil), 403)
}
func TestOpaUnreachable_FailOpen(t *testing.T) {
	p := newP(t, map[string]interface{}{"opaUrl": "http://127.0.0.1:1/x", "timeoutSeconds": 1.0, "failOpen": true})
	m := allowedAct(t, onReq(p, mcpBody("x", nil, ""), nil))
	if m.HeadersToSet["x-opa-authz"] != "fail-open" {
		t.Fatalf("want fail-open header, got %v", m.HeadersToSet)
	}
}
func TestOpaNon2xx_FailClosed(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer s.Close()
	p := newP(t, map[string]interface{}{"opaUrl": s.URL})
	denied(t, onReq(p, mcpBody("x", nil, ""), nil), 403)
}
func TestOpaNonJSON_FailClosed(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not json")) }))
	defer s.Close()
	p := newP(t, map[string]interface{}{"opaUrl": s.URL})
	denied(t, onReq(p, mcpBody("x", nil, ""), nil), 403)
}
func TestDecisionPathUnresolved_FailClosed(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"nothing":1}`)) }))
	defer s.Close()
	p := newP(t, map[string]interface{}{"opaUrl": s.URL})
	denied(t, onReq(p, mcpBody("x", nil, ""), nil), 403)
}

// ─── onDeny annotate ─────────────────────────────────────────────────────────

func TestOnDenyAnnotate(t *testing.T) {
	srv, _, _ := opaServer(t, false)
	p := newP(t, map[string]interface{}{"opaUrl": srv.URL, "onDeny": "annotate"})
	m := allowedAct(t, onReq(p, mcpBody("x", nil, ""), nil))
	if m.HeadersToSet["x-opa-authz"] != "deny-annotated" {
		t.Fatalf("want deny-annotated header, got %v", m.HeadersToSet)
	}
}

// ─── input document ──────────────────────────────────────────────────────────

func TestInput_ClaimsToolModelHeaders(t *testing.T) {
	srv, _, lastInput := opaServer(t, true)
	p := newP(t, map[string]interface{}{
		"opaUrl": srv.URL,
		"input":  map[string]interface{}{"includeHeaders": []interface{}{"X-Tenant"}},
	})
	claims := map[string]interface{}{"sub": "agent-7", "org_id": "acme"}
	cb, _ := json.Marshal(claims)
	jwt := "h." + base64.RawURLEncoding.EncodeToString(cb) + ".s"

	onReq(p, mcpBody("issue_refund", map[string]interface{}{"amount": 10}, "gpt-4o"),
		map[string]string{"Authorization": "Bearer " + jwt, "X-Tenant": "acme"})

	in := *lastInput
	pr, _ := in["principal"].(map[string]interface{})
	if pr["sub"] != "agent-7" || pr["org_id"] != "acme" {
		t.Fatalf("principal claims not decoded: %v", in["principal"])
	}
	tool, _ := in["tool"].(map[string]interface{})
	if tool["name"] != "issue_refund" {
		t.Fatalf("tool name missing: %v", in["tool"])
	}
	if in["model"] != "gpt-4o" {
		t.Fatalf("model missing: %v", in["model"])
	}
	hdr, _ := in["headers"].(map[string]interface{})
	if hdr["x-tenant"] != "acme" {
		t.Fatalf("header not passed: %v", in["headers"])
	}
	rt, _ := in["route"].(map[string]interface{})
	if rt["api"] != "acme-api" || rt["method"] != "POST" || rt["path"] != "/mcp" {
		t.Fatalf("route wrong: %v", rt)
	}
}

// ─── cache ───────────────────────────────────────────────────────────────────

func TestCache_HitsOpaOnce(t *testing.T) {
	srv, calls, _ := opaServer(t, true)
	p := newP(t, map[string]interface{}{"opaUrl": srv.URL, "cacheTtlSeconds": 60.0})
	body := mcpBody("run_sql", map[string]interface{}{"q": "SELECT 1"}, "gpt-4o")
	allowedAct(t, onReq(p, body, nil))
	allowedAct(t, onReq(p, body, nil))
	allowedAct(t, onReq(p, body, nil))
	if *calls != 1 {
		t.Fatalf("cache should have collapsed 3 identical requests to 1 OPA call, got %d", *calls)
	}
}
