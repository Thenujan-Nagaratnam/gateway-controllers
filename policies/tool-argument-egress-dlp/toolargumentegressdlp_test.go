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

package toolargumentegressdlp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newP(t *testing.T, params map[string]interface{}) *ToolArgumentEgressDlpPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*ToolArgumentEgressDlpPolicy)
}

func mcp(args map[string]interface{}) []byte {
	b, _ := json.Marshal(map[string]interface{}{"params": map[string]interface{}{"name": "call_partner_api", "arguments": args}})
	return b
}

func run(p *ToolArgumentEgressDlpPolicy, body []byte) policy.RequestAction {
	return p.OnRequestBody(context.Background(), &policy.RequestContext{Body: &policy.Body{Content: body, Present: true}}, nil)
}
func blocked(t *testing.T, a policy.RequestAction) policy.ImmediateResponse {
	t.Helper()
	ir, ok := a.(policy.ImmediateResponse)
	if !ok || ir.StatusCode != dlpErrorCode {
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

// ─── GetPolicy ───────────────────────────────────────────────────────────────

func TestGetPolicy_NoDetectors(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"detectors": map[string]interface{}{
			"secrets": map[string]interface{}{"enabled": false},
			"pii":     map[string]interface{}{"enabled": false},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "no detectors") {
		t.Fatalf("want no-detectors error, got %v", err)
	}
}
func TestGetPolicy_BadOnDetected(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"onDetected": "scrub"})
	if err == nil || !strings.Contains(err.Error(), "onDetected") {
		t.Fatalf("want onDetected error, got %v", err)
	}
}
func TestGetPolicy_BadCustomPattern(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"customPatterns": []interface{}{map[string]interface{}{"name": "x", "regex": "("}},
	})
	if err == nil || !strings.Contains(err.Error(), "customPatterns[0].regex") {
		t.Fatalf("want regex compile error, got %v", err)
	}
}

// ─── secrets ─────────────────────────────────────────────────────────────────

func TestSecret_AWSAccessKey(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	blocked(t, run(p, mcp(map[string]interface{}{"note": "creds are AKIAIOSFODNN7EXAMPLE for the bucket"})))
}
func TestSecret_GithubToken(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	blocked(t, run(p, mcp(map[string]interface{}{"token": "ghp_" + strings.Repeat("a1B2c3D4", 5)})))
}
func TestSecret_PrivateKeyBlock(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	blocked(t, run(p, mcp(map[string]interface{}{"pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"})))
}
func TestSecret_JWT(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	blocked(t, run(p, mcp(map[string]interface{}{"auth": jwt})))
}
func TestSecret_DSNWithCreds(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	blocked(t, run(p, mcp(map[string]interface{}{"db": "postgres://admin:s3cr3tP@db.internal:5432/prod"})))
}
func TestSecret_HighEntropyToken(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	blocked(t, run(p, mcp(map[string]interface{}{"x": "kJ8sQv2LpZ0aWxYt7Rn4Bc1Md6Ef9Gh3Ij5Kl0Op"})))
}
func TestSecret_LowEntropyLongToken_NotFlagged(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	allowed(t, run(p, mcp(map[string]interface{}{"x": strings.Repeat("ab", 30)})))
}
func TestSecret_EntropyDisabled(t *testing.T) {
	p := newP(t, map[string]interface{}{
		"detectors": map[string]interface{}{"secrets": map[string]interface{}{"entropyEnabled": false}},
	})
	allowed(t, run(p, mcp(map[string]interface{}{"x": "kJ8sQv2LpZ0aWxYt7Rn4Bc1Md6Ef9Gh3Ij5Kl0Op"})))
}

// ─── PII ─────────────────────────────────────────────────────────────────────

func TestPII_SSN(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	blocked(t, run(p, mcp(map[string]interface{}{"customer": "SSN 123-45-6789"})))
}
func TestPII_LuhnValidCC_Blocked_InvalidNot(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	blocked(t, run(p, mcp(map[string]interface{}{"card": "4242 4242 4242 4242"}))) // Luhn-valid test number
	allowed(t, run(p, mcp(map[string]interface{}{"ref": "1234 5678 9012 3456"}))) // Luhn-invalid
}
func TestPII_IBAN(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	blocked(t, run(p, mcp(map[string]interface{}{"iban": "DE89370400440532013000"})))
}
func TestPII_EmailOnlyWhenCategoryEnabled(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	allowed(t, run(p, mcp(map[string]interface{}{"contact": "bob@example.com"}))) // default categories omit email
	p2 := newP(t, map[string]interface{}{
		"detectors": map[string]interface{}{"pii": map[string]interface{}{"categories": []interface{}{"email"}}},
	})
	blocked(t, run(p2, mcp(map[string]interface{}{"contact": "bob@example.com"})))
}

// ─── nesting / paths ─────────────────────────────────────────────────────────

func TestNestedArgs_PathReported(t *testing.T) {
	p := newP(t, map[string]interface{}{"showAssessment": true})
	ir := blocked(t, run(p, mcp(map[string]interface{}{
		"batch": []interface{}{
			map[string]interface{}{"key": "ok"},
			map[string]interface{}{"key": "AKIAIOSFODNN7EXAMPLE"},
		},
	})))
	var env map[string]interface{}
	json.Unmarshal(ir.Body, &env)
	as := env["message"].(map[string]interface{})["assessments"].([]interface{})
	if !strings.Contains(as[0].(map[string]interface{})["path"].(string), "batch[1].key") {
		t.Fatalf("path should point to the offending element: %v", as)
	}
}

func TestAdditionalJsonPaths(t *testing.T) {
	p := newP(t, map[string]interface{}{"additionalJsonPaths": []interface{}{"$.metadata"}})
	body, _ := json.Marshal(map[string]interface{}{
		"params":   map[string]interface{}{"name": "x", "arguments": map[string]interface{}{"ok": "hi"}},
		"metadata": map[string]interface{}{"note": "token ghp_" + strings.Repeat("z9Y8x7W6", 5)},
	})
	blocked(t, run(p, body))
}

// ─── actions ─────────────────────────────────────────────────────────────────

func TestRedact_RewritesArg(t *testing.T) {
	p := newP(t, map[string]interface{}{"onDetected": "redact"})
	m := allowed(t, run(p, mcp(map[string]interface{}{"db": "postgres://admin:s3cr3tP@db.internal:5432/prod", "keep": "value"})))
	if m.Body == nil || m.HeadersToSet["x-egress-dlp-action"] != "redacted" {
		t.Fatalf("want redacted rewrite, got headers %v", m.HeadersToSet)
	}
	var out map[string]interface{}
	json.Unmarshal(m.Body, &out)
	args := out["params"].(map[string]interface{})["arguments"].(map[string]interface{})
	if strings.Contains(args["db"].(string), "s3cr3tP") {
		t.Fatalf("secret not redacted: %v", args["db"])
	}
	if args["keep"] != "value" {
		t.Fatalf("non-secret arg altered: %v", args["keep"])
	}
}

func TestAnnotate_HeadersOnly(t *testing.T) {
	p := newP(t, map[string]interface{}{"onDetected": "annotate"})
	m := allowed(t, run(p, mcp(map[string]interface{}{"note": "AKIAIOSFODNN7EXAMPLE"})))
	if m.Body != nil {
		t.Fatal("annotate must not rewrite the body")
	}
	if m.HeadersToSet["x-egress-dlp"] != "hit" || !strings.Contains(m.HeadersToSet["x-egress-dlp-categories"], "secret") {
		t.Fatalf("annotate headers wrong: %v", m.HeadersToSet)
	}
}

func TestAllowValues_Skip(t *testing.T) {
	p := newP(t, map[string]interface{}{"allowValues": []interface{}{"AKIAIOSFODNN7EXAMPLE"}})
	allowed(t, run(p, mcp(map[string]interface{}{"note": "AKIAIOSFODNN7EXAMPLE"})))
}

func TestBenign_Allowed(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	m := allowed(t, run(p, mcp(map[string]interface{}{"query": "weather in Paris tomorrow", "limit": 5})))
	if m.Body != nil {
		t.Fatal("benign args should not be rewritten")
	}
}

func TestNonJSON_BlockThenPassthrough(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	blocked(t, run(p, []byte("<<not json")))
	p2 := newP(t, map[string]interface{}{"passthroughOnError": true})
	allowed(t, run(p2, []byte("<<not json")))
}

func TestOversize_BlockThenPassthrough(t *testing.T) {
	p := newP(t, map[string]interface{}{"maxScanBytes": 1024.0})
	big := mcp(map[string]interface{}{"x": strings.Repeat("word ", 400)})
	blocked(t, run(p, big))
	p2 := newP(t, map[string]interface{}{"maxScanBytes": 1024.0, "passthroughOnError": true})
	allowed(t, run(p2, big))
}

func TestShowAssessment_MasksSecret(t *testing.T) {
	p := newP(t, map[string]interface{}{"showAssessment": true})
	ir := blocked(t, run(p, mcp(map[string]interface{}{"note": "AKIAIOSFODNN7EXAMPLE"})))
	if strings.Contains(string(ir.Body), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("assessment must NOT contain the raw secret: %s", ir.Body)
	}
}

// ─── custom patterns ────────────────────────────────────────────────────────

func TestCustomPattern(t *testing.T) {
	p := newP(t, map[string]interface{}{
		"customPatterns": []interface{}{map[string]interface{}{"name": "internalId", "regex": `INT-\d{6}`, "category": "internal"}},
	})
	ir := blocked(t, run(p, mcp(map[string]interface{}{"ref": "see INT-459201"})))
	if !strings.Contains(string(ir.Body), "internal") {
		t.Fatalf("custom category missing: %s", ir.Body)
	}
}
