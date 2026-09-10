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

package structuredoutputschemarepair

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const objSchema = `{"type":"object","required":["name","age"],"properties":{"name":{"type":"string"},"age":{"type":"integer"}},"additionalProperties":false}`

func newP(t *testing.T, params map[string]interface{}) *StructuredOutputSchemaRepairPolicy {
	t.Helper()
	if _, ok := params["schema"]; !ok {
		params["schema"] = objSchema
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*StructuredOutputSchemaRepairPolicy)
}

func reply(content string) []byte {
	b, _ := json.Marshal(map[string]interface{}{"choices": []interface{}{
		map[string]interface{}{"message": map[string]interface{}{"role": "assistant", "content": content}}}})
	return b
}

func onResp(p *StructuredOutputSchemaRepairPolicy, body []byte) policy.DownstreamResponseModifications {
	a := p.OnResponseBody(context.Background(), &policy.ResponseContext{ResponseBody: &policy.Body{Content: body, Present: true}}, nil)
	m, ok := a.(policy.DownstreamResponseModifications)
	if !ok {
		panic("unexpected action type")
	}
	return m
}

func replyContentOf(t *testing.T, body []byte) string {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	return out["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"].(string)
}

// ─── GetPolicy validation ────────────────────────────────────────────────────

func TestGetPolicy_SchemaRequired(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "'schema' is required") {
		t.Fatalf("want schema-required, got %v", err)
	}
}
func TestGetPolicy_InvalidSchema(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"schema": `{"type": 123}`})
	if err == nil || !strings.Contains(err.Error(), "not a valid JSON Schema") {
		t.Fatalf("want invalid-schema, got %v", err)
	}
}
func TestGetPolicy_BadOnFail(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"schema": objSchema, "onFail": "explode"})
	if err == nil || !strings.Contains(err.Error(), "onFail") {
		t.Fatalf("want onFail error, got %v", err)
	}
}
func TestGetPolicy_RepairNeedsEndpoint(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"schema": objSchema, "repair": map[string]interface{}{"enabled": true}})
	if err == nil || !strings.Contains(err.Error(), "repair.endpoint") {
		t.Fatalf("want repair.endpoint error, got %v", err)
	}
}
func TestGetPolicy_RepairEndpointScheme(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"schema": objSchema, "repair": map[string]interface{}{"enabled": true, "endpoint": "ftp://x/y"}})
	if err == nil || !strings.Contains(err.Error(), "http(s)") {
		t.Fatalf("want scheme error, got %v", err)
	}
}

// ─── clean / deterministic ───────────────────────────────────────────────────

func TestClean_NoRewrite(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	m := onResp(p, reply(`{"name":"Ada","age":36}`))
	if m.Body != nil {
		t.Fatal("clean JSON must not be rewritten")
	}
	if m.HeadersToSet["x-schema-repair"] != "clean" {
		t.Fatalf("want x-schema-repair: clean, got %v", m.HeadersToSet)
	}
}

func TestDeterministic_Fences(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	m := onResp(p, reply("```json\n{\"name\":\"Ada\",\"age\":36}\n```"))
	if m.Body == nil || m.HeadersToSet["x-schema-repair"] != "deterministic" {
		t.Fatalf("want deterministic rewrite, got headers %v body!=nil %v", m.HeadersToSet, m.Body != nil)
	}
	if c := replyContentOf(t, m.Body); c != `{"name":"Ada","age":36}` {
		t.Fatalf("fences not stripped cleanly: %q", c)
	}
}

func TestDeterministic_TrailingCommaAndProse(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	m := onResp(p, reply("Sure, here you go:\n{\"name\":\"Ada\",\"age\":36,}\nhope that helps!"))
	if m.Body == nil {
		t.Fatal("want deterministic rewrite")
	}
	var v map[string]interface{}
	if err := json.Unmarshal([]byte(replyContentOf(t, m.Body)), &v); err != nil {
		t.Fatalf("repaired content not valid JSON: %v", err)
	}
}

func TestDeterministic_Disabled(t *testing.T) {
	p := newP(t, map[string]interface{}{"deterministicRepair": false})
	m := onResp(p, reply("```json\n{\"name\":\"Ada\",\"age\":36}\n```"))
	if m.StatusCode == nil || *m.StatusCode != failStatusCode {
		t.Fatalf("deterministic disabled + fenced -> should fail, got %+v", m)
	}
}

// ─── schema failure / onFail ─────────────────────────────────────────────────

func TestFail_Block(t *testing.T) {
	p := newP(t, map[string]interface{}{"showAssessment": true})
	m := onResp(p, reply(`{"name":"Ada"}`)) // missing required age
	if m.StatusCode == nil || *m.StatusCode != failStatusCode {
		t.Fatalf("want 502, got %+v", m)
	}
	var env map[string]interface{}
	json.Unmarshal(m.Body, &env)
	if env["type"] != guardrailType {
		t.Fatalf("wrong type %v", env["type"])
	}
	msg := env["message"].(map[string]interface{})
	if msg["direction"] != "RESPONSE" || msg["assessments"] == nil {
		t.Fatalf("envelope missing fields: %v", msg)
	}
}

func TestFail_Passthrough(t *testing.T) {
	p := newP(t, map[string]interface{}{"onFail": "passthrough"})
	m := onResp(p, reply(`{"name":"Ada"}`))
	if m.StatusCode != nil {
		t.Fatal("passthrough must not set a status")
	}
	if m.HeadersToSet["x-schema-repair"] != "failed" {
		t.Fatalf("want x-schema-repair: failed, got %v", m.HeadersToSet)
	}
}

func TestFail_EmptyObject(t *testing.T) {
	p := newP(t, map[string]interface{}{"onFail": "emptyObject"})
	m := onResp(p, reply(`{"name":"Ada","extra":true}`)) // additionalProperties=false -> invalid
	if m.Body == nil {
		t.Fatal("emptyObject should rewrite body")
	}
	if c := strings.TrimSpace(replyContentOf(t, m.Body)); c != "{}" {
		t.Fatalf("want emptied {}, got %q", c)
	}
}

func TestNonJSONBody_BlockThenPassthrough(t *testing.T) {
	p := newP(t, map[string]interface{}{})
	m := onResp(p, []byte("<<not json"))
	if m.StatusCode == nil {
		t.Fatal("non-JSON body should fail")
	}
	p2 := newP(t, map[string]interface{}{"passthroughOnError": true})
	m2 := onResp(p2, []byte("<<not json"))
	if m2.StatusCode != nil || m2.Body != nil {
		t.Fatal("passthroughOnError should forward")
	}
}

func TestObjectValuedContent(t *testing.T) {
	// content is already an object, not a string
	p := newP(t, map[string]interface{}{})
	body, _ := json.Marshal(map[string]interface{}{"choices": []interface{}{
		map[string]interface{}{"message": map[string]interface{}{"content": map[string]interface{}{"name": "Ada", "age": 36}}}}})
	m := onResp(p, body)
	if m.HeadersToSet["x-schema-repair"] != "clean" {
		t.Fatalf("object-valued clean content should be 'clean', got %v", m.HeadersToSet)
	}
}

// ─── LLM repair ──────────────────────────────────────────────────────────────

func TestLLMRepair_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// return a corrected doc
		json.NewEncoder(w).Encode(map[string]interface{}{"choices": []interface{}{
			map[string]interface{}{"message": map[string]interface{}{"content": `{"name":"Ada","age":36}`}}}})
	}))
	defer srv.Close()

	p := newP(t, map[string]interface{}{
		"deterministicRepair": false,
		"repair":              map[string]interface{}{"enabled": true, "endpoint": srv.URL},
	})
	m := onResp(p, reply(`the answer is name Ada age thirty-six`)) // unrepairable deterministically
	if m.Body == nil || m.HeadersToSet["x-schema-repair"] != "llm" {
		t.Fatalf("want llm-stage rewrite, got headers %v", m.HeadersToSet)
	}
	if c := replyContentOf(t, m.Body); c != `{"name":"Ada","age":36}` {
		t.Fatalf("llm repair content wrong: %q", c)
	}
}

func TestLLMRepair_StillInvalid_Fails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"choices": []interface{}{
			map[string]interface{}{"message": map[string]interface{}{"content": `{"name":"Ada"}`}}}}) // still missing age
	}))
	defer srv.Close()
	p := newP(t, map[string]interface{}{"repair": map[string]interface{}{"enabled": true, "endpoint": srv.URL}})
	m := onResp(p, reply(`garbage`))
	if m.StatusCode == nil {
		t.Fatal("llm returned invalid -> should still fail")
	}
}

func TestLLMRepair_EndpointDown_Fails(t *testing.T) {
	p := newP(t, map[string]interface{}{"repair": map[string]interface{}{"enabled": true, "endpoint": "http://127.0.0.1:1/x", "timeoutSeconds": 1.0}})
	m := onResp(p, reply(`garbage`))
	if m.StatusCode == nil {
		t.Fatal("repair endpoint unreachable -> fail (default onFail=block)")
	}
}

// ─── deterministicRepair unit ────────────────────────────────────────────────

func TestDeterministicRepair_Unit(t *testing.T) {
	cases := map[string]string{
		"```json\n{\"a\":1}\n```":       `{"a":1}`,
		"prefix {\"a\":1} suffix":       `{"a":1}`,
		`{"a":1,}`:                       `{"a":1}`,
		`{"a":{"b":[1,2,]},}`:            `{"a":{"b":[1,2]}}`,
		`[1,2,3,]`:                       `[1,2,3]`,
	}
	for in, want := range cases {
		if got := deterministicRepair(in); got != want {
			t.Errorf("deterministicRepair(%q) = %q, want %q", in, got, want)
		}
	}
}
