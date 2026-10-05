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

package openaierrorformat

import (
	"context"
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// faultCase describes the error a fault policy is handed.
type faultCase struct {
	kind      policy.APIKind
	source    string
	policy    string
	status    int
	headers   map[string][]string
	body      []byte
	fault     *policy.FaultDetails
	committed bool
}

func newFaultContext(c faultCase) *policy.FaultContext {
	fc := &policy.FaultContext{
		SharedContext:     &policy.SharedContext{APIKind: c.kind},
		ResponseHeaders:   policy.NewHeaders(c.headers),
		ResponseStatus:    c.status,
		Source:            c.source,
		Policy:            c.policy,
		Fault:             c.fault,
		ResponseCommitted: c.committed,
		RouteKey:          "test-route",
	}
	if c.body != nil {
		fc.ResponseBody = &policy.Body{Content: c.body, EndOfStream: true, Present: true}
	}
	return fc
}

func mustPolicy(t *testing.T, params map[string]interface{}) *Policy {
	t.Helper()
	p, err := newPolicy(params)
	if err != nil {
		t.Fatalf("newPolicy: %v", err)
	}
	return p
}

func run(t *testing.T, p *Policy, c faultCase) *policy.FaultResponse {
	t.Helper()
	return p.OnFault(context.Background(), newFaultContext(c), nil)
}

// decodeEnvelope parses a written body and asserts the envelope's fixed shape.
func decodeEnvelope(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var top map[string]interface{}
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, body)
	}
	if len(top) != 1 {
		t.Fatalf("envelope must have exactly one top-level key, got %v", top)
	}
	inner, ok := top["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("envelope must hold an 'error' object, got %s", body)
	}
	if v, present := inner["param"]; !present || v != nil {
		t.Fatalf("error.param must be present and null, got %v", inner["param"])
	}
	if _, present := inner["code"]; !present {
		t.Fatalf("error.code must be present (string or null): %s", body)
	}
	if m, _ := inner["message"].(string); m == "" {
		t.Fatalf("error.message must be a non-empty string: %s", body)
	}
	return inner
}

func TestGetPolicy_Params(t *testing.T) {
	cases := []struct {
		name    string
		params  map[string]interface{}
		want    int
		wantErr bool
	}{
		{"nil params use the default", nil, defaultMaxInspectBytes, false},
		{"empty fault block uses the default", map[string]interface{}{"fault": map[string]interface{}{}}, defaultMaxInspectBytes, false},
		{"zero disables inspection", map[string]interface{}{"fault": map[string]interface{}{"maxInspectBytes": 0}}, 0, false},
		{"json number", map[string]interface{}{"fault": map[string]interface{}{"maxInspectBytes": float64(1024)}}, 1024, false},
		{"negative is rejected", map[string]interface{}{"fault": map[string]interface{}{"maxInspectBytes": -1}}, 0, true},
		{"fraction is rejected", map[string]interface{}{"fault": map[string]interface{}{"maxInspectBytes": 1.5}}, 0, true},
		{"string is rejected", map[string]interface{}{"fault": map[string]interface{}{"maxInspectBytes": "10"}}, 0, true},
		{"non-object fault block is rejected", map[string]interface{}{"fault": "x"}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetPolicy(policy.PolicyMetadata{}, tc.params)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p := got.(*Policy); p.maxInspectBytes != tc.want {
				t.Fatalf("maxInspectBytes = %d, want %d", p.maxInspectBytes, tc.want)
			}
		})
	}
}

func TestMode_SkipsEveryPhase(t *testing.T) {
	m := mustPolicy(t, nil).Mode()
	if m.RequestHeaderMode != policy.HeaderModeSkip || m.ResponseHeaderMode != policy.HeaderModeSkip ||
		m.RequestBodyMode != policy.BodyModeSkip || m.ResponseBodyMode != policy.BodyModeSkip {
		t.Fatalf("every phase must be SKIP, got %+v", m)
	}
}

func TestOnFault_NilContext(t *testing.T) {
	if got := mustPolicy(t, nil).OnFault(context.Background(), nil, nil); got != nil {
		t.Fatalf("nil context must change nothing, got %+v", got)
	}
}

func TestOnFault_RecoversFromPanic(t *testing.T) {
	// A FaultContext with no SharedContext makes the APIKind read panic.
	fc := &policy.FaultContext{ResponseStatus: 422, Source: policy.FaultSourceGateway}
	if got := mustPolicy(t, nil).OnFault(context.Background(), fc, nil); got != nil {
		t.Fatalf("a panic must leave the original error untouched, got %+v", got)
	}
}

// ── US1: a rejection on an LLM API becomes the OpenAI envelope ────────────────

func TestOnFault_US1_RejectionBecomesEnvelope(t *testing.T) {
	cases := []struct {
		name     string
		kind     policy.APIKind
		status   int
		fault    *policy.FaultDetails
		wantType string
		wantCode interface{}
	}{
		{"guardrail on a provider", policy.APIKindLlmProvider, 422,
			&policy.FaultDetails{Type: policy.FaultTypeGuardrail, Code: "906201", Message: "Word count exceeds the allowed range"},
			"invalid_request_error", "906201"},
		{"guardrail on a proxy", policy.APIKindLlmProxy, 422,
			&policy.FaultDetails{Type: policy.FaultTypeGuardrail, Code: "906201", Message: "Word count exceeds the allowed range"},
			"invalid_request_error", "906201"},
		{"authentication", policy.APIKindLlmProvider, 401,
			&policy.FaultDetails{Type: policy.FaultTypeAuthentication, Code: "900902", Message: "Invalid or expired credentials."},
			"authentication_error", "900902"},
		{"throttling", policy.APIKindLlmProvider, 429,
			&policy.FaultDetails{Type: policy.FaultTypeThrottling, Code: "900800", Message: "Rate limit exceeded"},
			"rate_limit_error", "900800"},
		{"no fault description", policy.APIKindLlmProvider, 403, nil,
			"permission_error", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := run(t, mustPolicy(t, nil), faultCase{
				kind: tc.kind, source: policy.FaultSourceGateway, policy: "some-policy",
				status: tc.status, fault: tc.fault,
			})
			if resp == nil {
				t.Fatalf("expected the error to be reshaped")
			}
			if resp.StatusCode != nil {
				t.Fatalf("the status must never change, got %d", *resp.StatusCode)
			}
			if resp.Final {
				t.Fatalf("must not end the fault chain: later entries keep the last word")
			}
			if resp.HeadersToSet["content-type"] != "application/json" {
				t.Fatalf("content-type must be application/json, got %v", resp.HeadersToSet)
			}
			e := decodeEnvelope(t, resp.Body)
			if e["type"] != tc.wantType || e["code"] != tc.wantCode {
				t.Fatalf("type/code = %v/%v, want %v/%v", e["type"], e["code"], tc.wantType, tc.wantCode)
			}
			if tc.fault != nil && e["message"] != tc.fault.Message {
				t.Fatalf("message = %v, want the fault's message %q", e["message"], tc.fault.Message)
			}
		})
	}
}

func TestOnFault_US1_RemovesContentEncodingOnlyWhenPresent(t *testing.T) {
	p := mustPolicy(t, nil)
	base := faultCase{kind: policy.APIKindLlmProvider, source: policy.FaultSourceGateway, policy: "x", status: 422}

	if resp := run(t, p, base); len(resp.HeadersToRemove) != 0 {
		t.Fatalf("nothing to remove without content-encoding, got %v", resp.HeadersToRemove)
	}

	enc := base
	enc.headers = map[string][]string{"Content-Encoding": {"gzip"}}
	enc.body = []byte{0x1f, 0x8b, 0x08}
	resp := run(t, p, enc)
	if len(resp.HeadersToRemove) != 1 || resp.HeadersToRemove[0] != "content-encoding" {
		t.Fatalf("the replacement body is plain JSON; content-encoding must go, got %v", resp.HeadersToRemove)
	}
}

// ── US2: nothing changes unless the API is an LLM API that opted in ───────────

func TestOnFault_US2_NonLLMKindsAreUntouched(t *testing.T) {
	p := mustPolicy(t, nil)
	for _, kind := range []policy.APIKind{
		policy.APIKindRestApi, policy.APIKindMCP, policy.APIKindWebSubApi,
		policy.APIKindGraphQL, policy.APIKindAgent, "",
	} {
		t.Run(string(kind), func(t *testing.T) {
			resp := run(t, p, faultCase{
				kind: kind, source: policy.FaultSourceGateway, policy: "word-count-guardrail",
				status: 422, body: []byte(`{"message":"Too many words"}`),
				fault: &policy.FaultDetails{Type: policy.FaultTypeGuardrail, Message: "Too many words"},
			})
			if resp != nil {
				t.Fatalf("a %q API must be left alone, got %+v", kind, resp)
			}
		})
	}
}

func TestOnFault_US2_CommittedResponseIsUntouched(t *testing.T) {
	resp := run(t, mustPolicy(t, nil), faultCase{
		kind: policy.APIKindLlmProvider, source: policy.FaultSourceGateway, policy: "x",
		status: 200, committed: true,
	})
	if resp != nil {
		t.Fatalf("a response already streaming to the client cannot be reshaped, got %+v", resp)
	}
}

// ── US3: the rejecting policy's own reason survives ───────────────────────────

func TestOnFault_US3_MessageSources(t *testing.T) {
	p := mustPolicy(t, nil)
	base := faultCase{kind: policy.APIKindLlmProvider, source: policy.FaultSourceGateway, policy: "x"}

	legacy := base
	legacy.status = 422
	legacy.body = []byte(`{"message":"Too many words"}`)
	e := decodeEnvelope(t, run(t, p, legacy).Body)
	if e["message"] != "Too many words" || e["type"] != "invalid_request_error" {
		t.Fatalf("the policy's own message must survive, got %v", e)
	}

	described := legacy
	described.fault = &policy.FaultDetails{Message: "from the fault"}
	if e := decodeEnvelope(t, run(t, p, described).Body); e["message"] != "from the fault" {
		t.Fatalf("Fault.Message outranks the body, got %v", e["message"])
	}

	bare := base
	bare.status = 503
	if e := decodeEnvelope(t, run(t, p, bare).Body); e["message"] != "Service Unavailable" {
		t.Fatalf("with nothing else, the status text is the message, got %v", e["message"])
	}

	guard := base
	guard.status = 422
	guard.body = []byte(guardrailBody)
	e = decodeEnvelope(t, run(t, p, guard).Body)
	if e["message"] != "Violation of applied word count constraints detected" {
		t.Fatalf("a shipped guardrail's reason must survive, got %v", e["message"])
	}
	if _, ok := e["guardrail"].(map[string]interface{}); !ok {
		t.Fatalf("the guardrail's assessment must be carried inside error, got %v", e)
	}

	// A guardrail block on the fault outranks the one lifted from the body.
	guard.fault = &policy.FaultDetails{Guardrail: &policy.GuardrailDetails{InterveningGuardrail: "from-fault"}}
	e = decodeEnvelope(t, run(t, p, guard).Body)
	if g := e["guardrail"].(map[string]interface{}); g["interveningGuardrail"] != "from-fault" {
		t.Fatalf("Fault.Guardrail must win over the body, got %v", g)
	}
}

// ── US4: router failures are formatted, the backend's own errors are not ──────

func TestOnFault_US4_Source(t *testing.T) {
	p := mustPolicy(t, nil)
	cases := []struct {
		name       string
		source     string
		policyName string
		status     int
		fault      *policy.FaultDetails
		body       []byte
		formatted  bool
		wantCode   interface{}
	}{
		{"gateway rejection", policy.FaultSourceGateway, "api-key-auth", 401, nil, nil, true, nil},
		{"router failure", policy.FaultSourceRouter, "", 503,
			&policy.FaultDetails{Type: policy.FaultTypeUpstream, Code: "303001"}, []byte("no healthy upstream"), true, "303001"},
		{"backend error", policy.FaultSourceBackend, "", 400, nil, []byte(`{"error":{"message":"bad model"}}`), false, nil},
		{"backend error with a fault", policy.FaultSourceBackend, "", 500,
			&policy.FaultDetails{Type: policy.FaultTypeUpstream}, nil, false, nil},
		{"no route", policy.FaultSourceNoRoute, "", 404, nil, nil, false, nil},
		{"unknown provenance, no policy", policy.FaultSourceUnknown, "", 503, nil, nil, false, nil},
		{"unknown provenance, policy rejection", policy.FaultSourceUnknown, "api-key-auth", 401, nil, nil, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := run(t, p, faultCase{
				kind: policy.APIKindLlmProvider, source: tc.source, policy: tc.policyName,
				status: tc.status, fault: tc.fault, body: tc.body,
			})
			if !tc.formatted {
				if resp != nil {
					t.Fatalf("must pass through unchanged, got %s", resp.Body)
				}
				return
			}
			if resp == nil {
				t.Fatalf("expected the error to be reshaped")
			}
			e := decodeEnvelope(t, resp.Body)
			if e["code"] != tc.wantCode {
				t.Fatalf("code = %v, want %v", e["code"], tc.wantCode)
			}
			if tc.source == policy.FaultSourceRouter {
				if e["type"] != "server_error" || e["message"] != "no healthy upstream" {
					t.Fatalf("router failure rendered as %v", e)
				}
			}
		})
	}
}

// ── US5: idempotent, so it composes with itself and with other fault policies ─

func TestOnFault_US5_Idempotent(t *testing.T) {
	p := mustPolicy(t, nil)
	first := run(t, p, faultCase{
		kind: policy.APIKindLlmProvider, source: policy.FaultSourceGateway, policy: "x",
		status: 422, body: []byte(guardrailBody),
	})
	if first == nil {
		t.Fatalf("the first run must reshape the body")
	}
	second := run(t, p, faultCase{
		kind: policy.APIKindLlmProvider, source: policy.FaultSourceGateway, policy: "x",
		status: 422, body: first.Body, headers: map[string][]string{"content-type": {"application/json"}},
	})
	if second != nil {
		t.Fatalf("an OpenAI envelope must be left as it is, got %s", second.Body)
	}
}

func TestOnFault_US5_EnvelopeWrittenByAnotherFaultPolicyIsKept(t *testing.T) {
	resp := run(t, mustPolicy(t, nil), faultCase{
		kind: policy.APIKindLlmProxy, source: policy.FaultSourceGateway, policy: "x", status: 400,
		body: []byte(`{"error":{"message":"custom","type":"invalid_request_error","param":"model","code":"custom_1"}}`),
	})
	if resp != nil {
		t.Fatalf("an envelope another entry wrote must not be rewritten, got %s", resp.Body)
	}
}

func TestOnFault_US5_IdempotentEvenWithInspectionDisabled(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"fault": map[string]interface{}{"maxInspectBytes": 0}})
	resp := run(t, p, faultCase{
		kind: policy.APIKindLlmProvider, source: policy.FaultSourceGateway, policy: "x", status: 422,
		body: []byte(`{"error":{"message":"keep me","type":"invalid_request_error","param":null,"code":null}}`),
	})
	if resp != nil {
		t.Fatalf("disabling message recovery must not make the policy rewrite an envelope, got %s", resp.Body)
	}
}
