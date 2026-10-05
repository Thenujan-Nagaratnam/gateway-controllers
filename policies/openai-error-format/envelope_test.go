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
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestErrorType(t *testing.T) {
	cases := []struct {
		faultType string
		status    int
		want      string
	}{
		{policy.FaultTypeAuthentication, 401, "authentication_error"},
		{policy.FaultTypeAuthorization, 403, "permission_error"},
		{policy.FaultTypeThrottling, 429, "rate_limit_error"},
		{policy.FaultTypeGuardrail, 422, "invalid_request_error"},
		{policy.FaultTypeValidation, 400, "invalid_request_error"},
		{policy.FaultTypeRequestSize, 413, "invalid_request_error"},
		{policy.FaultTypeRouting, 404, "not_found_error"},
		{policy.FaultTypeUpstream, 503, "server_error"},
		{policy.FaultTypeInternal, 500, "server_error"},
		// The class wins over the status.
		{policy.FaultTypeThrottling, 503, "rate_limit_error"},
		// Classes with no OpenAI equivalent, an absent class and an unknown one fall back to the status.
		{policy.FaultTypeMediation, 500, "server_error"},
		{policy.FaultTypeConfiguration, 400, "invalid_request_error"},
		{"", 401, "authentication_error"},
		{"", 403, "permission_error"},
		{"", 404, "not_found_error"},
		{"", 429, "rate_limit_error"},
		{"", 400, "invalid_request_error"},
		{"", 422, "invalid_request_error"},
		{"", 500, "server_error"},
		{"", 503, "server_error"},
		{"somethingNew", 418, "invalid_request_error"},
		{"", 0, "server_error"},
		{"", 302, "server_error"},
	}
	for _, tc := range cases {
		if got := errorType(tc.faultType, tc.status); got != tc.want {
			t.Errorf("errorType(%q, %d) = %q, want %q", tc.faultType, tc.status, got, tc.want)
		}
	}
}

func TestBuildEnvelope(t *testing.T) {
	t.Run("code from the fault", func(t *testing.T) {
		body, err := buildEnvelope(&policy.FaultDetails{Type: policy.FaultTypeGuardrail, Code: "906201"}, 422, "too long", nil)
		if err != nil {
			t.Fatal(err)
		}
		e := decodeEnvelope(t, body)
		if e["code"] != "906201" || e["type"] != "invalid_request_error" || e["message"] != "too long" {
			t.Fatalf("unexpected envelope %s", body)
		}
		if _, ok := e["guardrail"]; ok {
			t.Fatalf("guardrail must be omitted when the fault has none: %s", body)
		}
	})

	t.Run("null code without a fault", func(t *testing.T) {
		body, err := buildEnvelope(nil, 503, "Service Unavailable", nil)
		if err != nil {
			t.Fatal(err)
		}
		e := decodeEnvelope(t, body)
		if e["code"] != nil || e["type"] != "server_error" {
			t.Fatalf("unexpected envelope %s", body)
		}
	})

	t.Run("guardrail detail stays inside error", func(t *testing.T) {
		f := &policy.FaultDetails{
			Type: policy.FaultTypeGuardrail,
			Guardrail: &policy.GuardrailDetails{
				InterveningGuardrail: "word-count-guardrail",
				Action:               policy.GuardrailActionIntervened,
			},
		}
		body, err := buildEnvelope(f, 422, "blocked", nil)
		if err != nil {
			t.Fatal(err)
		}
		e := decodeEnvelope(t, body)
		if _, ok := e["guardrail"].(map[string]interface{}); !ok {
			t.Fatalf("guardrail detail must be inside error: %s", body)
		}
	})

	t.Run("message is JSON-escaped", func(t *testing.T) {
		body, err := buildEnvelope(nil, 400, "say \"hi\"\n<script>", nil)
		if err != nil {
			t.Fatal(err)
		}
		if e := decodeEnvelope(t, body); e["message"] != "say \"hi\"\n<script>" {
			t.Fatalf("message did not round-trip: %s", body)
		}
	})
}

func TestBuildEnvelope_NeverEmitsDescription(t *testing.T) {
	f := &policy.FaultDetails{
		Type:        policy.FaultTypeInternal,
		Message:     "public message",
		Description: "internal-only: db host 10.0.0.5 refused",
	}
	body, err := buildEnvelope(f, 500, f.Message, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "10.0.0.5") || strings.Contains(string(body), "internal-only") {
		t.Fatalf("Fault.Description leaked into the envelope: %s", body)
	}
}

func TestIsOpenAIEnvelope(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`{"error":{"message":"x","type":"invalid_request_error","param":null,"code":null}}`, true},
		{`{"error":{"message":"x","type":"server_error","guardrail":{"action":"a"}}}`, true},
		{` {"error":{"message":"","type":"t"}} `, true},
		{`{"error":"x"}`, false},
		{`{"error":{"message":"x"}}`, false},
		{`{"error":{"type":"t"}}`, false},
		{`{"error":{"message":1,"type":"t"}}`, false},
		{`{"error":{"message":"x","type":"t"},"extra":1}`, false},
		{`[{"error":{"message":"x","type":"t"}}]`, false},
		{`{"error":`, false},
		{``, false},
		{`no healthy upstream`, false},
	}
	for _, tc := range cases {
		if got := isOpenAIEnvelope([]byte(tc.body)); got != tc.want {
			t.Errorf("isOpenAIEnvelope(%s) = %v, want %v", tc.body, got, tc.want)
		}
	}
}
