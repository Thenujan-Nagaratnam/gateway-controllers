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

// guardrailBody is the shape every shipped guardrail writes when it rejects.
const guardrailBody = `{"type":"WORD_COUNT_GUARDRAIL","message":{"action":"GUARDRAIL_INTERVENED",` +
	`"interveningGuardrail":"word-count-guardrail","direction":"REQUEST",` +
	`"actionReason":"Violation of applied word count constraints detected",` +
	`"assessments":"Violation of word count detected. Expected word count to be between 1 and 5 words."}}`

func TestInspectBody_Message(t *testing.T) {
	json := map[string][]string{"content-type": {"application/json"}}
	cases := []struct {
		name    string
		body    string
		headers map[string][]string
		max     int
		want    string
	}{
		{"nested error.message", `{"error":{"message":"bad key","type":"x"}}`, json, 1024, "bad key"},
		{"top-level message", `{"message":"Too many words"}`, json, 1024, "Too many words"},
		{"shipped guardrail shape", guardrailBody, json, 1024, "Violation of applied word count constraints detected"},
		{"error_description", `{"error":"invalid_token","error_description":"token expired"}`, json, 1024, "token expired"},
		{"detail", `{"detail":"schema mismatch"}`, json, 1024, "schema mismatch"},
		{"error as string", `{"error":"Unauthorized"}`, json, 1024, "Unauthorized"},
		{"lookup order: message before detail", `{"message":"a","detail":"b"}`, json, 1024, "a"},
		{"lookup order: error.message before message", `{"error":{"message":"a"},"message":"b"}`, json, 1024, "a"},
		{"non-string values are skipped", `{"message":123,"detail":"d"}`, json, 1024, "d"},
		{"empty strings are skipped", `{"message":"  ","detail":"d"}`, json, 1024, "d"},
		{"JSON with no known field", `{"foo":"bar"}`, json, 1024, ""},
		{"JSON array", `["a"]`, json, 1024, ""},
		{"plain text", "no healthy upstream", nil, 1024, "no healthy upstream"},
		{"plain text is trimmed", "  upstream connect error  \n", map[string][]string{"content-type": {"text/plain"}}, 1024, "upstream connect error"},
		{"multi-line plain text is not a message", "panic: boom\ngoroutine 1", nil, 1024, ""},
		{"HTML is not a message", "<html>oops</html>", map[string][]string{"content-type": {"text/html"}}, 1024, ""},
		{"over the inspect limit", `{"message":"Too many words"}`, json, 10, ""},
		{"inspection disabled", `{"message":"Too many words"}`, json, 0, ""},
		{"encoded body", `{"message":"Too many words"}`, map[string][]string{"content-encoding": {"gzip"}}, 1024, ""},
		{"identity encoding is not encoded", `{"message":"ok"}`, map[string][]string{"content-encoding": {"identity"}}, 1024, "ok"},
		{"empty body", "", json, 1024, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inspectBody([]byte(tc.body), policy.NewHeaders(tc.headers), tc.max)
			if got.message != tc.want {
				t.Fatalf("message = %q, want %q", got.message, tc.want)
			}
		})
	}
}

func TestInspectBody_LongPlainTextIsNotAMessage(t *testing.T) {
	got := inspectBody([]byte(strings.Repeat("x", maxPlainTextMessage+1)), policy.NewHeaders(nil), 1<<20)
	if got.message != "" {
		t.Fatalf("plain text over %d characters must not be used", maxPlainTextMessage)
	}
}

func TestInspectBody_LiftsGuardrailAssessment(t *testing.T) {
	got := inspectBody([]byte(guardrailBody), policy.NewHeaders(nil), 1024)
	g := got.guardrail
	if g == nil {
		t.Fatalf("the guardrail's assessment must be carried over")
	}
	if g.InterveningGuardrail != "word-count-guardrail" || g.Action != "GUARDRAIL_INTERVENED" ||
		g.ActionReason != "Violation of applied word count constraints detected" {
		t.Fatalf("unexpected guardrail block %+v", g)
	}
	if g.Assessments == nil {
		t.Fatalf("assessments the guardrail chose to show must be kept")
	}

	if plain := inspectBody([]byte(`{"message":"x"}`), policy.NewHeaders(nil), 1024); plain.guardrail != nil {
		t.Fatalf("no guardrail block without an intervening guardrail, got %+v", plain.guardrail)
	}
}
