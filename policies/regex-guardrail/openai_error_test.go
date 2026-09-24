package regexguardrail

import (
	"context"
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestGuardrailErrorBody_Formats(t *testing.T) {
	assessment := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "test-guardrail",
		"direction":            "REQUEST",
		"actionReason":         "blocked for testing",
		"assessments":          "detail",
	}

	var llm struct {
		Error struct {
			Message   string                 `json:"message"`
			Type      string                 `json:"type"`
			Param     *string                `json:"param"`
			Code      *string                `json:"code"`
			Guardrail map[string]interface{} `json:"guardrail"`
		} `json:"error"`
	}
	if err := json.Unmarshal(guardrailErrorBody(assessment, true), &llm); err != nil {
		t.Fatalf("LLM body is not JSON: %v", err)
	}
	if llm.Error.Message != "blocked for testing" || llm.Error.Type != "invalid_request_error" || llm.Error.Param != nil {
		t.Errorf("unexpected OpenAI error: %+v", llm.Error)
	}
	if llm.Error.Code == nil || *llm.Error.Code != "guardrail_intervened" {
		t.Errorf("code = %v, want guardrail_intervened", llm.Error.Code)
	}
	if llm.Error.Guardrail["name"] != "test-guardrail" || llm.Error.Guardrail["direction"] != "REQUEST" || llm.Error.Guardrail["assessments"] != "detail" {
		t.Errorf("guardrail details = %v", llm.Error.Guardrail)
	}

	var legacy map[string]interface{}
	if err := json.Unmarshal(guardrailErrorBody(assessment, false), &legacy); err != nil {
		t.Fatalf("legacy body is not JSON: %v", err)
	}
	if legacy["type"] != "REGEX_GUARDRAIL" {
		t.Errorf("legacy type = %v, want REGEX_GUARDRAIL", legacy["type"])
	}
	if msg, ok := legacy["message"].(map[string]interface{}); !ok || msg["actionReason"] != "blocked for testing" {
		t.Errorf("legacy message = %v", legacy["message"])
	}
}

func TestRegexGuardrail_OnRequestBody_OpenAIErrorForLLMAPIs(t *testing.T) {
	p := mustGetRegexPolicy(t, map[string]interface{}{
		"request": map[string]interface{}{"regex": "^allowed$"},
	})
	for kind, wantOpenAI := range map[policy.APIKind]bool{
		policy.APIKindLlmProvider: true,
		policy.APIKindLlmProxy:    true,
		policy.APIKindRestApi:     false,
	} {
		action := p.OnRequestBody(context.Background(), &policy.RequestContext{
			SharedContext: &policy.SharedContext{APIKind: kind},
			Body:          &policy.Body{Content: []byte(`blocked`)},
		}, nil)
		resp, ok := action.(policy.ImmediateResponse)
		if !ok {
			t.Fatalf("%s: expected ImmediateResponse, got %T", kind, action)
		}
		wantStatus := GuardrailErrorCode
		if wantOpenAI {
			wantStatus = 400 // OpenAI content-policy refusals are 400
		}
		if resp.StatusCode != wantStatus {
			t.Errorf("%s: status = %d, want %d", kind, resp.StatusCode, wantStatus)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(resp.Body, &body); err != nil {
			t.Fatalf("%s: body not JSON: %v", kind, err)
		}
		_, hasErrorObj := body["error"].(map[string]interface{})
		if hasErrorObj != wantOpenAI {
			t.Errorf("%s: OpenAI error envelope = %v, want %v (body %s)", kind, hasErrorObj, wantOpenAI, resp.Body)
		}
	}
}

func TestGuardrailStatus(t *testing.T) {
	if got := guardrailStatus(true); got != 400 {
		t.Errorf("LLM API guardrail status = %d, want 400", got)
	}
	if got := guardrailStatus(false); got != GuardrailErrorCode {
		t.Errorf("non-LLM guardrail status = %d, want %d", got, GuardrailErrorCode)
	}
}
