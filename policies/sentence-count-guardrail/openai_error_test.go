package sentencecountguardrail

import (
	"encoding/json"
	"testing"
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
	if legacy["type"] != "SENTENCE_COUNT_GUARDRAIL" {
		t.Errorf("legacy type = %v, want SENTENCE_COUNT_GUARDRAIL", legacy["type"])
	}
	if msg, ok := legacy["message"].(map[string]interface{}); !ok || msg["actionReason"] != "blocked for testing" {
		t.Errorf("legacy message = %v", legacy["message"])
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
