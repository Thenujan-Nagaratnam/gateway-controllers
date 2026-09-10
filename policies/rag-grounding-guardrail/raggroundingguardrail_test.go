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

package raggroundingguardrail

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const passage = "The Apollo 11 mission launched on 16 July 1969 from Kennedy Space Center. " +
	"Neil Armstrong and Buzz Aldrin landed the lunar module Eagle in the Sea of Tranquility on 20 July 1969. " +
	"Michael Collins remained in lunar orbit aboard the command module Columbia. " +
	"Armstrong was the first person to walk on the Moon, followed about twenty minutes later by Aldrin. " +
	"The astronauts collected 21.5 kilograms of lunar material and returned to Earth on 24 July 1969."

func newP(t *testing.T, params map[string]interface{}) *RagGroundingGuardrailPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*RagGroundingGuardrailPolicy)
}

func reqWithContext(ctxText string) []byte {
	b, _ := json.Marshal(map[string]interface{}{"messages": []interface{}{
		map[string]interface{}{"role": "user", "content": "answer from the passage"},
		map[string]interface{}{"role": "tool", "content": ctxText},
	}})
	return b
}
func reqWithContextAt(path string, ctxText string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"messages": []interface{}{map[string]interface{}{"role": "user", "content": "q"}},
		path:       ctxText,
	})
	return b
}
func resp(answer string) []byte {
	b, _ := json.Marshal(map[string]interface{}{"choices": []interface{}{
		map[string]interface{}{"message": map[string]interface{}{"role": "assistant", "content": answer}}}})
	return b
}

func onResp(p *RagGroundingGuardrailPolicy, respBody, reqBody []byte) policy.DownstreamResponseModifications {
	a := p.OnResponseBody(context.Background(), &policy.ResponseContext{
		ResponseBody: &policy.Body{Content: respBody, Present: true},
		RequestBody:  &policy.Body{Content: reqBody, Present: true},
	}, nil)
	m, ok := a.(policy.DownstreamResponseModifications)
	if !ok {
		t := &testing.T{}
		t.Fatalf("unexpected action %T", a)
	}
	return m
}

func answerOf(t *testing.T, body []byte) string {
	t.Helper()
	var o map[string]interface{}
	json.Unmarshal(body, &o)
	return o["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"].(string)
}

// ─── GetPolicy ───────────────────────────────────────────────────────────────

func TestGetPolicy_BadMinScore(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"minGroundingScore": 2.0})
	if err == nil || !strings.Contains(err.Error(), "minGroundingScore") {
		t.Fatalf("want minGroundingScore error, got %v", err)
	}
}
func TestGetPolicy_BadOnLow(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"onLowGrounding": "nuke"})
	if err == nil || !strings.Contains(err.Error(), "onLowGrounding") {
		t.Fatalf("want onLowGrounding error, got %v", err)
	}
}
func TestGetPolicy_BadCitationPattern(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"citationPattern": "("})
	if err == nil || !strings.Contains(err.Error(), "citationPattern") {
		t.Fatalf("want citationPattern error, got %v", err)
	}
}

// ─── grounded vs ungrounded ─────────────────────────────────────────────────

func TestGrounded_Answer_NotLow(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "block"})
	ans := "Apollo 11 launched on 16 July 1969 from Kennedy Space Center. Neil Armstrong and Buzz Aldrin landed the lunar module Eagle in the Sea of Tranquility on 20 July 1969, while Michael Collins stayed in lunar orbit aboard Columbia. The astronauts collected 21.5 kilograms of lunar material and returned to Earth on 24 July 1969."
	m := onResp(p, resp(ans), reqWithContext(passage))
	if m.StatusCode != nil {
		t.Fatalf("grounded answer should not be blocked (score header: %v)", m.HeadersToSet)
	}
	if m.HeadersToSet["x-grounding-score"] == "" {
		t.Fatalf("expected x-grounding-score header, got %v", m.HeadersToSet)
	}
}

func TestUngrounded_Answer_Blocked(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "block"})
	ans := "The Great Barrier Reef is the world's largest coral reef system, located off the coast of Queensland, Australia. It supports thousands of marine species and is threatened by warming ocean temperatures and coral bleaching events."
	m := onResp(p, resp(ans), reqWithContext(passage))
	if m.StatusCode == nil || *m.StatusCode != guardrailCode {
		t.Fatalf("ungrounded answer should be blocked, got %+v", m)
	}
	var env map[string]interface{}
	json.Unmarshal(m.Body, &env)
	if env["message"].(map[string]interface{})["direction"] != "RESPONSE" {
		t.Fatalf("wrong direction")
	}
}

func TestUnsupportedSpecific_Blocked(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "block", "showAssessment": true, "minGroundingScore": 0.0})
	// mostly-grounded sentences but a fabricated figure + year
	ans := "Apollo 11 launched from Kennedy Space Center and Armstrong walked on the Moon. The mission cost 355 billion dollars and the crew returned in 1971."
	m := onResp(p, resp(ans), reqWithContext(passage))
	if m.StatusCode == nil {
		t.Fatalf("fabricated specifics should trigger the guardrail, got %+v", m)
	}
	if !strings.Contains(string(m.Body), "not found in the context") {
		t.Fatalf("assessment should list unsupported specifics: %s", m.Body)
	}
}

func TestSupportedSpecifics_NotFlagged(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "block", "minGroundingScore": 0.0, "checkUnsupportedSpecifics": true})
	ans := "The crew collected 21.5 kilograms of samples and returned to Earth on 24 July 1969 after launching on 16 July 1969."
	m := onResp(p, resp(ans), reqWithContext(passage))
	if m.StatusCode != nil {
		t.Fatalf("all specifics are in the passage; should not block: %s", m.Body)
	}
}

// ─── citations ───────────────────────────────────────────────────────────────

func TestRequireCitations(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "block", "requireCitations": true, "minGroundingScore": 0.0, "checkUnsupportedSpecifics": false})
	grounded := "Armstrong and Aldrin landed the lunar module Eagle in the Sea of Tranquility."
	if m := onResp(p, resp(grounded), reqWithContext(passage)); m.StatusCode == nil {
		t.Fatal("no citation -> should trigger")
	}
	cited := grounded + " [doc-1]"
	if m := onResp(p, resp(cited), reqWithContext(passage)); m.StatusCode != nil {
		t.Fatalf("citation present -> should pass: %s", m.Body)
	}
}

// ─── not-graded cases ────────────────────────────────────────────────────────

func TestShortAnswer_NotGraded(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "block"})
	m := onResp(p, resp("Neil Armstrong."), reqWithContext(passage))
	if m.StatusCode != nil || m.Body != nil {
		t.Fatal("short answers must not be graded")
	}
}

func TestNoContext_NotGraded(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "block"})
	noCtx, _ := json.Marshal(map[string]interface{}{"messages": []interface{}{
		map[string]interface{}{"role": "user", "content": "tell me about coral reefs"}}})
	m := onResp(p, resp("The Great Barrier Reef is off the coast of Queensland, Australia, and spans over 2000 kilometres."), noCtx)
	if m.StatusCode != nil || m.Body != nil {
		t.Fatal("no retrieved context -> not a RAG turn -> not graded")
	}
}

func TestContextJsonPath(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "block", "contextRoles": []interface{}{}, "contextJsonPaths": []interface{}{"$.context"}})
	m := onResp(p, resp("The Great Barrier Reef spans over 2000 kilometres off Queensland."), reqWithContextAt("context", passage))
	if m.StatusCode == nil {
		t.Fatalf("ungrounded answer with $.context should still be graded and blocked: %+v", m)
	}
}

// ─── actions ─────────────────────────────────────────────────────────────────

func TestWarnAction_AppendsText(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "warn"})
	ans := "The Great Barrier Reef is the world's largest coral reef system off Queensland, Australia, threatened by bleaching."
	m := onResp(p, resp(ans), reqWithContext(passage))
	if m.Body == nil {
		t.Fatal("warn should rewrite the answer")
	}
	got := answerOf(t, m.Body)
	if !strings.Contains(got, "may not be fully supported") {
		t.Fatalf("warnText not appended: %q", got)
	}
	if m.HeadersToSet["x-grounding-action"] != "warned" {
		t.Fatalf("expected warned header, got %v", m.HeadersToSet)
	}
}

func TestAnnotateAction_HeadersOnly(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "annotate"})
	ans := "The Great Barrier Reef is the world's largest coral reef system off Queensland, Australia, threatened by bleaching."
	m := onResp(p, resp(ans), reqWithContext(passage))
	if m.Body != nil {
		t.Fatal("annotate must not rewrite the body")
	}
	if m.HeadersToSet["x-grounding"] != "low" || m.HeadersToSet["x-grounding-score"] == "" {
		t.Fatalf("annotate headers wrong: %v", m.HeadersToSet)
	}
}

func TestNonJSONResponse_BlockThenPassthrough(t *testing.T) {
	p := newP(t, map[string]interface{}{"onLowGrounding": "block"})
	m := onResp(p, []byte("<<not json"), reqWithContext(passage))
	if m.StatusCode == nil {
		t.Fatal("non-JSON response -> block")
	}
	p2 := newP(t, map[string]interface{}{"onLowGrounding": "block", "passthroughOnError": true})
	m2 := onResp(p2, []byte("<<not json"), reqWithContext(passage))
	if m2.StatusCode != nil || m2.Body != nil {
		t.Fatal("passthroughOnError -> forward")
	}
}

// ─── grade() unit ───────────────────────────────────────────────────────────

func TestGrade_ScoreOrdering(t *testing.T) {
	cfg := config{minScore: 0.45, checkSpecifics: false}
	good := grade("Armstrong and Aldrin landed the Eagle in the Sea of Tranquility on 20 July 1969.", passage, cfg)
	bad := grade("Bananas are an excellent source of potassium and are grown in tropical climates worldwide.", passage, cfg)
	if !(good.score > bad.score) {
		t.Fatalf("grounded answer should score higher: good=%.2f bad=%.2f", good.score, bad.score)
	}
	if good.low {
		t.Fatalf("grounded answer flagged low (%.2f)", good.score)
	}
	if !bad.low {
		t.Fatalf("ungrounded answer not flagged (%.2f)", bad.score)
	}
}
