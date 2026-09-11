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

// Package topicscopeguardrail keeps a narrowly-deployed AI assistant within
// its intended domain (brand/liability risk mitigation), using a
// deterministic content-word overlap heuristic plus an explicit denied-topic
// phrase list - no external ML classifier or embedding API. See
// policy-definition.yaml for the full design.
package topicscopeguardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	guardrailCode = 422
	guardrailType = "TOPIC_SCOPE_GUARDRAIL"
	guardrailName = "TopicScopeGuardrail"

	actionBlock    = "block"
	actionAnnotate = "annotate"
)

type config struct {
	referenceWords  map[string]bool
	deniedTopics    []string // lowercased
	minScopeScore   float64
	checkResponse   bool
	requestPath     string
	responsePath    string
	onOffTopic      string
	minMessageChars int
	showAssessment  bool
	passthrough     bool
}

// TopicScopeGuardrailPolicy implements the v1alpha2 policy interface.
type TopicScopeGuardrailPolicy struct{ cfg config }

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		minScopeScore:   0.25,
		requestPath:     "$.messages[-1].content",
		responsePath:    "$.choices[0].message.content",
		onOffTopic:      actionBlock,
		minMessageChars: 10,
	}

	desc, ok := params["scopeDescription"].(string)
	if !ok || utf8.RuneCountInString(strings.TrimSpace(desc)) < 10 {
		return nil, wrap(fmt.Errorf("'scopeDescription' is required and must be at least 10 characters"))
	}

	refText := desc
	if raw, ok := params["inScopeExamples"]; ok {
		examples, ok := raw.([]interface{})
		if !ok {
			return nil, wrap(fmt.Errorf("'inScopeExamples' must be an array of strings"))
		}
		for _, e := range examples {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, wrap(fmt.Errorf("'inScopeExamples' entries must be non-empty strings"))
			}
			refText += "\n" + s
		}
	}
	cfg.referenceWords = contentWordSet(refText)
	if len(cfg.referenceWords) == 0 {
		return nil, wrap(fmt.Errorf("'scopeDescription' (plus inScopeExamples) produced no usable reference vocabulary"))
	}

	if raw, ok := params["deniedTopics"]; ok {
		list, ok := raw.([]interface{})
		if !ok {
			return nil, wrap(fmt.Errorf("'deniedTopics' must be an array of strings"))
		}
		for _, e := range list {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, wrap(fmt.Errorf("'deniedTopics' entries must be non-empty strings"))
			}
			cfg.deniedTopics = append(cfg.deniedTopics, strings.ToLower(s))
		}
	}

	if v, ok := params["minScopeScore"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 0 || f > 1 {
			return nil, wrap(fmt.Errorf("'minScopeScore' must be a number in [0,1]"))
		}
		cfg.minScopeScore = f
	}
	if err := boolParam(params, "checkResponse", &cfg.checkResponse); err != nil {
		return nil, wrap(err)
	}
	strOpt(params, "requestJsonPath", &cfg.requestPath)
	strOpt(params, "responseJsonPath", &cfg.responsePath)
	if v, ok := params["onOffTopic"]; ok {
		s, _ := v.(string)
		if s != actionBlock && s != actionAnnotate {
			return nil, wrap(fmt.Errorf("'onOffTopic' must be block or annotate"))
		}
		cfg.onOffTopic = s
	}
	if v, ok := params["minMessageChars"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 0 {
			return nil, wrap(fmt.Errorf("'minMessageChars' must be a number >= 0"))
		}
		cfg.minMessageChars = int(f)
	}
	if err := boolParam(params, "showAssessment", &cfg.showAssessment); err != nil {
		return nil, wrap(err)
	}
	if err := boolParam(params, "passthroughOnError", &cfg.passthrough); err != nil {
		return nil, wrap(err)
	}

	return &TopicScopeGuardrailPolicy{cfg: cfg}, nil
}

// Mode buffers the request body always; the response body only when
// checkResponse is enabled.
func (p *TopicScopeGuardrailPolicy) Mode() policy.ProcessingMode {
	respMode := policy.BodyModeSkip
	if p.cfg.checkResponse {
		respMode = policy.BodyModeBuffer
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   respMode,
	}
}

// OnRequestBody scores the caller's latest message against the configured
// scope.
func (p *TopicScopeGuardrailPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	msg, ok, err := extractString(body, p.cfg.requestPath)
	if err != nil {
		if p.cfg.passthrough {
			return policy.UpstreamRequestModifications{}
		}
		return p.blockRequest("Unable to evaluate the request against the configured scope.", nil, 0)
	}
	if !ok || utf8.RuneCountInString(strings.TrimSpace(msg)) < p.cfg.minMessageChars {
		return policy.UpstreamRequestModifications{}
	}

	res := p.evaluate(msg)
	if !res.offTopic {
		return policy.UpstreamRequestModifications{}
	}
	if p.cfg.onOffTopic == actionAnnotate {
		return policy.UpstreamRequestModifications{
			HeadersToSet:      map[string]string{"x-topic-scope": "off-topic"},
			AnalyticsMetadata: scopeAnalytics(res, "REQUEST", "annotated"),
		}
	}
	return p.blockRequest("This request is outside the assistant's configured scope.", res.reasons, res.score)
}

// OnResponseBody optionally scores the model's own reply, catching topic
// drift even when the request itself was in-scope.
func (p *TopicScopeGuardrailPolicy) OnResponseBody(_ context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.cfg.checkResponse {
		return policy.DownstreamResponseModifications{}
	}
	var body []byte
	if respCtx.ResponseBody != nil {
		body = respCtx.ResponseBody.Content
	}
	reply, ok, err := extractString(body, p.cfg.responsePath)
	if err != nil {
		if p.cfg.passthrough {
			return policy.DownstreamResponseModifications{}
		}
		return p.blockResponse("Unable to evaluate the reply against the configured scope.", nil, 0)
	}
	if !ok || utf8.RuneCountInString(strings.TrimSpace(reply)) < p.cfg.minMessageChars {
		return policy.DownstreamResponseModifications{}
	}

	res := p.evaluate(reply)
	if !res.offTopic {
		return policy.DownstreamResponseModifications{}
	}
	if p.cfg.onOffTopic == actionAnnotate {
		return policy.DownstreamResponseModifications{
			HeadersToSet:      map[string]string{"x-topic-scope": "off-topic"},
			AnalyticsMetadata: scopeAnalytics(res, "RESPONSE", "annotated"),
		}
	}
	return p.blockResponse("The reply drifted outside the assistant's configured scope.", res.reasons, res.score)
}

func (p *TopicScopeGuardrailPolicy) blockRequest(reason string, reasons []string, score float64) policy.RequestAction {
	return policy.ImmediateResponse{
		StatusCode:        guardrailCode,
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              buildEnvelope(reason, reasons, score, p.cfg.showAssessment, "REQUEST"),
		AnalyticsMetadata: map[string]any{"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "REQUEST"},
	}
}

func (p *TopicScopeGuardrailPolicy) blockResponse(reason string, reasons []string, score float64) policy.ResponseAction {
	sc := guardrailCode
	return policy.DownstreamResponseModifications{
		StatusCode:        &sc,
		HeadersToSet:      map[string]string{"Content-Type": "application/json"},
		Body:              buildEnvelope(reason, reasons, score, p.cfg.showAssessment, "RESPONSE"),
		AnalyticsMetadata: map[string]any{"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "RESPONSE"},
	}
}

func buildEnvelope(reason string, reasons []string, score float64, showAssessment bool, direction string) []byte {
	msg := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": guardrailName,
		"direction":            direction,
		"actionReason":         reason,
		"scopeScore":           score,
	}
	if showAssessment && len(reasons) > 0 {
		msg["assessments"] = reasons
	}
	b, _ := json.Marshal(map[string]interface{}{"type": guardrailType, "message": msg})
	return b
}

func scopeAnalytics(r evalResult, direction, action string) map[string]any {
	return map[string]any{
		"isGuardrailHit": true, "guardrailName": guardrailName, "direction": direction,
		"topicScopeAction": action, "scopeScore": r.score, "deniedTopicMatch": r.deniedMatch,
	}
}

// ─── evaluation ──────────────────────────────────────────────────────────────

type evalResult struct {
	offTopic    bool
	score       float64
	deniedMatch string
	reasons     []string
}

func (p *TopicScopeGuardrailPolicy) evaluate(message string) evalResult {
	res := evalResult{}
	lower := strings.ToLower(message)
	for _, denied := range p.cfg.deniedTopics {
		if strings.Contains(lower, denied) {
			res.offTopic = true
			res.deniedMatch = denied
			res.reasons = append(res.reasons, fmt.Sprintf("message matches a denied topic: %q", denied))
			return res
		}
	}

	words := contentWords(message)
	if len(words) == 0 {
		// Nothing meaningful to score (e.g. all stopwords/punctuation) -
		// don't penalize what we can't classify.
		res.score = 1
		return res
	}
	hit := 0
	for _, w := range words {
		if p.cfg.referenceWords[w] {
			hit++
		}
	}
	res.score = float64(hit) / float64(len(words))
	if res.score < p.cfg.minScopeScore {
		res.offTopic = true
		res.reasons = append(res.reasons, fmt.Sprintf("content-word overlap with the configured scope (%.2f) is below the %.2f minimum", res.score, p.cfg.minScopeScore))
	}
	return res
}

// ─── content-word extraction (same style as rag-grounding-guardrail) ────────

var wordRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9'\-]+`)

var stopwords = map[string]bool{
	"the": true, "a": true, "an": true, "and": true, "or": true, "but": true, "is": true, "are": true,
	"was": true, "were": true, "be": true, "been": true, "of": true, "to": true, "in": true, "on": true,
	"for": true, "with": true, "as": true, "at": true, "by": true, "it": true, "this": true, "that": true,
	"these": true, "those": true, "from": true, "which": true, "who": true, "what": true, "when": true,
	"where": true, "how": true, "can": true, "will": true, "would": true, "should": true, "may": true,
	"there": true, "their": true, "its": true, "has": true, "have": true, "had": true, "not": true,
	"you": true, "your": true, "we": true, "our": true, "they": true, "he": true, "she": true, "i": true,
	"me": true, "my": true, "do": true, "does": true, "did": true, "please": true, "could": true,
}

func contentWords(s string) []string {
	var out []string
	for _, w := range wordRe.FindAllString(strings.ToLower(s), -1) {
		if len(w) < 3 || stopwords[w] {
			continue
		}
		out = append(out, normalizeWord(w))
	}
	return out
}

// normalizeWord is a deliberately light plural/singular fold (not a real
// stemmer): a scope description written as "account balances" must still
// match a query asking about an "account balance" - a naive exact-word
// overlap would otherwise false-positive-block plenty of legitimately
// in-scope phrasing. Irregular plurals (e.g. "inquiries") aren't folded;
// that's an accepted limitation of a heuristic this lightweight.
func normalizeWord(w string) string {
	if len(w) > 4 && strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss") {
		return w[:len(w)-1]
	}
	return w
}

func contentWordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range contentWords(s) {
		m[w] = true
	}
	return m
}

// ─── minimal JSONPath (get only - this policy never rewrites bodies) ────────

func extractString(body []byte, path string) (string, bool, error) {
	if len(body) == 0 {
		return "", false, nil
	}
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return "", false, fmt.Errorf("body is not JSON")
	}
	v := valueAt(root, path)
	s, ok := v.(string)
	return s, ok, nil
}

func valueAt(root interface{}, jsonPath string) interface{} {
	cur := root
	p := strings.TrimPrefix(strings.TrimPrefix(jsonPath, "$"), ".")
	if p == "" {
		return cur
	}
	for _, comp := range strings.Split(p, ".") {
		if comp == "" {
			continue
		}
		key, idx, hasIdx := comp, 0, false
		if o := strings.IndexByte(comp, '['); o >= 0 && strings.HasSuffix(comp, "]") {
			key = comp[:o]
			hasIdx = true
			in := comp[o+1 : len(comp)-1]
			n, neg := 0, false
			for _, c := range in {
				if c == '-' {
					neg = true
					continue
				}
				if c < '0' || c > '9' {
					n = 0
					break
				}
				n = n*10 + int(c-'0')
			}
			if neg {
				n = -n
			}
			idx = n
		}
		if key != "" {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return nil
			}
			cur = m[key]
		}
		if hasIdx {
			a, ok := cur.([]interface{})
			if !ok || len(a) == 0 {
				return nil
			}
			switch {
			case idx < 0:
				if -idx > len(a) {
					return nil
				}
				cur = a[len(a)+idx]
			case idx < len(a):
				cur = a[idx]
			default:
				return nil
			}
		}
	}
	return cur
}

// ─── param helpers ───────────────────────────────────────────────────────────

func wrap(err error) error { return fmt.Errorf("invalid params: %w", err) }

func strOpt(m map[string]interface{}, k string, dst *string) {
	if s, ok := m[k].(string); ok && s != "" {
		*dst = s
	}
}

func boolParam(m map[string]interface{}, k string, dst *bool) error {
	if v, ok := m[k]; ok {
		b, ok := v.(bool)
		if !ok {
			return fmt.Errorf("'%s' must be a boolean", k)
		}
		*dst = b
	}
	return nil
}

func toFloat(v interface{}) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case json.Number:
		return n.Float64()
	default:
		return 0, fmt.Errorf("not a number")
	}
}
