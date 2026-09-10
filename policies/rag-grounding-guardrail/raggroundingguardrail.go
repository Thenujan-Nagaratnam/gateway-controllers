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

// Package raggroundingguardrail flags RAG answers that are not grounded in the
// retrieved context (OWASP LLM09): deterministic sentence-overlap grounding
// score plus unsupported-specific and citation checks, with block / warn /
// annotate actions.
package raggroundingguardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	guardrailCode = 422
	guardrailType = "RAG_GROUNDING_GUARDRAIL"
	guardrailName = "RagGroundingGuardrail"

	answerDefaultPath = "$.choices[0].message.content"

	actionBlock    = "block"
	actionWarn     = "warn"
	actionAnnotate = "annotate"

	sentenceSupportThreshold = 0.34
)

type config struct {
	contextRoles     map[string]bool
	contextPaths     []string
	answerPath       string
	minScore         float64
	onLow            string
	warnText         string
	requireCitations bool
	citationRe       *regexp.Regexp
	checkSpecifics   bool
	maxSpecifics     int
	minAnswerChars   int
	showAssessment   bool
	passthrough      bool
}

// RagGroundingGuardrailPolicy implements the v1alpha2 policy interface.
type RagGroundingGuardrailPolicy struct{ cfg config }

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		contextRoles:   map[string]bool{"tool": true},
		answerPath:     answerDefaultPath,
		minScore:       0.45,
		onLow:          actionAnnotate,
		warnText:       "\n\n_Note: parts of this answer may not be fully supported by the retrieved sources._",
		checkSpecifics: true,
		minAnswerChars: 40,
	}
	cfg.citationRe = regexp.MustCompile(`\[[0-9A-Za-z\-]+\]|\(source:[^)]+\)`)

	if roles := strSlice(params["contextRoles"]); roles != nil {
		cfg.contextRoles = map[string]bool{}
		for _, r := range roles {
			cfg.contextRoles[strings.ToLower(r)] = true
		}
	}
	cfg.contextPaths = strSlice(params["contextJsonPaths"])
	strOpt(params, "answerJsonPath", &cfg.answerPath)
	strOpt(params, "warnText", &cfg.warnText)
	if err := boolOpt(params, "requireCitations", &cfg.requireCitations); err != nil {
		return nil, wrap(err)
	}
	if err := boolOpt(params, "checkUnsupportedSpecifics", &cfg.checkSpecifics); err != nil {
		return nil, wrap(err)
	}
	if err := boolOpt(params, "showAssessment", &cfg.showAssessment); err != nil {
		return nil, wrap(err)
	}
	if err := boolOpt(params, "passthroughOnError", &cfg.passthrough); err != nil {
		return nil, wrap(err)
	}
	if v, ok := params["minGroundingScore"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 0 || f > 1 {
			return nil, wrap(fmt.Errorf("'minGroundingScore' must be a number in [0,1]"))
		}
		cfg.minScore = f
	}
	if v, ok := params["onLowGrounding"]; ok {
		s, _ := v.(string)
		if s != actionBlock && s != actionWarn && s != actionAnnotate {
			return nil, wrap(fmt.Errorf("'onLowGrounding' must be one of block, warn, annotate"))
		}
		cfg.onLow = s
	}
	if v, ok := params["maxUnsupportedSpecifics"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 0 {
			return nil, wrap(fmt.Errorf("'maxUnsupportedSpecifics' must be >= 0"))
		}
		cfg.maxSpecifics = int(f)
	}
	if v, ok := params["minAnswerChars"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 1 {
			return nil, wrap(fmt.Errorf("'minAnswerChars' must be >= 1"))
		}
		cfg.minAnswerChars = int(f)
	}
	if v, ok := params["citationPattern"]; ok {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, wrap(fmt.Errorf("'citationPattern' must be a non-empty string"))
		}
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, wrap(fmt.Errorf("'citationPattern': %w", err))
		}
		cfg.citationRe = re
	}
	return &RagGroundingGuardrailPolicy{cfg: cfg}, nil
}

// Mode buffers the response body only.
func (p *RagGroundingGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// OnResponseBody grades the answer against the retrieved context.
func (p *RagGroundingGuardrailPolicy) OnResponseBody(_ context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	var respBody, reqBody []byte
	if respCtx.ResponseBody != nil {
		respBody = respCtx.ResponseBody.Content
	}
	if respCtx.RequestBody != nil {
		reqBody = respCtx.RequestBody.Content
	}

	answer, ok, err := extractString(respBody, p.cfg.answerPath)
	if err != nil {
		slog.Warn("RagGroundingGuardrail: could not read the answer", "error", err.Error())
		if p.cfg.passthrough {
			return policy.DownstreamResponseModifications{}
		}
		return p.block("Unable to evaluate answer grounding.", nil, 0)
	}
	if !ok || utf8.RuneCountInString(strings.TrimSpace(answer)) < p.cfg.minAnswerChars {
		return policy.DownstreamResponseModifications{}
	}

	contextText := p.gatherContext(reqBody)
	if strings.TrimSpace(contextText) == "" {
		// Nothing was retrieved - not a RAG turn; don't grade.
		return policy.DownstreamResponseModifications{}
	}

	res := grade(answer, contextText, p.cfg)
	if !res.low {
		return policy.DownstreamResponseModifications{
			HeadersToSet: map[string]string{"x-grounding-score": fmt.Sprintf("%.2f", res.score)},
		}
	}

	switch p.cfg.onLow {
	case actionAnnotate:
		return policy.DownstreamResponseModifications{
			HeadersToSet:      groundingHeaders(res),
			AnalyticsMetadata: groundingAnalytics(res, "annotated"),
		}
	case actionWarn:
		nb, werr := setString(respBody, p.cfg.answerPath, answer+p.cfg.warnText)
		if werr != nil {
			if p.cfg.passthrough {
				return policy.DownstreamResponseModifications{}
			}
			return p.block("Low answer grounding; could not attach a warning.", res.reasons, res.score)
		}
		return policy.DownstreamResponseModifications{
			Body:              nb,
			HeadersToSet:      merge(groundingHeaders(res), map[string]string{"Content-Type": "application/json", "x-grounding-action": "warned"}),
			AnalyticsMetadata: groundingAnalytics(res, "warned"),
		}
	default:
		return p.block("The answer is not sufficiently grounded in the retrieved context.", res.reasons, res.score)
	}
}

func (p *RagGroundingGuardrailPolicy) block(reason string, reasons []string, score float64) policy.ResponseAction {
	sc := guardrailCode
	msg := map[string]interface{}{
		"action":              "GUARDRAIL_INTERVENED",
		"interveningGuardrail": guardrailName,
		"direction":           "RESPONSE",
		"actionReason":        reason,
		"groundingScore":      score,
	}
	if p.cfg.showAssessment && len(reasons) > 0 {
		msg["assessments"] = reasons
	}
	b, _ := json.Marshal(map[string]interface{}{"type": guardrailType, "message": msg})
	return policy.DownstreamResponseModifications{
		StatusCode:        &sc,
		HeadersToSet:      map[string]string{"Content-Type": "application/json", "x-grounding-score": fmt.Sprintf("%.2f", score)},
		Body:              b,
		AnalyticsMetadata: map[string]any{"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "RESPONSE"},
	}
}

// ─── context gathering ───────────────────────────────────────────────────────

func (p *RagGroundingGuardrailPolicy) gatherContext(reqBody []byte) string {
	if len(reqBody) == 0 {
		return ""
	}
	var payload map[string]interface{}
	if json.Unmarshal(reqBody, &payload) != nil {
		return ""
	}
	var parts []string
	if msgs, ok := payload["messages"].([]interface{}); ok {
		for _, m := range msgs {
			mm, ok := m.(map[string]interface{})
			if !ok {
				continue
			}
			role, _ := mm["role"].(string)
			if p.cfg.contextRoles[strings.ToLower(role)] {
				parts = append(parts, stringify(mm["content"]))
			}
		}
	}
	for _, jp := range p.cfg.contextPaths {
		collectStrings(valueAt(payload, jp), &parts)
	}
	return strings.Join(parts, "\n")
}

func collectStrings(v interface{}, out *[]string) {
	switch t := v.(type) {
	case string:
		if t != "" {
			*out = append(*out, t)
		}
	case []interface{}:
		for _, e := range t {
			collectStrings(e, out)
		}
	case map[string]interface{}:
		for _, e := range t {
			collectStrings(e, out)
		}
	}
}

// ─── grading ─────────────────────────────────────────────────────────────────

type gradeResult struct {
	low     bool
	score   float64
	reasons []string
	unsup   []string
}

var (
	sentSplit  = regexp.MustCompile(`(?:[.!?]+["')\]]*\s+|\n+)`)
	numRe      = regexp.MustCompile(`\b\d[\d,.]*%?\b`)
	properRe   = regexp.MustCompile(`\b[A-Z][a-z]{2,}(?:\s+(?:[A-Z][a-z]+|of|the|and|for|de|van|von))*\s+[A-Z][a-z]{2,}\b`)
	urlRe      = regexp.MustCompile(`https?://[^\s)>\]]+`)
	emailRe    = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	yearRe     = regexp.MustCompile(`\b(1[0-9]{3}|20[0-9]{2})\b`)
	wordRe     = regexp.MustCompile(`[A-Za-z][A-Za-z0-9'\-]+`)
)

func grade(answer, contextText string, cfg config) gradeResult {
	res := gradeResult{}
	ctxLower := strings.ToLower(contextText)
	ctxTri := trigramSet(contextText)
	ctxWords := contentWordSet(contextText)

	// sentence-support score
	var supportedChars, totalChars float64
	for _, s := range splitSentences(answer) {
		st := strings.TrimSpace(s)
		if len(st) < 3 {
			continue
		}
		totalChars += float64(len(st))
		if sentenceSupported(st, ctxTri, ctxWords) {
			supportedChars += float64(len(st))
		}
	}
	if totalChars == 0 {
		res.score = 1
	} else {
		res.score = supportedChars / totalChars
	}

	// unsupported specifics
	if cfg.checkSpecifics {
		for _, sp := range extractSpecifics(answer) {
			if !specificInContext(sp, ctxLower) {
				res.unsup = append(res.unsup, sp)
			}
		}
	}

	// citations
	missingCitation := false
	if cfg.requireCitations && !cfg.citationRe.MatchString(answer) {
		missingCitation = true
	}

	if res.score < cfg.minScore {
		res.low = true
		res.reasons = append(res.reasons, fmt.Sprintf("grounding score %.2f is below the %.2f minimum", res.score, cfg.minScore))
	}
	if len(res.unsup) > cfg.maxSpecifics {
		res.low = true
		show := res.unsup
		if len(show) > 5 {
			show = show[:5]
		}
		res.reasons = append(res.reasons, fmt.Sprintf("%d specific claim(s) not found in the context: %s", len(res.unsup), strings.Join(show, ", ")))
	}
	if missingCitation {
		res.low = true
		res.reasons = append(res.reasons, "answer makes claims but contains no citation marker")
	}
	return res
}

func splitSentences(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	parts := sentSplit.Split(s, -1)
	var out []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

func sentenceSupported(sentence string, ctxTri map[string]bool, ctxWords map[string]bool) bool {
	tri := trigramSet(sentence)
	if len(tri) > 0 {
		hit := 0
		for t := range tri {
			if ctxTri[t] {
				hit++
			}
		}
		if float64(hit)/float64(len(tri)) >= sentenceSupportThreshold {
			return true
		}
	}
	// short sentence fallback: content-word overlap
	words := contentWords(sentence)
	if len(words) == 0 {
		return true
	}
	hit := 0
	for _, w := range words {
		if ctxWords[w] {
			hit++
		}
	}
	return float64(hit)/float64(len(words)) >= 0.6
}

var stopwords = map[string]bool{
	"the": true, "a": true, "an": true, "and": true, "or": true, "but": true, "is": true, "are": true,
	"was": true, "were": true, "be": true, "been": true, "of": true, "to": true, "in": true, "on": true,
	"for": true, "with": true, "as": true, "at": true, "by": true, "it": true, "this": true, "that": true,
	"these": true, "those": true, "from": true, "which": true, "who": true, "what": true, "when": true,
	"where": true, "how": true, "can": true, "will": true, "would": true, "should": true, "may": true,
	"there": true, "their": true, "its": true, "has": true, "have": true, "had": true, "not": true,
	"you": true, "your": true, "we": true, "our": true, "they": true, "he": true, "she": true, "i": true,
}

func contentWords(s string) []string {
	var out []string
	for _, w := range wordRe.FindAllString(strings.ToLower(s), -1) {
		if len(w) < 3 || stopwords[w] {
			continue
		}
		out = append(out, w)
	}
	return out
}
func contentWordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range contentWords(s) {
		m[w] = true
	}
	return m
}
func trigramSet(s string) map[string]bool {
	words := contentWords(s)
	m := map[string]bool{}
	for i := 0; i+3 <= len(words); i++ {
		m[words[i]+" "+words[i+1]+" "+words[i+2]] = true
	}
	if len(words) < 3 && len(words) > 0 {
		m[strings.Join(words, " ")] = true
	}
	return m
}

func extractSpecifics(answer string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(list []string) {
		for _, s := range list {
			k := strings.ToLower(strings.TrimSpace(s))
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, strings.TrimSpace(s))
		}
	}
	add(urlRe.FindAllString(answer, -1))
	add(emailRe.FindAllString(answer, -1))
	add(yearRe.FindAllString(answer, -1))
	add(numRe.FindAllString(answer, -1))
	add(properRe.FindAllString(answer, -1))
	return out
}

func specificInContext(sp, ctxLower string) bool {
	l := strings.ToLower(strings.TrimSpace(sp))
	if l == "" {
		return true
	}
	if strings.Contains(ctxLower, l) {
		return true
	}
	// numbers: also accept if the digits (comma/space stripped) appear
	if numRe.MatchString(sp) || yearRe.MatchString(sp) {
		digits := strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) {
				return r
			}
			return -1
		}, sp)
		if digits != "" && strings.Contains(strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) {
				return r
			}
			return -1
		}, ctxLower), digits) {
			return true
		}
	}
	return false
}

// ─── output helpers ─────────────────────────────────────────────────────────

func groundingHeaders(r gradeResult) map[string]string {
	return map[string]string{
		"x-grounding":       "low",
		"x-grounding-score": fmt.Sprintf("%.2f", r.score),
	}
}
func groundingAnalytics(r gradeResult, action string) map[string]any {
	return map[string]any{
		"isGuardrailHit":       true,
		"guardrailName":        guardrailName,
		"direction":            "RESPONSE",
		"groundingScore":       r.score,
		"groundingAction":      action,
		"unsupportedSpecifics": r.unsup,
	}
}
func merge(a, b map[string]string) map[string]string {
	for k, v := range b {
		a[k] = v
	}
	return a
}

// ─── JSON get/set + helpers ────────────────────────────────────────────────

func extractString(body []byte, path string) (string, bool, error) {
	if len(body) == 0 {
		return "", false, nil
	}
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return "", false, fmt.Errorf("body is not JSON")
	}
	v := valueAt(root, path)
	switch t := v.(type) {
	case string:
		return t, true, nil
	case nil:
		return "", false, nil
	default:
		return "", false, nil
	}
}
func setString(body []byte, path, value string) ([]byte, error) {
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, err
	}
	if err := assign(root, path, value); err != nil {
		return nil, err
	}
	return json.Marshal(root)
}
func stringify(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []interface{}:
		var b strings.Builder
		for _, e := range t {
			if m, ok := e.(map[string]interface{}); ok {
				if s, ok := m["text"].(string); ok {
					b.WriteString(s)
					b.WriteByte('\n')
				}
			}
		}
		return b.String()
	default:
		return ""
	}
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
			if in == "*" {
				idx = -1 << 30
			} else {
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
			case idx == -1<<30:
				return a // caller collectStrings handles the slice
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

func assign(root interface{}, jsonPath, value string) error {
	p := strings.TrimPrefix(strings.TrimPrefix(jsonPath, "$"), ".")
	comps := strings.Split(p, ".")
	cur := root
	for i, comp := range comps {
		if comp == "" {
			continue
		}
		last := i == len(comps)-1
		key, idx, hasIdx := comp, 0, false
		if o := strings.IndexByte(comp, '['); o >= 0 && strings.HasSuffix(comp, "]") {
			key = comp[:o]
			hasIdx = true
			fmt.Sscanf(comp[o+1:len(comp)-1], "%d", &idx)
		}
		if key != "" {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return fmt.Errorf("not object")
			}
			if last && !hasIdx {
				m[key] = value
				return nil
			}
			v, ok := m[key]
			if !ok {
				return fmt.Errorf("missing")
			}
			cur = v
		}
		if hasIdx {
			a, ok := cur.([]interface{})
			if !ok || idx < 0 || idx >= len(a) {
				return fmt.Errorf("bad index")
			}
			if last {
				a[idx] = value
				return nil
			}
			cur = a[idx]
		}
	}
	return fmt.Errorf("unset")
}

func wrap(err error) error { return fmt.Errorf("invalid params: %w", err) }
func strOpt(m map[string]interface{}, k string, dst *string) {
	if s, ok := m[k].(string); ok && s != "" {
		*dst = s
	}
}
func boolOpt(m map[string]interface{}, k string, dst *bool) error {
	if v, ok := m[k]; ok {
		b, ok := v.(bool)
		if !ok {
			return fmt.Errorf("'%s' must be a boolean", k)
		}
		*dst = b
	}
	return nil
}
func strSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
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
