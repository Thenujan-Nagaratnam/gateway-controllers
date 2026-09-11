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

// Package embeddinginputguardrail protects what gets embedded/stored, not
// just what gets read back at generation time (OWASP Top 10 for LLM
// Applications 2026: LLM09 - Vector and Embedding Weaknesses). See
// policy-definition.yaml for the full behavior.
package embeddinginputguardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	guardrailCode = 422
	guardrailType = "EMBEDDING_INPUT_GUARDRAIL"
	guardrailName = "EmbeddingInputGuardrail"

	actionBlock    = "block"
	actionAnnotate = "annotate"
)

type config struct {
	textPath       string
	maxInputChars  int
	maxBatchSize   int
	scanInjection  bool
	maxEntropyBits float64
	entropyMinLen  int
	onViolation    string
	showAssessment bool
	passthrough    bool
}

// EmbeddingInputGuardrailPolicy implements the v1alpha2 policy interface.
type EmbeddingInputGuardrailPolicy struct{ cfg config }

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		textPath:       "$.input",
		maxInputChars:  8192,
		maxBatchSize:   100,
		scanInjection:  true,
		maxEntropyBits: 4.0,
		entropyMinLen:  24,
		onViolation:    actionBlock,
	}

	strOpt(params, "textJsonPath", &cfg.textPath)

	if v, ok := params["maxInputChars"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 1 {
			return nil, wrap(fmt.Errorf("'maxInputChars' must be a number >= 1"))
		}
		cfg.maxInputChars = int(f)
	}
	if v, ok := params["maxBatchSize"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 1 {
			return nil, wrap(fmt.Errorf("'maxBatchSize' must be a number >= 1"))
		}
		cfg.maxBatchSize = int(f)
	}
	if err := boolParam(params, "scanForInjectionMarkers", &cfg.scanInjection); err != nil {
		return nil, wrap(err)
	}
	if v, ok := params["maxEntropyBits"]; ok {
		f, err := toFloat(v)
		if err != nil || f <= 0 {
			return nil, wrap(fmt.Errorf("'maxEntropyBits' must be a number > 0"))
		}
		cfg.maxEntropyBits = f
	}
	if v, ok := params["entropyMinLength"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 8 {
			return nil, wrap(fmt.Errorf("'entropyMinLength' must be a number >= 8"))
		}
		cfg.entropyMinLen = int(f)
	}
	if v, ok := params["onViolation"]; ok {
		s, _ := v.(string)
		if s != actionBlock && s != actionAnnotate {
			return nil, wrap(fmt.Errorf("'onViolation' must be block or annotate"))
		}
		cfg.onViolation = s
	}
	if err := boolParam(params, "showAssessment", &cfg.showAssessment); err != nil {
		return nil, wrap(err)
	}
	if err := boolParam(params, "passthroughOnError", &cfg.passthrough); err != nil {
		return nil, wrap(err)
	}

	return &EmbeddingInputGuardrailPolicy{cfg: cfg}, nil
}

// Mode buffers the request body only.
func (p *EmbeddingInputGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

type finding struct {
	itemIndex int
	category  string
	detail    string
}

// OnRequestBody bounds and scans the embedding input before it reaches the
// backend / vector store.
func (p *EmbeddingInputGuardrailPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		if p.cfg.passthrough {
			return policy.UpstreamRequestModifications{}
		}
		return p.block(nil, "The request body could not be evaluated.")
	}

	items, ok := normalizeInput(valueAt(root, p.cfg.textPath))
	if !ok {
		return policy.UpstreamRequestModifications{} // not an embeddings-shaped request at this path
	}

	var findings []finding
	if len(items) > p.cfg.maxBatchSize {
		findings = append(findings, finding{itemIndex: -1, category: "oversized_batch",
			detail: fmt.Sprintf("batch contains %d items, exceeding the %d item limit", len(items), p.cfg.maxBatchSize)})
	}

	for i, item := range items {
		if len(item) > p.cfg.maxInputChars {
			findings = append(findings, finding{itemIndex: i, category: "oversized_input",
				detail: fmt.Sprintf("item %d is %d characters, exceeding the %d character limit", i, len(item), p.cfg.maxInputChars)})
			continue // an oversized item isn't worth scanning further
		}
		if p.cfg.scanInjection {
			findings = append(findings, scanInjectionMarkers(i, item)...)
		}
		findings = append(findings, scanHighEntropy(i, item, p.cfg.entropyMinLen, p.cfg.maxEntropyBits)...)
	}

	if len(findings) == 0 {
		return policy.UpstreamRequestModifications{}
	}
	return p.violation(findings)
}

func (p *EmbeddingInputGuardrailPolicy) violation(findings []finding) policy.RequestAction {
	if p.cfg.onViolation == actionAnnotate {
		categories := categorySet(findings)
		return policy.UpstreamRequestModifications{
			HeadersToSet: map[string]string{"x-embedding-guard": "violation", "x-embedding-guard-categories": strings.Join(categories, ",")},
			AnalyticsMetadata: map[string]any{
				"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "REQUEST",
				"embeddingGuardCategories": categories,
			},
		}
	}
	return p.block(findings, "This input contains content that isn't permitted to be embedded/stored.")
}

func (p *EmbeddingInputGuardrailPolicy) block(findings []finding, reason string) policy.RequestAction {
	msg := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": guardrailName,
		"direction":            "REQUEST",
		"actionReason":         reason,
	}
	categories := categorySet(findings)
	if p.cfg.showAssessment && len(findings) > 0 {
		assessments := make([]string, 0, len(findings))
		for _, f := range findings {
			if f.itemIndex < 0 {
				assessments = append(assessments, fmt.Sprintf("%s: %s", f.category, f.detail))
			} else {
				assessments = append(assessments, fmt.Sprintf("item[%d] %s: %s", f.itemIndex, f.category, f.detail))
			}
		}
		msg["assessments"] = assessments
	}
	b, _ := json.Marshal(map[string]interface{}{"type": guardrailType, "message": msg})
	return policy.ImmediateResponse{
		StatusCode: guardrailCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       b,
		AnalyticsMetadata: map[string]any{
			"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "REQUEST",
			"embeddingGuardCategories": categories,
		},
	}
}

func categorySet(findings []finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if !seen[f.category] {
			seen[f.category] = true
			out = append(out, f.category)
		}
	}
	return out
}

// ─── input normalization: OpenAI embeddings "input" is a string OR []string ──

func normalizeInput(v interface{}) ([]string, bool) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil, false
		}
		return []string{t}, true
	case []interface{}:
		if len(t) == 0 {
			return nil, false
		}
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false // not a simple string array - not this policy's shape to judge
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

// ─── detectors ───────────────────────────────────────────────────────────────

// A lighter version of indirect-prompt-injection-guardrail's detectors,
// applied to content headed INTO a vector store rather than a live prompt.
var (
	imperativePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|above|preceding|earlier|foregoing)\s+(instructions?|prompts?|messages?|context|rules?|directions?)`),
		regexp.MustCompile(`(?i)disregard\s+(all\s+|the\s+|any\s+)?(previous|above|prior|preceding|earlier)\b`),
		regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(a|an|the|no longer)\b`),
		regexp.MustCompile(`(?i)\bnew\s+(system\s+)?(instructions?|prompt|rules?|persona|role)\s*[:\-]`),
		regexp.MustCompile(`(?i)(print|output|repeat|reveal|show|display|reproduce)\s+(your|the|all\s+of\s+your)\s+(system\s+|initial\s+|original\s+)?(prompt|instructions?|rules?|configuration)`),
		regexp.MustCompile(`(?i)override\s+(your|the|all)\s+(previous\s+|prior\s+)?(instructions?|rules?|settings?|guardrails?|safety)`),
	}

	delimiterLiterals = []string{
		"<|im_start|>", "<|im_end|>", "<|system|>", "<|user|>", "<|assistant|>",
		"<|endoftext|>", "<|eot_id|>", "<|start_header_id|>", "<|end_header_id|>",
		"[INST]", "[/INST]", "<<SYS>>", "<</SYS>>",
	}

	entropyCandidate = regexp.MustCompile(`[A-Za-z0-9+/_\-]{16,}`)
)

func scanInjectionMarkers(itemIndex int, text string) []finding {
	var out []finding
	for _, re := range imperativePatterns {
		if m := re.FindString(text); m != "" {
			out = append(out, finding{itemIndex: itemIndex, category: "imperative_override", detail: excerpt(m)})
			break
		}
	}
	for _, lit := range delimiterLiterals {
		if strings.Contains(text, lit) {
			out = append(out, finding{itemIndex: itemIndex, category: "template_delimiters", detail: lit})
			break
		}
	}
	if n, sample := countInvisible(text); n > 0 {
		out = append(out, finding{itemIndex: itemIndex, category: "invisible_unicode",
			detail: fmt.Sprintf("%d hidden/control character(s): %s", n, sample)})
	}
	return out
}

func scanHighEntropy(itemIndex int, text string, minLen int, maxBits float64) []finding {
	for _, tok := range entropyCandidate.FindAllString(text, -1) {
		if len(tok) < minLen {
			continue
		}
		if shannonBits(tok) >= maxBits {
			return []finding{{itemIndex: itemIndex, category: "high_entropy_blob", detail: fmt.Sprintf("token of length %d, ~%.1f bits/char", len(tok), shannonBits(tok))}}
		}
	}
	return nil
}

func shannonBits(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range freq {
		pv := c / n
		h -= pv * math.Log2(pv)
	}
	return h
}

func countInvisible(text string) (int, string) {
	var zeroWidth, hard int
	var samples []string
	for _, r := range text {
		if !isHiddenRune(r) {
			continue
		}
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || (r >= 0xE0000 && r <= 0xE007F) {
			hard++
		} else {
			zeroWidth++
		}
		if len(samples) < 5 {
			samples = append(samples, fmt.Sprintf("U+%04X", r))
		}
	}
	total := hard + zeroWidth
	if hard >= 1 || zeroWidth >= 3 {
		return total, strings.Join(samples, " ")
	}
	return 0, ""
}

func isHiddenRune(r rune) bool {
	switch {
	case r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF: // zero-width space/joiners/BOM
		return true
	case r >= 0x202A && r <= 0x202E: // bidi override controls
		return true
	case r >= 0x2066 && r <= 0x2069: // bidi isolate controls
		return true
	case r >= 0xE0000 && r <= 0xE007F: // Unicode tag characters
		return true
	default:
		return false
	}
}

func excerpt(s string) string {
	const max = 80
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ─── minimal read-only JSONPath ───────────────────────────────────────────────

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
