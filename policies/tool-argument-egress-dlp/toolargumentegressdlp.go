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

// Package toolargumentegressdlp scans an agent's outbound tool-call arguments for
// secrets and PII before they leave the boundary (OWASP LLM02; Agentic T2
// tool-based exfiltration) and blocks, redacts, or annotates.
package toolargumentegressdlp

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	dlpErrorCode = 422
	dlpType      = "TOOL_ARGUMENT_EGRESS_DLP"
	dlpName      = "ToolArgumentEgressDlp"

	actionBlock    = "block"
	actionRedact   = "redact"
	actionAnnotate = "annotate"
)

// ─── config ──────────────────────────────────────────────────────────────────

type customPat struct {
	name     string
	category string
	re       *regexp.Regexp
}

type config struct {
	argsPath       string
	extraPaths     []string
	onDetected     string
	secretsEnabled bool
	entropyEnabled bool
	minEntropyBits float64
	entropyMinLen  int
	piiEnabled     bool
	piiCategories  map[string]bool
	allowValues    map[string]bool
	customPatterns []customPat
	showAssessment bool
	passthrough    bool
	maxScanBytes   int
}

// ToolArgumentEgressDlpPolicy implements the v1alpha2 policy interface.
type ToolArgumentEgressDlpPolicy struct{ cfg config }

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		argsPath:       "$.params.arguments",
		onDetected:     actionBlock,
		secretsEnabled: true,
		entropyEnabled: true,
		minEntropyBits: 3.5,
		entropyMinLen:  24,
		piiEnabled:     true,
		piiCategories:  map[string]bool{"ssn": true, "creditCard": true, "iban": true},
		allowValues:    map[string]bool{},
		maxScanBytes:   262144,
	}

	strOpt(params, "argumentsJsonPath", &cfg.argsPath)
	if err := boolOpt(params, "showAssessment", &cfg.showAssessment); err != nil {
		return nil, wrap(err)
	}
	if err := boolOpt(params, "passthroughOnError", &cfg.passthrough); err != nil {
		return nil, wrap(err)
	}
	if v, ok := params["onDetected"]; ok {
		s, _ := v.(string)
		if s != actionBlock && s != actionRedact && s != actionAnnotate {
			return nil, wrap(fmt.Errorf("'onDetected' must be one of block, redact, annotate"))
		}
		cfg.onDetected = s
	}
	if v, ok := params["maxScanBytes"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 1024 {
			return nil, wrap(fmt.Errorf("'maxScanBytes' must be >= 1024"))
		}
		cfg.maxScanBytes = int(f)
	}
	for _, e := range strSlice(params["additionalJsonPaths"]) {
		cfg.extraPaths = append(cfg.extraPaths, e)
	}
	for _, e := range strSlice(params["allowValues"]) {
		cfg.allowValues[e] = true
	}

	if d, ok := params["detectors"].(map[string]interface{}); ok {
		if s, ok := d["secrets"].(map[string]interface{}); ok {
			_ = boolOpt(s, "enabled", &cfg.secretsEnabled)
			_ = boolOpt(s, "entropyEnabled", &cfg.entropyEnabled)
			if v, ok := s["minEntropyBits"]; ok {
				f, err := toFloat(v)
				if err != nil || f < 0 {
					return nil, wrap(fmt.Errorf("'detectors.secrets.minEntropyBits' must be >= 0"))
				}
				cfg.minEntropyBits = f
			}
			if v, ok := s["entropyMinLength"]; ok {
				f, err := toFloat(v)
				if err != nil || f < 8 {
					return nil, wrap(fmt.Errorf("'detectors.secrets.entropyMinLength' must be >= 8"))
				}
				cfg.entropyMinLen = int(f)
			}
		}
		if pi, ok := d["pii"].(map[string]interface{}); ok {
			_ = boolOpt(pi, "enabled", &cfg.piiEnabled)
			if cats, ok := pi["categories"].([]interface{}); ok {
				cfg.piiCategories = map[string]bool{}
				for _, c := range cats {
					if s, ok := c.(string); ok {
						cfg.piiCategories[s] = true
					}
				}
			}
		}
	}

	if arr, ok := params["customPatterns"].([]interface{}); ok {
		for i, e := range arr {
			em, ok := e.(map[string]interface{})
			if !ok {
				return nil, wrap(fmt.Errorf("customPatterns[%d] must be an object", i))
			}
			name, _ := em["name"].(string)
			rx, _ := em["regex"].(string)
			if name == "" || rx == "" {
				return nil, wrap(fmt.Errorf("customPatterns[%d] needs name and regex", i))
			}
			re, err := regexp.Compile(rx)
			if err != nil {
				return nil, wrap(fmt.Errorf("customPatterns[%d].regex: %w", i, err))
			}
			cat := "custom"
			if c, ok := em["category"].(string); ok && c != "" {
				cat = c
			}
			cfg.customPatterns = append(cfg.customPatterns, customPat{name: name, category: cat, re: re})
		}
	}

	if !cfg.secretsEnabled && !cfg.piiEnabled && len(cfg.customPatterns) == 0 {
		return nil, wrap(fmt.Errorf("no detectors enabled - the policy would do nothing"))
	}
	return &ToolArgumentEgressDlpPolicy{cfg: cfg}, nil
}

// Mode buffers the request body only.
func (p *ToolArgumentEgressDlpPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody scans the outbound tool arguments.
func (p *ToolArgumentEgressDlpPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	if p.cfg.maxScanBytes > 0 && len(body) > p.cfg.maxScanBytes {
		if p.cfg.passthrough {
			return policy.UpstreamRequestModifications{}
		}
		return p.block([]finding{{Category: "unscannable", Detector: "size", Path: "$", Excerpt: "request larger than maxScanBytes"}})
	}
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		if p.cfg.passthrough {
			return policy.UpstreamRequestModifications{}
		}
		return p.block([]finding{{Category: "error", Detector: "json", Path: "$", Excerpt: "request body is not JSON"}})
	}

	targets := append([]string{p.cfg.argsPath}, p.cfg.extraPaths...)
	var findings []finding
	changed := false
	for _, tp := range targets {
		node, container, key := locate(root, tp)
		if node == nil {
			continue
		}
		red, fs := p.scanValue(node, tp)
		findings = append(findings, fs...)
		if p.cfg.onDetected == actionRedact && len(fs) > 0 {
			putBack(container, key, red)
			changed = true
		}
	}

	if len(findings) == 0 {
		return policy.UpstreamRequestModifications{}
	}
	switch p.cfg.onDetected {
	case actionAnnotate:
		return policy.UpstreamRequestModifications{
			HeadersToSet:      dlpHeaders(findings),
			AnalyticsMetadata: dlpAnalytics(findings, "annotated"),
		}
	case actionRedact:
		if !changed {
			return policy.UpstreamRequestModifications{HeadersToSet: dlpHeaders(findings)}
		}
		nb, err := json.Marshal(root)
		if err != nil {
			return p.block(findings)
		}
		return policy.UpstreamRequestModifications{
			Body:              nb,
			HeadersToSet:      merge(dlpHeaders(findings), map[string]string{"Content-Type": "application/json", "x-egress-dlp-action": "redacted"}),
			AnalyticsMetadata: dlpAnalytics(findings, "redacted"),
		}
	default:
		return p.block(findings)
	}
}

func (p *ToolArgumentEgressDlpPolicy) block(findings []finding) policy.RequestAction {
	cats := distinctCategories(findings)
	msg := map[string]interface{}{
		"action":              "EGRESS_BLOCKED",
		"interveningGuardrail": dlpName,
		"direction":           "REQUEST",
		"actionReason":        "The tool call carries " + strings.Join(cats, " / ") + " that must not leave the boundary.",
	}
	if p.cfg.showAssessment {
		msg["assessments"] = redactExcerpts(findings)
	}
	b, _ := json.Marshal(map[string]interface{}{"type": dlpType, "message": msg})
	return policy.ImmediateResponse{
		StatusCode:        dlpErrorCode,
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              b,
		AnalyticsMetadata: dlpAnalytics(findings, "blocked"),
	}
}

// ─── scanning ────────────────────────────────────────────────────────────────

type finding struct {
	Category string `json:"category"`
	Detector string `json:"detector"`
	Path     string `json:"path"`
	Excerpt  string `json:"excerpt,omitempty"`
}

// scanValue walks v, returning a redacted copy plus findings.
func (p *ToolArgumentEgressDlpPolicy) scanValue(v interface{}, path string) (interface{}, []finding) {
	switch t := v.(type) {
	case string:
		red, fs := p.scanString(t, path)
		return red, fs
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		var fs []finding
		for k, val := range t {
			r, f := p.scanValue(val, path+"."+k)
			out[k] = r
			fs = append(fs, f...)
		}
		return out, fs
	case []interface{}:
		out := make([]interface{}, len(t))
		var fs []finding
		for i, val := range t {
			r, f := p.scanValue(val, fmt.Sprintf("%s[%d]", path, i))
			out[i] = r
			fs = append(fs, f...)
		}
		return out, fs
	default:
		return v, nil
	}
}

func (p *ToolArgumentEgressDlpPolicy) scanString(s, path string) (string, []finding) {
	if p.cfg.allowValues[s] {
		return s, nil
	}
	var fs []finding
	redacted := s

	apply := func(re *regexp.Regexp, category, detector string) {
		for _, loc := range re.FindAllStringIndex(redacted, -1) {
			match := redacted[loc[0]:loc[1]]
			if p.cfg.allowValues[match] {
				continue
			}
			fs = append(fs, finding{Category: category, Detector: detector, Path: path, Excerpt: mask(match)})
		}
		redacted = re.ReplaceAllString(redacted, "[REDACTED:"+category+"]")
	}

	if p.cfg.secretsEnabled {
		for _, sp := range secretPatterns {
			apply(sp.re, "secret", sp.name)
		}
	}
	if p.cfg.piiEnabled {
		for _, pp := range piiPatterns {
			if !p.cfg.piiCategories[pp.name] {
				continue
			}
			if pp.name == "creditCard" {
				// Luhn-check each candidate so we don't flag arbitrary long digit runs.
				for _, loc := range pp.re.FindAllStringIndex(redacted, -1) {
					m := redacted[loc[0]:loc[1]]
					if luhnValid(m) && !p.cfg.allowValues[m] {
						fs = append(fs, finding{Category: "pii", Detector: "creditCard", Path: path, Excerpt: mask(m)})
					}
				}
				redacted = pp.re.ReplaceAllStringFunc(redacted, func(m string) string {
					if luhnValid(m) {
						return "[REDACTED:pii]"
					}
					return m
				})
				continue
			}
			apply(pp.re, "pii", pp.name)
		}
	}
	for _, cp := range p.cfg.customPatterns {
		apply(cp.re, cp.category, cp.name)
	}

	if p.cfg.secretsEnabled && p.cfg.entropyEnabled {
		for _, tok := range entropyCandidate.FindAllString(s, -1) {
			if len(tok) < p.cfg.entropyMinLen || p.cfg.allowValues[tok] {
				continue
			}
			if shannonBits(tok) >= p.cfg.minEntropyBits && !alreadyFound(fs, tok) {
				fs = append(fs, finding{Category: "secret", Detector: "highEntropy", Path: path, Excerpt: mask(tok)})
				redacted = strings.ReplaceAll(redacted, tok, "[REDACTED:secret]")
			}
		}
	}
	return redacted, fs
}

func alreadyFound(fs []finding, tok string) bool {
	m := mask(tok)
	for _, f := range fs {
		if f.Excerpt == m {
			return true
		}
	}
	return false
}

var (
	entropyCandidate = regexp.MustCompile(`[A-Za-z0-9+/_\-]{16,}`)

	secretPatterns = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"awsAccessKeyId", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
		{"awsSecretKey", regexp.MustCompile(`(?i)aws_secret_access_key["'\s:=]+([A-Za-z0-9/+]{40})`)},
		{"githubToken", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
		{"slackToken", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
		{"googleApiKey", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
		{"stripeKey", regexp.MustCompile(`\bsk_(live|test)_[0-9A-Za-z]{20,}\b`)},
		{"privateKeyBlock", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
		{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b`)},
		{"bearerToken", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}`)},
		{"dsnWithCreds", regexp.MustCompile(`(?i)\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:/@]+:[^\s:/@]+@`)},
	}

	piiPatterns = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"email", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
		{"phone", regexp.MustCompile(`\b(\+?\d{1,3}[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b`)},
		{"ssn", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
		{"creditCard", regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)},
		{"iban", regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)},
	}
)

func luhnValid(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	dbl := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if dbl {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		dbl = !dbl
	}
	return sum%10 == 0
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

// ─── locate / put back a node by dot-path ──────────────────────────────────

func locate(root interface{}, jsonPath string) (node, container interface{}, key string) {
	p := strings.TrimPrefix(strings.TrimPrefix(jsonPath, "$"), ".")
	if p == "" {
		return root, nil, ""
	}
	comps := strings.Split(p, ".")
	cur := root
	var parent interface{}
	var pkey string
	for _, comp := range comps {
		if comp == "" {
			continue
		}
		k, idx, hasIdx := comp, 0, false
		if o := strings.IndexByte(comp, '['); o >= 0 && strings.HasSuffix(comp, "]") {
			k = comp[:o]
			hasIdx = true
			fmt.Sscanf(comp[o+1:len(comp)-1], "%d", &idx)
		}
		if k != "" {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return nil, nil, ""
			}
			v, ok := m[k]
			if !ok {
				return nil, nil, ""
			}
			parent, pkey, cur = cur, k, v
		}
		if hasIdx {
			a, ok := cur.([]interface{})
			if !ok || idx < 0 || idx >= len(a) {
				return nil, nil, ""
			}
			parent, pkey, cur = cur, fmt.Sprintf("[%d]", idx), a[idx]
		}
	}
	return cur, parent, pkey
}

func putBack(container interface{}, key string, value interface{}) {
	if container == nil {
		return
	}
	if strings.HasPrefix(key, "[") {
		var idx int
		fmt.Sscanf(key, "[%d]", &idx)
		if a, ok := container.([]interface{}); ok && idx >= 0 && idx < len(a) {
			a[idx] = value
		}
		return
	}
	if m, ok := container.(map[string]interface{}); ok {
		m[key] = value
	}
}

// ─── output helpers ─────────────────────────────────────────────────────────

func mask(s string) string {
	s = strings.TrimSpace(s)
	n := utf8.RuneCountInString(s)
	if n <= 8 {
		return "***"
	}
	r := []rune(s)
	return string(r[:3]) + "…" + string(r[n-2:])
}

func redactExcerpts(fs []finding) []finding {
	out := make([]finding, 0, len(fs))
	seen := map[string]bool{}
	for _, f := range fs {
		k := f.Category + "|" + f.Detector + "|" + f.Path
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

func distinctCategories(fs []finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if !seen[f.Category] {
			seen[f.Category] = true
			out = append(out, f.Category)
		}
	}
	return out
}

func dlpHeaders(fs []finding) map[string]string {
	return map[string]string{
		"x-egress-dlp":            "hit",
		"x-egress-dlp-categories": strings.Join(distinctCategories(fs), ","),
		"x-egress-dlp-count":      fmt.Sprintf("%d", len(fs)),
	}
}
func dlpAnalytics(fs []finding, action string) map[string]any {
	return map[string]any{
		"isGuardrailHit":    true,
		"guardrailName":     dlpName,
		"direction":         "REQUEST",
		"egressDlpAction":   action,
		"egressDlpCategories": distinctCategories(fs),
		"egressDlpCount":    len(fs),
	}
}
func merge(a, b map[string]string) map[string]string {
	for k, v := range b {
		a[k] = v
	}
	return a
}

// ─── param helpers ──────────────────────────────────────────────────────────

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
