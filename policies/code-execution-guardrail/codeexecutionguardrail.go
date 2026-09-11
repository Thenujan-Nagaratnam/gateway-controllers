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

// Package codeexecutionguardrail is a static firewall for code-interpreter
// tool calls (OWASP Agentic AI Top 10: ASI05 - Unexpected Code Execution).
// Deterministic pattern matching, not a language parser or a sandbox - see
// policy-definition.yaml for the full detector list.
package codeexecutionguardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	guardrailCode = 422
	guardrailType = "CODE_EXECUTION_GUARDRAIL"
	guardrailName = "CodeExecutionGuardrail"

	actionBlock    = "block"
	actionAnnotate = "annotate"
)

type config struct {
	codeToolNames   []string
	toolNamePath    string
	codePath        string
	allowedFsPrefix []string
	maxCodeBytes    int
	onViolation     string
	showAssessment  bool
	passthrough     bool
}

// CodeExecutionGuardrailPolicy implements the v1alpha2 policy interface.
type CodeExecutionGuardrailPolicy struct{ cfg config }

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		toolNamePath:    "$.params.name",
		codePath:        "$.params.arguments.code",
		allowedFsPrefix: []string{"/tmp", "/workspace"},
		maxCodeBytes:    65536,
		onViolation:     actionBlock,
	}

	raw, ok := params["codeToolNames"].([]interface{})
	if !ok || len(raw) == 0 {
		return nil, wrap(fmt.Errorf("'codeToolNames' must be a non-empty array of tool names/globs"))
	}
	for _, e := range raw {
		s, ok := e.(string)
		if !ok || s == "" {
			return nil, wrap(fmt.Errorf("'codeToolNames' entries must be non-empty strings"))
		}
		cfg.codeToolNames = append(cfg.codeToolNames, s)
	}

	strOpt(params, "toolNameJsonPath", &cfg.toolNamePath)
	strOpt(params, "codeJsonPath", &cfg.codePath)

	if raw, ok := params["allowedFsPrefixes"]; ok {
		list, ok := raw.([]interface{})
		if !ok {
			return nil, wrap(fmt.Errorf("'allowedFsPrefixes' must be an array of strings"))
		}
		cfg.allowedFsPrefix = nil
		for _, e := range list {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, wrap(fmt.Errorf("'allowedFsPrefixes' entries must be non-empty strings"))
			}
			cfg.allowedFsPrefix = append(cfg.allowedFsPrefix, s)
		}
	}

	if v, ok := params["maxCodeBytes"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 1 {
			return nil, wrap(fmt.Errorf("'maxCodeBytes' must be a number >= 1"))
		}
		cfg.maxCodeBytes = int(f)
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

	return &CodeExecutionGuardrailPolicy{cfg: cfg}, nil
}

// Mode buffers the request body only.
func (p *CodeExecutionGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody scans a matching tool call's code argument for dangerous
// patterns before the call reaches the interpreter backend.
func (p *CodeExecutionGuardrailPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		if p.cfg.passthrough {
			return policy.UpstreamRequestModifications{}
		}
		return p.block("", nil, "The request body could not be evaluated.")
	}

	name, _ := valueAt(root, p.cfg.toolNamePath).(string)
	if name == "" || !p.matchesCodeTool(name) {
		return policy.UpstreamRequestModifications{}
	}

	code, ok := valueAt(root, p.cfg.codePath).(string)
	if !ok || code == "" {
		return policy.UpstreamRequestModifications{}
	}
	if len(code) > p.cfg.maxCodeBytes {
		return p.violation(name, []finding{{category: "oversized", detail: fmt.Sprintf("code body is %d bytes, exceeding the %d byte limit", len(code), p.cfg.maxCodeBytes)}})
	}

	findings := scan(code, p.cfg.allowedFsPrefix)
	if len(findings) == 0 {
		return policy.UpstreamRequestModifications{}
	}
	return p.violation(name, findings)
}

func (p *CodeExecutionGuardrailPolicy) matchesCodeTool(name string) bool {
	for _, pattern := range p.cfg.codeToolNames {
		if pattern == name {
			return true
		}
		if strings.ContainsAny(pattern, "*?") && globMatch(pattern, name) {
			return true
		}
	}
	return false
}

func (p *CodeExecutionGuardrailPolicy) violation(tool string, findings []finding) policy.RequestAction {
	if p.cfg.onViolation == actionAnnotate {
		categories := make([]string, 0, len(findings))
		for _, f := range findings {
			categories = append(categories, f.category)
		}
		return policy.UpstreamRequestModifications{
			HeadersToSet: map[string]string{"x-code-exec-guard": "violation", "x-code-exec-categories": strings.Join(categories, ",")},
			AnalyticsMetadata: map[string]any{
				"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "REQUEST",
				"codeExecTool": tool, "codeExecCategories": categories,
			},
		}
	}
	return p.block(tool, findings, "This code contains a pattern that isn't permitted to execute.")
}

func (p *CodeExecutionGuardrailPolicy) block(tool string, findings []finding, reason string) policy.RequestAction {
	msg := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": guardrailName,
		"direction":            "REQUEST",
		"actionReason":         reason,
	}
	if tool != "" {
		msg["tool"] = tool
	}
	categories := make([]string, 0, len(findings))
	for _, f := range findings {
		categories = append(categories, f.category)
	}
	if p.cfg.showAssessment && len(findings) > 0 {
		assessments := make([]string, 0, len(findings))
		for _, f := range findings {
			assessments = append(assessments, fmt.Sprintf("%s: %s", f.category, f.detail))
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
			"codeExecTool": tool, "codeExecCategories": categories,
		},
	}
}

// ─── detectors ───────────────────────────────────────────────────────────────

type finding struct {
	category string
	detail   string
}

// Note on trailing \b: for any alternative that ends in a literal "(" (a
// function-call form), we deliberately do NOT also require a trailing \b
// after it. "(" and a following quote (the overwhelmingly common case -
// exec('cmd'), __import__('os')) are both non-word characters, so a
// trailing \b would never match there - the \( itself already disambiguates
// a real call from a longer identifier, making the trailing boundary both
// unnecessary and actively wrong. The leading \b is still useful (it stops
// "myexec(" from matching bare "exec(") and is kept throughout.
var (
	shellExecRe = regexp.MustCompile(`(?i)\b(os\.system|subprocess\.(run|call|Popen|check_output)|child_process\.(exec|spawn)|Runtime\.getRuntime\(\)\.exec)\b|\bexec\s*\(|\beval\s*\(|\bspawn\s*\(|` + "`[^`]*`" + `|\|\s*(sh|bash|zsh)\b`)
	privescRe   = regexp.MustCompile(`(?i)\b(sudo\s|chmod\s+\+?s\b|chown\s+root\b)|\bsetuid\s*\(`)
	dynLoadRe   = regexp.MustCompile(`(?i)\bimportlib\.import_module\b|\b__import__\s*\(|\bexec\s*\(\s*compile\s*\(|\bbase64\.b64decode\s*\(.*exec\b`)
	envAccessRe = regexp.MustCompile(`(?i)\b(os\.environ|process\.env)\b|\bgetenv\s*\(|~/\.aws/credentials|~/\.ssh/|/etc/shadow|/etc/passwd`)
	deleteRe    = regexp.MustCompile(`(?i)\b(rm\s+-rf|shutil\.rmtree|os\.remove|os\.unlink|fs\.rmSync|fs\.unlinkSync)\b`)
	writeOpRe   = regexp.MustCompile(`(?i)\bopen\s*\(\s*["']([^"']+)["']\s*,\s*["'][wa]`)
	urlRe       = regexp.MustCompile(`https?://[^\s"'` + "`" + `]+`)
	curlPipeRe  = regexp.MustCompile(`(?i)(curl|wget)\b[^|]*\|\s*(sh|bash)\b`)
)

func scan(code string, allowedFsPrefix []string) []finding {
	var out []finding

	if shellExecRe.MatchString(code) {
		out = append(out, finding{"shell_exec", "matches a shell/OS command execution pattern"})
	}
	if privescRe.MatchString(code) {
		out = append(out, finding{"privilege_escalation", "matches a privilege-escalation pattern (sudo/chmod +s/setuid)"})
	}
	if dynLoadRe.MatchString(code) {
		out = append(out, finding{"dynamic_load", "matches a dynamic code-loading / obfuscated eval pattern"})
	}
	if envAccessRe.MatchString(code) {
		out = append(out, finding{"secret_access", "reads environment variables or a common credential-file path"})
	}
	if deleteRe.MatchString(code) {
		out = append(out, finding{"destructive_fs", "matches a recursive/destructive filesystem delete"})
	}
	if curlPipeRe.MatchString(code) {
		out = append(out, finding{"pipe_to_shell", "downloads and pipes content directly into a shell"})
	}

	for _, m := range writeOpRe.FindAllStringSubmatch(code, -1) {
		path := m[1]
		if !pathAllowed(path, allowedFsPrefix) {
			out = append(out, finding{"fs_escape", fmt.Sprintf("write targets %q, outside the allowed filesystem prefixes", path)})
			break
		}
	}

	for _, u := range urlRe.FindAllString(code, -1) {
		if hostIsPrivateOrMeta(u) {
			out = append(out, finding{"ssrf", fmt.Sprintf("network target %q resolves to a private/loopback/metadata address", u)})
			break
		}
	}

	return out
}

func pathAllowed(path string, allowedPrefixes []string) bool {
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func hostIsPrivateOrMeta(rawURL string) bool {
	// Minimal host extraction - full URL parsing isn't needed for this
	// heuristic scan; a malformed URL simply doesn't match and is ignored.
	rest := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	host := rest
	if i := strings.IndexAny(rest, "/:"); i >= 0 {
		host = rest[:i]
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost" || host == "metadata.google.internal"
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		case v4[0] == 169 && v4[1] == 254: // link-local + 169.254.169.254 metadata
			return true
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // CGNAT
			return true
		}
	} else if ip[0]&0xfe == 0xfc { // fc00::/7 unique-local
		return true
	}
	return false
}

// globMatch supports '*' (any run) and '?' (single char).
func globMatch(pattern, name string) bool { return globMatchRec([]rune(pattern), []rune(name)) }

func globMatchRec(p, s []rune) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for len(p) > 0 && p[0] == '*' {
				p = p[1:]
			}
			if len(p) == 0 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globMatchRec(p, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			if len(s) == 0 || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return len(s) == 0
}

// ─── minimal JSONPath ────────────────────────────────────────────────────────

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
