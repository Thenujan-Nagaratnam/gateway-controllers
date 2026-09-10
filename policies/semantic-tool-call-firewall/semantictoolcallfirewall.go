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

// Package semantictoolcallfirewall enforces operation-level boundaries on agent
// tool calls (OWASP LLM06, Agentic ASI02): it inspects the arguments of an MCP
// tools/call request against per-tool rules (SQL statement type, URL SSRF,
// string/number/recipient constraints) and blocks or annotates violations.
package semantictoolcallfirewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	firewallErrorCode = 422
	firewallType      = "SEMANTIC_TOOL_CALL_FIREWALL"
	firewallName      = "SemanticToolCallFirewall"

	actionBlock    = "block"
	actionAnnotate = "annotate"
)

// ─── config ──────────────────────────────────────────────────────────────────

type sqlRule struct {
	argPath              string
	allow                map[string]bool
	deny                 map[string]bool
	blockMultiple        bool
	requireWhere         bool
}

type urlRule struct {
	argPaths     []string
	schemes      map[string]bool
	blockPrivate bool
	allowHosts   map[string]bool
	denyHosts    map[string]bool
}

type stringRule struct {
	argPath      string
	maxLength    int
	denyRe       []*regexp.Regexp
	allowRe      *regexp.Regexp
}

type recipientRule struct {
	argPaths     []string
	allowDomains map[string]bool
}

type numberRule struct {
	argPath  string
	hasMin   bool
	min      float64
	hasMax   bool
	max      float64
}

type toolRule struct {
	toolName   string
	glob       *regexp.Regexp // nil when exact
	sql        *sqlRule
	url        *urlRule
	strings    []stringRule
	recipients *recipientRule
	numbers    []numberRule
}

type config struct {
	toolNamePath  string
	argsPath      string
	onViolation   string
	defaultAction string
	showAssess    bool
	passthrough   bool
	rules         []toolRule
}

// SemanticToolCallFirewallPolicy implements the v1alpha2 policy interface.
type SemanticToolCallFirewallPolicy struct{ cfg config }

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		toolNamePath:  "$.params.name",
		argsPath:      "$.params.arguments",
		onViolation:   actionBlock,
		defaultAction: "allow",
	}
	if err := strParam(params, "toolNameJsonPath", &cfg.toolNamePath); err != nil {
		return nil, wrap(err)
	}
	if err := strParam(params, "argumentsJsonPath", &cfg.argsPath); err != nil {
		return nil, wrap(err)
	}
	if v, ok := params["onViolation"]; ok {
		s, _ := v.(string)
		if s != actionBlock && s != actionAnnotate {
			return nil, wrap(fmt.Errorf("'onViolation' must be block or annotate"))
		}
		cfg.onViolation = s
	}
	if v, ok := params["defaultAction"]; ok {
		s, _ := v.(string)
		if s != "allow" && s != "block" {
			return nil, wrap(fmt.Errorf("'defaultAction' must be allow or block"))
		}
		cfg.defaultAction = s
	}
	if err := boolParam(params, "showAssessment", &cfg.showAssess); err != nil {
		return nil, wrap(err)
	}
	if err := boolParam(params, "passthroughOnError", &cfg.passthrough); err != nil {
		return nil, wrap(err)
	}

	rawRules, ok := params["rules"].([]interface{})
	if !ok && params["rules"] != nil {
		return nil, wrap(fmt.Errorf("'rules' must be an array"))
	}
	for i, rr := range rawRules {
		rm, ok := rr.(map[string]interface{})
		if !ok {
			return nil, wrap(fmt.Errorf("rules[%d] must be an object", i))
		}
		tr, err := parseToolRule(rm)
		if err != nil {
			return nil, wrap(fmt.Errorf("rules[%d]: %w", i, err))
		}
		cfg.rules = append(cfg.rules, tr)
	}
	if len(cfg.rules) == 0 && cfg.defaultAction == "allow" {
		return nil, wrap(fmt.Errorf("no rules configured and defaultAction is allow - the firewall would do nothing"))
	}
	return &SemanticToolCallFirewallPolicy{cfg: cfg}, nil
}

// Mode buffers the request body only.
func (p *SemanticToolCallFirewallPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody inspects the tool call's arguments against the matching rule.
func (p *SemanticToolCallFirewallPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return p.onError("The request body is not valid JSON.")
	}

	toolName, _ := valueAt(root, p.cfg.toolNamePath).(string)
	if toolName == "" {
		// Not a recognisable tool call - nothing to enforce.
		if p.cfg.passthrough {
			return policy.UpstreamRequestModifications{}
		}
		return p.onError("Could not find a tool name in the request.")
	}
	argsVal := valueAt(root, p.cfg.argsPath)
	args, _ := argsVal.(map[string]interface{})

	rule := p.matchRule(toolName)
	if rule == nil {
		if p.cfg.defaultAction == "block" {
			return p.violation(toolName, []violation{{Rule: "defaultAction", Detail: "no rule permits this tool"}})
		}
		return policy.UpstreamRequestModifications{}
	}

	vios := evaluate(rule, args)
	if len(vios) == 0 {
		return policy.UpstreamRequestModifications{}
	}
	if p.cfg.onViolation == actionAnnotate {
		return policy.UpstreamRequestModifications{
			HeadersToSet:      annotateHeaders(toolName, vios),
			AnalyticsMetadata: analytics(toolName, vios),
		}
	}
	return p.violation(toolName, vios)
}

func (p *SemanticToolCallFirewallPolicy) onError(reason string) policy.RequestAction {
	if p.cfg.passthrough {
		return policy.UpstreamRequestModifications{}
	}
	return policy.ImmediateResponse{
		StatusCode: firewallErrorCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       buildEnvelope("", reason, nil, false, ""),
		AnalyticsMetadata: map[string]any{"isGuardrailHit": true, "guardrailName": firewallName},
	}
}

func (p *SemanticToolCallFirewallPolicy) violation(toolName string, vios []violation) policy.RequestAction {
	return policy.ImmediateResponse{
		StatusCode: firewallErrorCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       buildEnvelope(toolName, "The tool call violates the configured operation-level policy.", vios, p.cfg.showAssess, ""),
		AnalyticsMetadata: analytics(toolName, vios),
	}
}

func (p *SemanticToolCallFirewallPolicy) matchRule(tool string) *toolRule {
	for i := range p.cfg.rules {
		if p.cfg.rules[i].glob == nil && p.cfg.rules[i].toolName == tool {
			return &p.cfg.rules[i]
		}
	}
	for i := range p.cfg.rules {
		if p.cfg.rules[i].glob != nil && p.cfg.rules[i].glob.MatchString(tool) {
			return &p.cfg.rules[i]
		}
	}
	return nil
}

// ─── evaluation ──────────────────────────────────────────────────────────────

type violation struct {
	Rule   string `json:"rule"`
	Arg    string `json:"arg,omitempty"`
	Detail string `json:"detail"`
}

func evaluate(r *toolRule, args map[string]interface{}) []violation {
	var out []violation
	if r.sql != nil {
		out = append(out, checkSQL(r.sql, args)...)
	}
	if r.url != nil {
		out = append(out, checkURL(r.url, args)...)
	}
	for _, sr := range r.strings {
		out = append(out, checkString(sr, args)...)
	}
	if r.recipients != nil {
		out = append(out, checkRecipients(r.recipients, args)...)
	}
	for _, nr := range r.numbers {
		out = append(out, checkNumber(nr, args)...)
	}
	return out
}

var (
	sqlLeadComment = regexp.MustCompile(`^(\s|--[^\n]*\n|/\*.*?\*/)+`)
	whereRe        = regexp.MustCompile(`(?is)\bWHERE\b`)
)

func checkSQL(r *sqlRule, args map[string]interface{}) []violation {
	q, ok := valueAt(args, r.argPath).(string)
	if !ok || strings.TrimSpace(q) == "" {
		return nil
	}
	trimmed := sqlLeadComment.ReplaceAllString(q, "")
	trimmed = strings.TrimSpace(trimmed)
	fields := strings.Fields(trimmed)
	stmt := ""
	if len(fields) > 0 {
		stmt = strings.ToUpper(strings.TrimRight(fields[0], ";("))
	}

	var out []violation
	switch {
	case len(r.deny) > 0:
		if r.deny[stmt] {
			out = append(out, violation{Rule: "sql", Arg: r.argPath, Detail: fmt.Sprintf("statement type %q is denied", stmt)})
		}
	case len(r.allow) > 0:
		if !r.allow[stmt] {
			out = append(out, violation{Rule: "sql", Arg: r.argPath, Detail: fmt.Sprintf("statement type %q is not in the allow-list", stmt)})
		}
	}
	if r.blockMultiple && containsStatementSeparator(q) {
		out = append(out, violation{Rule: "sql", Arg: r.argPath, Detail: "multiple statements are not permitted"})
	}
	if r.requireWhere && (stmt == "UPDATE" || stmt == "DELETE") && !whereRe.MatchString(q) {
		out = append(out, violation{Rule: "sql", Arg: r.argPath, Detail: stmt + " without a WHERE clause is not permitted"})
	}
	return out
}

// containsStatementSeparator reports a ';' that is not merely trailing and not inside a quoted string.
func containsStatementSeparator(q string) bool {
	inS, inD := false, false
	for i := 0; i < len(q); i++ {
		switch q[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case ';':
			if !inS && !inD {
				if strings.TrimSpace(q[i+1:]) != "" {
					return true
				}
			}
		}
	}
	return false
}

func checkURL(r *urlRule, args map[string]interface{}) []violation {
	var out []violation
	for _, ap := range r.argPaths {
		raw, ok := valueAt(args, ap).(string)
		if !ok || raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			out = append(out, violation{Rule: "url", Arg: ap, Detail: "not a valid URL"})
			continue
		}
		if len(r.schemes) > 0 && !r.schemes[strings.ToLower(u.Scheme)] {
			out = append(out, violation{Rule: "url", Arg: ap, Detail: fmt.Sprintf("scheme %q is not allowed", u.Scheme)})
		}
		if u.User != nil {
			out = append(out, violation{Rule: "url", Arg: ap, Detail: "URL must not embed userinfo"})
		}
		host := u.Hostname()
		if r.blockPrivate {
			if ip := net.ParseIP(host); ip != nil && isPrivateOrMeta(ip) {
				out = append(out, violation{Rule: "url", Arg: ap, Detail: "host resolves to a private / loopback / link-local / metadata address"})
			}
		}
		if len(r.allowHosts) > 0 && !r.allowHosts[strings.ToLower(host)] {
			out = append(out, violation{Rule: "url", Arg: ap, Detail: fmt.Sprintf("host %q is not in the allow-list", host)})
		}
		if r.denyHosts[strings.ToLower(host)] {
			out = append(out, violation{Rule: "url", Arg: ap, Detail: fmt.Sprintf("host %q is denied", host)})
		}
	}
	return out
}

func isPrivateOrMeta(ip net.IP) bool {
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
		case v4[0] == 0:
			return true
		}
	}
	if ip.To4() == nil {
		// fc00::/7 unique-local
		if ip[0]&0xfe == 0xfc {
			return true
		}
	}
	return false
}

func checkString(r stringRule, args map[string]interface{}) []violation {
	s, ok := valueAt(args, r.argPath).(string)
	if !ok {
		return nil
	}
	var out []violation
	if r.maxLength > 0 && utf8.RuneCountInString(s) > r.maxLength {
		out = append(out, violation{Rule: "strings", Arg: r.argPath, Detail: fmt.Sprintf("value is longer than %d characters", r.maxLength)})
	}
	for _, re := range r.denyRe {
		if re.MatchString(s) {
			out = append(out, violation{Rule: "strings", Arg: r.argPath, Detail: "value matches a denied pattern"})
			break
		}
	}
	if r.allowRe != nil && !r.allowRe.MatchString(s) {
		out = append(out, violation{Rule: "strings", Arg: r.argPath, Detail: "value does not match the required pattern"})
	}
	return out
}

func checkRecipients(r *recipientRule, args map[string]interface{}) []violation {
	if len(r.allowDomains) == 0 {
		return nil
	}
	var out []violation
	var recips []string
	for _, ap := range r.argPaths {
		switch v := valueAt(args, ap).(type) {
		case string:
			recips = append(recips, v)
		case []interface{}:
			for _, e := range v {
				if s, ok := e.(string); ok {
					recips = append(recips, s)
				}
			}
		}
	}
	for _, addr := range recips {
		at := strings.LastIndexByte(addr, '@')
		dom := ""
		if at >= 0 {
			dom = strings.ToLower(strings.TrimSpace(addr[at+1:]))
		} else {
			dom = strings.ToLower(strings.TrimSpace(addr))
		}
		if dom != "" && !r.allowDomains[dom] {
			out = append(out, violation{Rule: "recipients", Detail: fmt.Sprintf("recipient domain %q is not in the allow-list", dom)})
		}
	}
	return out
}

func checkNumber(r numberRule, args map[string]interface{}) []violation {
	f, ok := toNumber(valueAt(args, r.argPath))
	if !ok {
		return nil
	}
	var out []violation
	if r.hasMin && f < r.min {
		out = append(out, violation{Rule: "numbers", Arg: r.argPath, Detail: fmt.Sprintf("value %g is below the minimum %g", f, r.min)})
	}
	if r.hasMax && f > r.max {
		out = append(out, violation{Rule: "numbers", Arg: r.argPath, Detail: fmt.Sprintf("value %g exceeds the maximum %g", f, r.max)})
	}
	return out
}

// ─── minimal JSONPath ────────────────────────────────────────────────────────

// valueAt resolves "$.a.b", "$.a[0].b", "$.a[-1]", "$.a[*]" against root.
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
			in := comp[o+1 : len(comp)-1]
			hasIdx = true
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
				cur = a[0]
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

// ─── response builders ───────────────────────────────────────────────────────

func buildEnvelope(toolName, reason string, vios []violation, showAssessment bool, _ string) []byte {
	msg := map[string]interface{}{
		"action":              "TOOL_CALL_BLOCKED",
		"interveningGuardrail": firewallName,
		"direction":           "REQUEST",
		"actionReason":        reason,
	}
	if toolName != "" {
		msg["tool"] = toolName
	}
	if showAssessment && len(vios) > 0 {
		msg["assessments"] = vios
	}
	out := map[string]interface{}{"type": firewallType, "message": msg}
	// JSON-RPC-shaped mirror so an MCP client can also parse the error.
	out["jsonrpc"] = "2.0"
	out["error"] = map[string]interface{}{"code": -32000, "message": reason}
	b, _ := json.Marshal(out)
	return b
}

func annotateHeaders(tool string, vios []violation) map[string]string {
	rules := make([]string, 0, len(vios))
	seen := map[string]bool{}
	for _, v := range vios {
		if !seen[v.Rule] {
			seen[v.Rule] = true
			rules = append(rules, v.Rule)
		}
	}
	return map[string]string{
		"x-tool-firewall":            "violation",
		"x-tool-firewall-tool":       tool,
		"x-tool-firewall-rules":      strings.Join(rules, ","),
	}
}

func analytics(tool string, vios []violation) map[string]any {
	rules := make([]string, 0, len(vios))
	for _, v := range vios {
		rules = append(rules, v.Rule)
	}
	return map[string]any{
		"isGuardrailHit":     true,
		"guardrailName":      firewallName,
		"direction":          "REQUEST",
		"toolFirewallTool":   tool,
		"toolFirewallRules":  rules,
	}
}

// ─── param parsing ───────────────────────────────────────────────────────────

func parseToolRule(m map[string]interface{}) (toolRule, error) {
	tr := toolRule{}
	name, ok := m["toolName"].(string)
	if !ok || name == "" {
		return tr, fmt.Errorf("'toolName' is required")
	}
	tr.toolName = name
	if strings.ContainsAny(name, "*?") {
		re, err := regexp.Compile("^" + globToRegex(name) + "$")
		if err != nil {
			return tr, fmt.Errorf("invalid toolName glob %q", name)
		}
		tr.glob = re
	}

	if s, ok := m["sql"].(map[string]interface{}); ok {
		sr := &sqlRule{argPath: "$.query", blockMultiple: true, requireWhere: true}
		strParamDefault(s, "argPath", &sr.argPath)
		_ = boolParam(s, "blockMultipleStatements", &sr.blockMultiple)
		_ = boolParam(s, "requireWhereForUpdateDelete", &sr.requireWhere)
		sr.allow = upperSet(s["allowStatements"], []string{"SELECT", "WITH", "EXPLAIN", "SHOW", "DESCRIBE"})
		sr.deny = upperSet(s["denyStatements"], nil)
		if len(sr.deny) > 0 {
			sr.allow = nil
		}
		tr.sql = sr
	}
	if u, ok := m["url"].(map[string]interface{}); ok {
		ur := &urlRule{
			argPaths:     strSlice(u["argPaths"], []string{"$.url", "$.endpoint", "$.uri"}),
			schemes:      lowerSet(u["allowedSchemes"], []string{"https"}),
			blockPrivate: true,
			allowHosts:   lowerSet(u["allowHosts"], nil),
			denyHosts:    lowerSet(u["denyHosts"], nil),
		}
		_ = boolParam(u, "blockPrivateNetworks", &ur.blockPrivate)
		tr.url = ur
	}
	if arr, ok := m["strings"].([]interface{}); ok {
		for _, e := range arr {
			em, ok := e.(map[string]interface{})
			if !ok {
				return tr, fmt.Errorf("strings entries must be objects")
			}
			sr := stringRule{}
			if err := strParam(em, "argPath", &sr.argPath); err != nil || sr.argPath == "" {
				return tr, fmt.Errorf("strings.argPath is required")
			}
			if v, ok := em["maxLength"]; ok {
				n, err := toNumber(v)
				if err2 := err; !err2 || n <= 0 {
					return tr, fmt.Errorf("strings.maxLength must be a positive integer")
				}
				sr.maxLength = int(n)
			}
			for _, dp := range strSlice(em["denyPatterns"], nil) {
				re, err := regexp.Compile(dp)
				if err != nil {
					return tr, fmt.Errorf("strings.denyPatterns %q: %w", dp, err)
				}
				sr.denyRe = append(sr.denyRe, re)
			}
			if ap, ok := em["allowPattern"].(string); ok && ap != "" {
				re, err := regexp.Compile(ap)
				if err != nil {
					return tr, fmt.Errorf("strings.allowPattern %q: %w", ap, err)
				}
				sr.allowRe = re
			}
			tr.strings = append(tr.strings, sr)
		}
	}
	if rc, ok := m["recipients"].(map[string]interface{}); ok {
		tr.recipients = &recipientRule{
			argPaths:     strSlice(rc["argPaths"], []string{"$.to", "$.recipient", "$.recipients"}),
			allowDomains: lowerSet(rc["allowDomains"], nil),
		}
	}
	if arr, ok := m["numbers"].([]interface{}); ok {
		for _, e := range arr {
			em, ok := e.(map[string]interface{})
			if !ok {
				return tr, fmt.Errorf("numbers entries must be objects")
			}
			nr := numberRule{}
			if err := strParam(em, "argPath", &nr.argPath); err != nil || nr.argPath == "" {
				return tr, fmt.Errorf("numbers.argPath is required")
			}
			if v, ok := em["min"]; ok {
				f, ok := toNumber(v)
				if !ok {
					return tr, fmt.Errorf("numbers.min must be a number")
				}
				nr.hasMin, nr.min = true, f
			}
			if v, ok := em["max"]; ok {
				f, ok := toNumber(v)
				if !ok {
					return tr, fmt.Errorf("numbers.max must be a number")
				}
				nr.hasMax, nr.max = true, f
			}
			tr.numbers = append(tr.numbers, nr)
		}
	}
	if tr.sql == nil && tr.url == nil && tr.recipients == nil && len(tr.strings) == 0 && len(tr.numbers) == 0 {
		return tr, fmt.Errorf("rule for %q has no constraints", name)
	}
	return tr, nil
}

func globToRegex(g string) string {
	var b strings.Builder
	for _, r := range g {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

func upperSet(v interface{}, def []string) map[string]bool {
	list := strSlice(v, def)
	out := map[string]bool{}
	for _, s := range list {
		out[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
func lowerSet(v interface{}, def []string) map[string]bool {
	list := strSlice(v, def)
	out := map[string]bool{}
	for _, s := range list {
		out[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return out
}
func strSlice(v interface{}, def []string) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return def
	}
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	if out == nil {
		return def
	}
	return out
}

func strParam(m map[string]interface{}, key string, dst *string) error {
	if v, ok := m[key]; ok {
		s, ok := v.(string)
		if !ok || s == "" {
			return fmt.Errorf("'%s' must be a non-empty string", key)
		}
		*dst = s
	}
	return nil
}
func strParamDefault(m map[string]interface{}, key string, dst *string) {
	if s, ok := m[key].(string); ok && s != "" {
		*dst = s
	}
}
func boolParam(m map[string]interface{}, key string, dst *bool) error {
	if v, ok := m[key]; ok {
		b, ok := v.(bool)
		if !ok {
			return fmt.Errorf("'%s' must be a boolean", key)
		}
		*dst = b
	}
	return nil
}
func toNumber(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		return 0, false
	default:
		return 0, false
	}
}

func wrap(err error) error { return fmt.Errorf("invalid params: %w", err) }

