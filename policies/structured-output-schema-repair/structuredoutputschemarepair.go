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

// Package structuredoutputschemarepair validates the structured output in an LLM
// reply against a JSON Schema (OWASP LLM05), repairs it deterministically and,
// optionally, with one bounded LLM call, and replaces the reply content with the
// corrected JSON - or fails the response per onFail.
package structuredoutputschemarepair

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/xeipuuv/gojsonschema"
)

const (
	failStatusCode  = 502
	guardrailType   = "STRUCTURED_OUTPUT_SCHEMA_REPAIR"
	guardrailName   = "StructuredOutputSchemaRepair"
	defaultRespPath = "$.choices[0].message.content"

	onFailBlock       = "block"
	onFailPassthrough = "passthrough"
	onFailEmpty       = "emptyObject"
)

type repairCfg struct {
	enabled      bool
	endpoint     string
	model        string
	apiKey       string
	timeout      time.Duration
	maxRespBytes int64
}

type config struct {
	schema          *gojsonschema.Schema
	schemaRaw       string
	respPath        string
	deterministic   bool
	repair          repairCfg
	onFail          string
	showAssessment  bool
	passthroughErr  bool
}

// StructuredOutputSchemaRepairPolicy implements the v1alpha2 policy interface.
type StructuredOutputSchemaRepairPolicy struct {
	cfg    config
	client *http.Client
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		respPath:      defaultRespPath,
		deterministic: true,
		onFail:        onFailBlock,
		repair:        repairCfg{model: "gpt-4o-mini", timeout: 15 * time.Second, maxRespBytes: 262144},
	}

	schemaStr, ok := params["schema"].(string)
	if !ok || strings.TrimSpace(schemaStr) == "" {
		return nil, wrap(fmt.Errorf("'schema' is required and must be a JSON Schema string"))
	}
	sc, err := gojsonschema.NewSchema(gojsonschema.NewStringLoader(schemaStr))
	if err != nil {
		return nil, wrap(fmt.Errorf("'schema' is not a valid JSON Schema: %w", err))
	}
	cfg.schema = sc
	cfg.schemaRaw = schemaStr

	if v, ok := params["responseJsonPath"]; ok {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, wrap(fmt.Errorf("'responseJsonPath' must be a non-empty string"))
		}
		cfg.respPath = s
	}
	if err := boolParam(params, "deterministicRepair", &cfg.deterministic); err != nil {
		return nil, wrap(err)
	}
	if err := boolParam(params, "showAssessment", &cfg.showAssessment); err != nil {
		return nil, wrap(err)
	}
	if err := boolParam(params, "passthroughOnError", &cfg.passthroughErr); err != nil {
		return nil, wrap(err)
	}
	if v, ok := params["onFail"]; ok {
		s, _ := v.(string)
		if s != onFailBlock && s != onFailPassthrough && s != onFailEmpty {
			return nil, wrap(fmt.Errorf("'onFail' must be one of block, passthrough, emptyObject"))
		}
		cfg.onFail = s
	}

	if rc, ok := params["repair"].(map[string]interface{}); ok {
		if err := boolParam(rc, "enabled", &cfg.repair.enabled); err != nil {
			return nil, wrap(err)
		}
		strParamDefault(rc, "endpoint", &cfg.repair.endpoint)
		strParamDefault(rc, "model", &cfg.repair.model)
		strParamDefault(rc, "apiKey", &cfg.repair.apiKey)
		if v, ok := rc["timeoutSeconds"]; ok {
			f, err := toFloat(v)
			if err != nil || f <= 0 {
				return nil, wrap(fmt.Errorf("'repair.timeoutSeconds' must be a positive number"))
			}
			cfg.repair.timeout = time.Duration(f * float64(time.Second))
		}
		if v, ok := rc["maxResponseBytes"]; ok {
			f, err := toFloat(v)
			if err != nil || f < 1024 {
				return nil, wrap(fmt.Errorf("'repair.maxResponseBytes' must be >= 1024"))
			}
			cfg.repair.maxRespBytes = int64(f)
		}
		if cfg.repair.enabled {
			if cfg.repair.endpoint == "" {
				return nil, wrap(fmt.Errorf("'repair.endpoint' is required when repair.enabled is true"))
			}
			if err := validateHTTPURL(cfg.repair.endpoint); err != nil {
				return nil, wrap(fmt.Errorf("'repair.endpoint' %w", err))
			}
		}
	}

	return &StructuredOutputSchemaRepairPolicy{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.repair.timeout},
	}, nil
}

// Mode buffers the response body only.
func (p *StructuredOutputSchemaRepairPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// OnResponseBody validates + repairs the structured output.
func (p *StructuredOutputSchemaRepairPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	var body []byte
	if respCtx.ResponseBody != nil {
		body = respCtx.ResponseBody.Content
	}
	raw, ok, err := extractString(body, p.cfg.respPath)
	if err != nil || !ok {
		if p.cfg.passthroughErr {
			return policy.DownstreamResponseModifications{}
		}
		if err != nil {
			return p.fail(body, "The response could not be parsed to locate the structured output.", nil)
		}
		return policy.DownstreamResponseModifications{}
	}

	stage, fixed, valErrs := p.validateAndRepair(ctx, raw)
	switch stage {
	case "clean":
		return policy.DownstreamResponseModifications{
			HeadersToSet: map[string]string{"x-schema-repair": "clean"},
		}
	case "deterministic", "llm":
		newBody, werr := setString(body, p.cfg.respPath, fixed)
		if werr != nil {
			return p.fail(body, "Repaired the structured output but could not rewrite the response.", nil)
		}
		return policy.DownstreamResponseModifications{
			Body:              newBody,
			HeadersToSet:      map[string]string{"Content-Type": "application/json", "x-schema-repair": stage},
			AnalyticsMetadata: map[string]any{"schemaRepairApplied": stage, "guardrailName": guardrailName},
		}
	default: // failed
		return p.fail(body, "The structured output does not satisfy the required schema and could not be repaired.", valErrs)
	}
}

func (p *StructuredOutputSchemaRepairPolicy) fail(body []byte, reason string, valErrs []string) policy.ResponseAction {
	switch p.cfg.onFail {
	case onFailPassthrough:
		return policy.DownstreamResponseModifications{
			HeadersToSet:      map[string]string{"x-schema-repair": "failed"},
			AnalyticsMetadata: map[string]any{"isGuardrailHit": true, "guardrailName": guardrailName, "schemaRepair": "failed"},
		}
	case onFailEmpty:
		empty := "{}"
		if strings.HasPrefix(strings.TrimSpace(p.cfg.schemaRaw), `{"type":"array"`) || strings.Contains(p.cfg.schemaRaw, `"type": "array"`) {
			empty = "[]"
		}
		if nb, err := setString(body, p.cfg.respPath, empty); err == nil {
			return policy.DownstreamResponseModifications{
				Body:              nb,
				HeadersToSet:      map[string]string{"Content-Type": "application/json", "x-schema-repair": "failed-emptied"},
				AnalyticsMetadata: map[string]any{"isGuardrailHit": true, "guardrailName": guardrailName, "schemaRepair": "failed-emptied"},
			}
		}
		fallthrough
	default:
		sc := failStatusCode
		msg := map[string]interface{}{
			"action":              "SCHEMA_VALIDATION_FAILED",
			"interveningGuardrail": guardrailName,
			"direction":           "RESPONSE",
			"actionReason":        reason,
		}
		if p.cfg.showAssessment && len(valErrs) > 0 {
			msg["assessments"] = valErrs
		}
		b, _ := json.Marshal(map[string]interface{}{"type": guardrailType, "message": msg})
		return policy.DownstreamResponseModifications{
			StatusCode:        &sc,
			HeadersToSet:      map[string]string{"Content-Type": "application/json"},
			Body:              b,
			AnalyticsMetadata: map[string]any{"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "RESPONSE"},
		}
	}
}

// ─── validate + repair pipeline ──────────────────────────────────────────────

// validateAndRepair returns (stage, repairedJSON, validationErrors) where stage
// is "clean" | "deterministic" | "llm" | "failed".
func (p *StructuredOutputSchemaRepairPolicy) validateAndRepair(ctx context.Context, raw string) (string, string, []string) {
	if errs := p.validate(raw); errs == nil {
		return "clean", raw, nil
	}

	if p.cfg.deterministic {
		if cand := deterministicRepair(raw); cand != "" && cand != raw {
			if errs := p.validate(cand); errs == nil {
				return "deterministic", cand, nil
			}
		}
	}

	lastErrs := p.validate(raw)
	if p.cfg.repair.enabled {
		if cand, err := p.llmRepair(ctx, raw, lastErrs); err == nil && cand != "" {
			// try the raw correction, then a deterministic clean-up of it
			for _, c := range []string{cand, deterministicRepair(cand)} {
				if c == "" {
					continue
				}
				if errs := p.validate(c); errs == nil {
					return "llm", c, nil
				}
			}
		} else if err != nil {
			slog.Warn("StructuredOutputSchemaRepair: LLM repair call failed", "error", err.Error())
		}
	}
	return "failed", "", lastErrs
}

func (p *StructuredOutputSchemaRepairPolicy) validate(doc string) []string {
	res, err := p.cfg.schema.Validate(gojsonschema.NewStringLoader(doc))
	if err != nil {
		return []string{"not valid JSON: " + trunc(err.Error(), 200)}
	}
	if res.Valid() {
		return nil
	}
	out := make([]string, 0, len(res.Errors()))
	for _, e := range res.Errors() {
		out = append(out, e.String())
	}
	return out
}

var (
	fenceRe    = regexp.MustCompile("(?s)^\\s*```[a-zA-Z0-9]*\\s*\\n?(.*?)\\n?\\s*```\\s*$")
	trailComma = regexp.MustCompile(`,(\s*[}\]])`)
)

// deterministicRepair applies conservative, structure-preserving fixes.
func deterministicRepair(s string) string {
	t := strings.TrimSpace(s)
	if m := fenceRe.FindStringSubmatch(t); m != nil {
		t = strings.TrimSpace(m[1])
	}
	// trim leading/trailing prose around the outermost JSON value
	if i := strings.IndexAny(t, "{["); i >= 0 {
		open := t[i]
		close := byte('}')
		if open == '[' {
			close = ']'
		}
		if j := matchingClose(t, i, open, close); j > i {
			t = t[i : j+1]
		}
	}
	t = trailComma.ReplaceAllString(t, "$1")
	// collapse doubled backslashes only if that yields valid JSON
	if !json.Valid([]byte(t)) {
		if alt := strings.ReplaceAll(t, `\\`, `\`); json.Valid([]byte(alt)) {
			t = alt
		}
	}
	return strings.TrimSpace(t)
}

func matchingClose(s string, start int, open, close byte) int {
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// ─── LLM repair call ─────────────────────────────────────────────────────────

func (p *StructuredOutputSchemaRepairPolicy) llmRepair(ctx context.Context, broken string, valErrs []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.repair.timeout)
	defer cancel()

	sys := "You are a JSON repair tool. Given a JSON Schema, a malformed document, and its validation errors, output ONLY the corrected JSON document that satisfies the schema. No prose, no code fences."
	user := fmt.Sprintf("JSON Schema:\n%s\n\nMalformed document:\n%s\n\nValidation errors:\n- %s\n\nCorrected JSON:",
		p.cfg.schemaRaw, broken, strings.Join(valErrs, "\n- "))

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":       p.cfg.repair.model,
		"temperature": 0,
		"messages": []map[string]string{
			{"role": "system", "content": sys},
			{"role": "user", "content": user},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.repair.endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cfg.repair.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.repair.apiKey)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("repair endpoint returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, p.cfg.repair.maxRespBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > p.cfg.repair.maxRespBytes {
		return "", fmt.Errorf("repair response exceeded the size limit")
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil || len(parsed.Choices) == 0 {
		return "", fmt.Errorf("repair response was not an OpenAI-shaped completion")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

// ─── JSON helpers (dot-path get/set) ────────────────────────────────────────

func extractString(body []byte, path string) (string, bool, error) {
	if len(body) == 0 {
		return "", false, nil
	}
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return "", false, fmt.Errorf("response body is not JSON")
	}
	v, err := walk(root, path)
	if err != nil {
		return "", false, nil
	}
	switch t := v.(type) {
	case string:
		return t, true, nil
	case map[string]interface{}, []interface{}:
		b, _ := json.Marshal(t)
		return string(b), true, nil
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

type seg struct {
	key    string
	idx    int
	hasIdx bool
}

const wc = -1 << 30

func parse(path string) []seg {
	path = strings.TrimPrefix(strings.TrimPrefix(path, "$"), ".")
	var out []seg
	for _, raw := range strings.Split(path, ".") {
		if raw == "" {
			continue
		}
		s := seg{key: raw}
		if o := strings.IndexByte(raw, '['); o >= 0 && strings.HasSuffix(raw, "]") {
			s.key = raw[:o]
			s.hasIdx = true
			in := raw[o+1 : len(raw)-1]
			if in == "*" {
				s.idx = wc
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
				s.idx = n
			}
		}
		out = append(out, s)
	}
	return out
}

func walk(root interface{}, path string) (interface{}, error) {
	cur := root
	for _, s := range parse(path) {
		if s.key != "" {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("not object")
			}
			v, ok := m[s.key]
			if !ok {
				return nil, fmt.Errorf("missing")
			}
			cur = v
		}
		if s.hasIdx {
			a, ok := cur.([]interface{})
			if !ok || len(a) == 0 {
				return nil, fmt.Errorf("not array")
			}
			switch {
			case s.idx == wc:
				cur = a[0]
			case s.idx < 0:
				cur = a[len(a)+s.idx]
			case s.idx < len(a):
				cur = a[s.idx]
			default:
				return nil, fmt.Errorf("oob")
			}
		}
	}
	return cur, nil
}

func assign(root interface{}, path, value string) error {
	segs := parse(path)
	cur := root
	for i, s := range segs {
		last := i == len(segs)-1
		if s.key != "" {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return fmt.Errorf("not object")
			}
			if last && !s.hasIdx {
				m[s.key] = value
				return nil
			}
			v, ok := m[s.key]
			if !ok {
				return fmt.Errorf("missing")
			}
			cur = v
		}
		if s.hasIdx {
			a, ok := cur.([]interface{})
			if !ok || len(a) == 0 {
				return fmt.Errorf("not array")
			}
			j := s.idx
			if j == wc {
				j = 0
			} else if j < 0 {
				j = len(a) + j
			}
			if j < 0 || j >= len(a) {
				return fmt.Errorf("oob")
			}
			if last {
				a[j] = value
				return nil
			}
			cur = a[j]
		}
	}
	return fmt.Errorf("unset")
}

// ─── misc ────────────────────────────────────────────────────────────────────

func validateHTTPURL(s string) error {
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return fmt.Errorf("must be an http(s) URL")
	}
	return nil
}

func wrap(err error) error { return fmt.Errorf("invalid params: %w", err) }

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
func strParamDefault(m map[string]interface{}, key string, dst *string) {
	if s, ok := m[key].(string); ok && s != "" {
		*dst = s
	}
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
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
