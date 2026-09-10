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

// Package opaauthorizationinterceptor evaluates each request against an Open
// Policy Agent decision (OWASP Agentic T3): it builds a context-rich input
// document, POSTs it to OPA, and denies (fail-closed) when the decision is not
// allow, optionally applying redact obligations.
package opaauthorizationinterceptor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	guardrailType = "OPA_AUTHORIZATION"
	guardrailName = "OpaAuthorizationInterceptor"

	onDenyBlock    = "block"
	onDenyAnnotate = "annotate"
)

type config struct {
	opaURL         string
	decisionPath   string
	failOpen       bool
	onDeny         string
	denyStatus     int
	timeout        time.Duration
	maxRespBytes   int64
	cacheTTL       time.Duration
	apiKey         string
	showAssessment bool

	includeClaims   bool
	includeHeaders  []string
	toolNamePath    string
	argsPath        string
	modelPath       string
	staticAttrs     map[string]interface{}
}

// OpaAuthorizationInterceptorPolicy implements the v1alpha2 policy interface.
type OpaAuthorizationInterceptorPolicy struct {
	cfg    config
	client *http.Client

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	dec decision
	exp time.Time
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		decisionPath:  "$.result",
		onDeny:        onDenyBlock,
		denyStatus:    403,
		timeout:       5 * time.Second,
		maxRespBytes:  65536,
		includeClaims: true,
		toolNamePath:  "$.params.name",
		argsPath:      "$.params.arguments",
		modelPath:     "$.model",
		staticAttrs:   map[string]interface{}{},
	}

	u, ok := params["opaUrl"].(string)
	if !ok || strings.TrimSpace(u) == "" {
		return nil, wrap(fmt.Errorf("'opaUrl' is required"))
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return nil, wrap(fmt.Errorf("'opaUrl' must be an http(s) URL"))
	}
	cfg.opaURL = u

	strOpt(params, "decisionPath", &cfg.decisionPath)
	strOpt(params, "apiKey", &cfg.apiKey)
	if err := boolOpt(params, "failOpen", &cfg.failOpen); err != nil {
		return nil, wrap(err)
	}
	if err := boolOpt(params, "showAssessment", &cfg.showAssessment); err != nil {
		return nil, wrap(err)
	}
	if v, ok := params["onDeny"]; ok {
		s, _ := v.(string)
		if s != onDenyBlock && s != onDenyAnnotate {
			return nil, wrap(fmt.Errorf("'onDeny' must be block or annotate"))
		}
		cfg.onDeny = s
	}
	if v, ok := params["denyStatusCode"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 400 || f > 599 {
			return nil, wrap(fmt.Errorf("'denyStatusCode' must be 400-599"))
		}
		cfg.denyStatus = int(f)
	}
	if v, ok := params["timeoutSeconds"]; ok {
		f, err := toFloat(v)
		if err != nil || f <= 0 {
			return nil, wrap(fmt.Errorf("'timeoutSeconds' must be positive"))
		}
		cfg.timeout = time.Duration(f * float64(time.Second))
	}
	if v, ok := params["maxResponseBytes"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 512 {
			return nil, wrap(fmt.Errorf("'maxResponseBytes' must be >= 512"))
		}
		cfg.maxRespBytes = int64(f)
	}
	if v, ok := params["cacheTtlSeconds"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 0 {
			return nil, wrap(fmt.Errorf("'cacheTtlSeconds' must be >= 0"))
		}
		cfg.cacheTTL = time.Duration(f * float64(time.Second))
	}

	if in, ok := params["input"].(map[string]interface{}); ok {
		if err := boolOpt(in, "includeClaims", &cfg.includeClaims); err != nil {
			return nil, wrap(err)
		}
		strOpt(in, "toolNameJsonPath", &cfg.toolNamePath)
		strOpt(in, "argumentsJsonPath", &cfg.argsPath)
		strOpt(in, "modelJsonPath", &cfg.modelPath)
		if hs, ok := in["includeHeaders"].([]interface{}); ok {
			for _, h := range hs {
				if s, ok := h.(string); ok && s != "" {
					cfg.includeHeaders = append(cfg.includeHeaders, s)
				}
			}
		}
		if sa, ok := in["staticAttributes"].(map[string]interface{}); ok {
			cfg.staticAttrs = sa
		}
	}

	p := &OpaAuthorizationInterceptorPolicy{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.timeout},
	}
	if cfg.cacheTTL > 0 {
		p.cache = map[string]cacheEntry{}
	}
	return p, nil
}

// Mode buffers the request body only.
func (p *OpaAuthorizationInterceptorPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody builds the OPA input, queries OPA, and enforces the decision.
func (p *OpaAuthorizationInterceptorPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	input := p.buildInput(reqCtx, body)
	key := ""
	if p.cache != nil {
		if b, err := json.Marshal(input); err == nil {
			key = string(b)
			if d, ok := p.cacheGet(key); ok {
				return p.enforce(d, body)
			}
		}
	}

	dec, err := p.query(ctx, input)
	if err != nil {
		slog.Warn("OpaAuthorizationInterceptor: OPA query failed", "error", err.Error(), "failOpen", p.cfg.failOpen)
		if p.cfg.failOpen {
			return policy.UpstreamRequestModifications{HeadersToSet: map[string]string{"x-opa-authz": "fail-open"}}
		}
		return p.deny("Authorization service is unavailable.", nil)
	}
	if key != "" {
		p.cachePut(key, dec)
	}
	return p.enforce(dec, body)
}

func (p *OpaAuthorizationInterceptorPolicy) enforce(dec decision, body []byte) policy.RequestAction {
	if !dec.Allow {
		slog.Info("OpaAuthorizationInterceptor: request denied by OPA", "reason", dec.Reason)
		return p.deny("This action is not permitted by policy.", dec.assessments())
	}
	if len(dec.Redact) == 0 {
		return policy.UpstreamRequestModifications{HeadersToSet: map[string]string{"x-opa-authz": "allow"}}
	}
	newBody, changed := applyRedactions(body, dec.Redact)
	if !changed {
		return policy.UpstreamRequestModifications{HeadersToSet: map[string]string{"x-opa-authz": "allow"}}
	}
	return policy.UpstreamRequestModifications{
		Body:              newBody,
		HeadersToSet:      map[string]string{"Content-Type": "application/json", "x-opa-authz": "allow-redacted"},
		AnalyticsMetadata: map[string]any{"guardrailName": guardrailName, "opaObligations": dec.Redact},
	}
}

func (p *OpaAuthorizationInterceptorPolicy) deny(reason string, assess []string) policy.RequestAction {
	if p.cfg.onDeny == onDenyAnnotate {
		return policy.UpstreamRequestModifications{
			HeadersToSet:      map[string]string{"x-opa-authz": "deny-annotated"},
			AnalyticsMetadata: map[string]any{"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "REQUEST"},
		}
	}
	msg := map[string]interface{}{
		"action":              "AUTHORIZATION_DENIED",
		"interveningGuardrail": guardrailName,
		"direction":           "REQUEST",
		"actionReason":        reason,
	}
	if p.cfg.showAssessment && len(assess) > 0 {
		msg["assessments"] = assess
	}
	b, _ := json.Marshal(map[string]interface{}{"type": guardrailType, "message": msg})
	return policy.ImmediateResponse{
		StatusCode:        p.cfg.denyStatus,
		Headers:           map[string]string{"Content-Type": "application/json"},
		Body:              b,
		AnalyticsMetadata: map[string]any{"isGuardrailHit": true, "guardrailName": guardrailName, "direction": "REQUEST"},
	}
}

// ─── OPA input + query ───────────────────────────────────────────────────────

func (p *OpaAuthorizationInterceptorPolicy) buildInput(reqCtx *policy.RequestContext, body []byte) map[string]interface{} {
	in := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"route": map[string]interface{}{
			"api":     reqCtx.APIName,
			"version": reqCtx.APIVersion,
			"method":  reqCtx.Method,
			"path":    reqCtx.Path,
		},
	}
	if len(p.cfg.staticAttrs) > 0 {
		in["attributes"] = p.cfg.staticAttrs
	}

	var parsed interface{}
	_ = json.Unmarshal(body, &parsed)
	if s, ok := valueAt(parsed, p.cfg.modelPath).(string); ok && s != "" {
		in["model"] = s
	}
	if name, ok := valueAt(parsed, p.cfg.toolNamePath).(string); ok && name != "" {
		tool := map[string]interface{}{"name": name}
		if args := valueAt(parsed, p.cfg.argsPath); args != nil {
			tool["arguments"] = args
		}
		in["tool"] = tool
	}

	if reqCtx.Headers != nil {
		if p.cfg.includeClaims {
			if vals := reqCtx.Headers.Get("Authorization"); len(vals) > 0 {
				if claims := decodeJWTClaims(vals[0]); claims != nil {
					in["principal"] = claims
				}
			}
		}
		if len(p.cfg.includeHeaders) > 0 {
			h := map[string]interface{}{}
			for _, name := range p.cfg.includeHeaders {
				if vals := reqCtx.Headers.Get(name); len(vals) > 0 {
					h[strings.ToLower(name)] = vals[0]
				}
			}
			if len(h) > 0 {
				in["headers"] = h
			}
		}
	}
	return in
}

type decision struct {
	Allow  bool
	Reason string
	Redact []string
}

func (d decision) assessments() []string {
	if d.Reason == "" {
		return nil
	}
	return []string{"opa: " + d.Reason}
}

func (p *OpaAuthorizationInterceptorPolicy) query(ctx context.Context, input map[string]interface{}) (decision, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.timeout)
	defer cancel()

	reqBody, _ := json.Marshal(map[string]interface{}{"input": input})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.opaURL, bytes.NewReader(reqBody))
	if err != nil {
		return decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cfg.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return decision{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decision{}, fmt.Errorf("OPA returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, p.cfg.maxRespBytes+1))
	if err != nil {
		return decision{}, err
	}
	if int64(len(data)) > p.cfg.maxRespBytes {
		return decision{}, fmt.Errorf("OPA response exceeded the size limit")
	}
	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return decision{}, fmt.Errorf("OPA response was not JSON")
	}
	return interpretDecision(valueAt(root, p.cfg.decisionPath)), nil
}

func interpretDecision(v interface{}) decision {
	switch t := v.(type) {
	case bool:
		return decision{Allow: t}
	case map[string]interface{}:
		d := decision{}
		if b, ok := t["allow"].(bool); ok {
			d.Allow = b
		}
		if s, ok := t["reason"].(string); ok {
			d.Reason = s
		}
		if arr, ok := t["redact"].([]interface{}); ok {
			for _, e := range arr {
				if s, ok := e.(string); ok {
					d.Redact = append(d.Redact, s)
				}
			}
		}
		return d
	default:
		return decision{Allow: false, Reason: "decision path did not resolve to a boolean or object"}
	}
}

func (p *OpaAuthorizationInterceptorPolicy) cacheGet(key string) (decision, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.cache[key]
	if !ok || time.Now().After(e.exp) {
		return decision{}, false
	}
	return e.dec, true
}
func (p *OpaAuthorizationInterceptorPolicy) cachePut(key string, d decision) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.cache) > 1024 {
		p.cache = map[string]cacheEntry{}
	}
	p.cache[key] = cacheEntry{dec: d, exp: time.Now().Add(p.cfg.cacheTTL)}
}

// ─── request-body redaction ──────────────────────────────────────────────────

func applyRedactions(body []byte, paths []string) ([]byte, bool) {
	var root interface{}
	if json.Unmarshal(body, &root) != nil {
		return body, false
	}
	changed := false
	for _, jp := range paths {
		if assignString(root, jp, "[redacted by policy]") == nil {
			changed = true
		}
	}
	if !changed {
		return body, false
	}
	nb, err := json.Marshal(root)
	if err != nil {
		return body, false
	}
	return nb, true
}

// ─── JWT (decode only, no verification) ─────────────────────────────────────

func decodeJWTClaims(authHeader string) map[string]interface{} {
	tok := strings.TrimSpace(authHeader)
	if i := strings.IndexByte(tok, ' '); i >= 0 {
		tok = tok[i+1:]
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1] + strings.Repeat("=", (4-len(parts[1])%4)%4)); err != nil {
			return nil
		}
	}
	var claims map[string]interface{}
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims
}

// ─── minimal JSONPath ───────────────────────────────────────────────────────

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

func assignString(root interface{}, jsonPath, value string) error {
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
			if in == "*" {
				idx = 0
			}
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
			if !ok || len(a) == 0 {
				return fmt.Errorf("not array")
			}
			j := idx
			if j < 0 {
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
