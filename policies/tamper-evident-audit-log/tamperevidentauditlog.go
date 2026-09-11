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

// Package tamperevidentauditlog is a hash-chained audit trail for agent
// traffic (Agentic AI T8 Repudiation & Untraceability). Never blocks traffic
// - see policy-definition.yaml for the full record shape and chain design.
package tamperevidentauditlog

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	auditType = "TAMPER_EVIDENT_AUDIT_LOG"
	auditName = "TamperEvidentAuditLog"

	sinkMaxRespBytes = 1 << 16

	// Metadata keys stashed on SharedContext.Metadata in the request phase
	// and read back in the response phase.
	mdRequestHash = "tal:requestHash"
	mdTimestamp   = "tal:timestamp"
	mdRequestID   = "tal:requestID"
	mdPrincipal   = "tal:principal"
	mdModel       = "tal:model"
	mdToolName    = "tal:toolName"
	mdToolArgs    = "tal:toolArgs"
	mdToolArgHash = "tal:toolArgHash"
)

// ─── config ──────────────────────────────────────────────────────────────────

type config struct {
	genesisHash          string
	includeClaims        bool
	includeToolArguments bool
	modelPath            string
	toolNamePath         string
	argsPath             string
	statusPath           string
	sinkURL              string
	sinkTimeout          time.Duration
	anchorEveryN         int64
}

// TamperEvidentAuditLogPolicy implements the v1alpha2 policy interface.
type TamperEvidentAuditLogPolicy struct {
	cfg    config
	client *http.Client

	mu   sync.Mutex
	seq  int64
	head string
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg := config{
		modelPath:    "$.model",
		toolNamePath: "$.params.name",
		argsPath:     "$.params.arguments",
		statusPath:   "$.auditStatus",
		sinkTimeout:  5 * time.Second,
		anchorEveryN: 50,
	}

	if v, ok := params["genesisHash"]; ok {
		s, ok := v.(string)
		if !ok || !isHex64(s) {
			return nil, wrap(fmt.Errorf("'genesisHash' must be a 64-character hex-encoded SHA-256"))
		}
		cfg.genesisHash = strings.ToLower(s)
	}
	if err := boolParam(params, "includeClaims", &cfg.includeClaims); err != nil {
		return nil, wrap(err)
	}
	if err := boolParam(params, "includeToolArguments", &cfg.includeToolArguments); err != nil {
		return nil, wrap(err)
	}
	strOpt(params, "modelJsonPath", &cfg.modelPath)
	strOpt(params, "toolNameJsonPath", &cfg.toolNamePath)
	strOpt(params, "argumentsJsonPath", &cfg.argsPath)
	strOpt(params, "statusJsonPath", &cfg.statusPath)

	if v, ok := params["sinkUrl"]; ok {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, wrap(fmt.Errorf("'sinkUrl' must be a non-empty string"))
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, wrap(fmt.Errorf("'sinkUrl' must be a valid http(s) URL"))
		}
		cfg.sinkURL = s
	}
	if v, ok := params["sinkTimeoutSeconds"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 1 {
			return nil, wrap(fmt.Errorf("'sinkTimeoutSeconds' must be a number >= 1"))
		}
		cfg.sinkTimeout = time.Duration(f * float64(time.Second))
	}
	if v, ok := params["anchorEveryN"]; ok {
		f, err := toFloat(v)
		if err != nil || f < 0 {
			return nil, wrap(fmt.Errorf("'anchorEveryN' must be a number >= 0"))
		}
		cfg.anchorEveryN = int64(f)
	}

	head := cfg.genesisHash
	if head == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, wrap(fmt.Errorf("failed to generate a genesis hash: %w", err))
		}
		head = hex.EncodeToString(b)
	}

	return &TamperEvidentAuditLogPolicy{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.sinkTimeout},
		head:   head,
	}, nil
}

// Mode buffers both bodies: the request body to hash + extract identity from,
// the response body to hash and to pair with it into one chained record.
func (p *TamperEvidentAuditLogPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// OnRequestBody captures identity/hash material for this call and stashes it
// on SharedContext.Metadata for the response phase to pick up - or, for a
// chain-status query, answers directly without recording anything.
func (p *TamperEvidentAuditLogPolicy) OnRequestBody(_ context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	var body []byte
	if reqCtx.Body != nil {
		body = reqCtx.Body.Content
	}
	var root interface{}
	_ = json.Unmarshal(body, &root)

	if v := valueAt(root, p.cfg.statusPath); v != nil {
		return p.statusResponse()
	}

	reqHash := sha256.Sum256(body)
	md := reqCtx.Metadata
	if md == nil {
		md = map[string]interface{}{}
		reqCtx.Metadata = md
	}
	md[mdRequestHash] = hex.EncodeToString(reqHash[:])
	md[mdTimestamp] = time.Now().UTC().Format(time.RFC3339Nano)
	md[mdRequestID] = reqCtx.RequestID

	if model, ok := valueAt(root, p.cfg.modelPath).(string); ok {
		md[mdModel] = model
	}
	if name, ok := valueAt(root, p.cfg.toolNamePath).(string); ok && name != "" {
		md[mdToolName] = name
		args := valueAt(root, p.cfg.argsPath)
		canon, _ := json.Marshal(args)
		argHash := sha256.Sum256(canon)
		md[mdToolArgHash] = hex.EncodeToString(argHash[:])
		if p.cfg.includeToolArguments {
			md[mdToolArgs] = args
		}
	}

	if reqCtx.Headers != nil {
		if vals := reqCtx.Headers.Get("Authorization"); len(vals) > 0 {
			if principal := decodePrincipal(vals[0], p.cfg.includeClaims); principal != nil {
				md[mdPrincipal] = principal
			}
		}
	}

	return policy.UpstreamRequestModifications{}
}

func (p *TamperEvidentAuditLogPolicy) statusResponse() policy.RequestAction {
	p.mu.Lock()
	seq, head, genesis := p.seq, p.head, p.cfg.genesisHash
	p.mu.Unlock()
	if genesis == "" {
		genesis = "(random, generated at policy start)"
	}
	b, _ := json.Marshal(map[string]interface{}{
		"type": auditType,
		"message": map[string]interface{}{
			"action": "CHAIN_STATUS", "interveningGuardrail": auditName,
			"seq": seq, "headHash": head, "genesisHash": genesis,
		},
	})
	return policy.ImmediateResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       b,
	}
}

// OnResponseBody pairs the response with the stashed request data, extends
// the hash chain, and attaches the resulting record without altering the
// response itself.
func (p *TamperEvidentAuditLogPolicy) OnResponseBody(_ context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	md := respCtx.Metadata
	reqHash, ok := md[mdRequestHash].(string)
	if !ok {
		// No request-phase record (e.g. this call never went through
		// OnRequestBody - a chain-status query short-circuits before this
		// point). Nothing to chain.
		return policy.DownstreamResponseModifications{}
	}

	var respBody []byte
	if respCtx.ResponseBody != nil {
		respBody = respCtx.ResponseBody.Content
	}
	respHash := sha256.Sum256(respBody)
	respHashHex := hex.EncodeToString(respHash[:])

	record := map[string]interface{}{
		"timestamp": md[mdTimestamp],
		"requestId": md[mdRequestID],
		"route": map[string]interface{}{
			"api": respCtx.APIName, "version": respCtx.APIVersion,
			"method": respCtx.RequestMethod, "path": respCtx.RequestPath,
		},
		"requestHash":    reqHash,
		"responseHash":   respHashHex,
		"responseStatus": respCtx.ResponseStatus,
		"policyVersion":  "v0.1.0",
	}
	if v, ok := md[mdPrincipal]; ok {
		record["principal"] = v
	}
	if v, ok := md[mdModel]; ok {
		record["model"] = v
	}
	if name, ok := md[mdToolName]; ok {
		tool := map[string]interface{}{"name": name, "argsHash": md[mdToolArgHash]}
		if v, ok := md[mdToolArgs]; ok {
			tool["arguments"] = v
		}
		record["tool"] = tool
	}

	p.mu.Lock()
	p.seq++
	seq := p.seq
	prevHash := p.head
	record["seq"] = seq
	record["prevHash"] = prevHash
	recordHash := chainHash(prevHash, record)
	p.head = recordHash
	isAnchor := p.cfg.anchorEveryN > 0 && seq%p.cfg.anchorEveryN == 0
	sinkURL := p.cfg.sinkURL
	p.mu.Unlock()

	record["recordHash"] = recordHash
	record["isAnchor"] = isAnchor

	if sinkURL != "" {
		go p.deliver(sinkURL, record)
	}

	return policy.DownstreamResponseModifications{
		HeadersToSet: map[string]string{
			"x-audit-seq":           fmt.Sprintf("%d", seq),
			"x-audit-hash":          recordHash,
			"x-audit-prev-hash":     prevHash,
			"x-audit-request-hash":  reqHash,
			"x-audit-response-hash": respHashHex,
		},
		AnalyticsMetadata: map[string]any{"guardrailName": auditName, "auditRecord": record},
	}
}

// chainHash computes recordHash = SHA256(prevHash || canonicalRecordFields).
// encoding/json sorts map keys, so marshaling `record` (which at this point
// has not yet had recordHash/isAnchor added) is a deterministic canonical
// form for any two implementations that agree on the field set.
func chainHash(prevHash string, record map[string]interface{}) string {
	canon, _ := json.Marshal(record)
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil))
}

func (p *TamperEvidentAuditLogPolicy) deliver(sinkURL string, record map[string]interface{}) {
	b, err := json.Marshal(record)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, sinkURL, strings.NewReader(string(b)))
	if err != nil {
		slog.Warn("TamperEvidentAuditLog: failed to build sink request", "error", err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		slog.Warn("TamperEvidentAuditLog: sink unreachable", "error", err.Error())
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, sinkMaxRespBytes))
	if resp.StatusCode >= 300 {
		slog.Warn("TamperEvidentAuditLog: sink returned a non-2xx status", "status", resp.StatusCode)
	}
}

// ─── principal (unverified) ──────────────────────────────────────────────────

// decodePrincipal base64url-decodes a JWT's payload segment WITHOUT
// verifying its signature - this policy only records what the caller
// claimed, for audit purposes, never for an authorization decision.
func decodePrincipal(authHeader string, includeClaims bool) interface{} {
	tok := authHeader
	if i := strings.IndexByte(tok, ' '); i >= 0 {
		tok = tok[i+1:]
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]interface{}
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	if includeClaims {
		return claims
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub
	}
	return nil
}

// ─── minimal JSONPath ────────────────────────────────────────────────────────

// valueAt resolves "$.a.b", "$.a[0].b", "$.a[-1]" against root.
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

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
