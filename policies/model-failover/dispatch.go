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

package modelfailover

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// internalLoopbackHeader mirrors constants.InternalLoopbackHeader in gateway-controller's
// llm_transformer.go — this is a separate Go module with no import path to that package, so
// the literal value is duplicated here rather than shared. Set on every provider-loopback
// dial for parity with the existing additionalProviders loopback mechanism (today it's
// consumed only for analytics dedup, not as an access-control bypass — see the package doc's
// open question on this).
const internalLoopbackHeader = "x-wso2-internal-loopback"

// retryHTTPClient abstracts the outbound call a fallback dial makes, so tests can substitute
// a fake transport instead of hitting the network. *http.Client satisfies this directly.
type retryHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func newDefaultRetryHTTPClient() retryHTTPClient {
	// No client-level Timeout: every call site wraps ctx with context.WithTimeout using the
	// policy's own configured (or default) per-attempt timeout, which is what actually
	// bounds latency here — see go-network-service-hardening.md on explicit, non-zero
	// timeouts for every outbound call.
	return &http.Client{}
}

// hopByHopHeaders (RFC 7230 §6.1) and connection-specific headers must never be blindly
// replayed onto a new outbound request — a subset were the actual cause of a live bug in
// oauth2-generator's own self-retry (net/http.Transport rejects some of these outright).
// content-length and host are excluded here too: content-length is recomputed by net/http
// from the (possibly transformed) body, and host is set via the target URL, not header
// replay.
var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"content-length":      {},
	"host":                {},
}

// credentialHeaders are stripped before dialing a provider-loopback fallback (fb.provider !=
// "") — the original request's credential was for the PRIMARY's own upstream, not this
// target. tryFallback sets the provider's own resolved credential explicitly afterward (see
// resolvedAuthHeader/resolvedAuthValue) when one is declared; stripping first means a request
// missing that resolved credential never falls back to leaking the primary's own credential to
// a backend it was never meant for.
var credentialHeaders = map[string]struct{}{
	"authorization": {},
	"x-api-key":     {},
}

// tryFallback makes one direct outbound attempt at fb and reports (action, true) on success
// or (nil, false) on any failure — network error, a response status still in statusCodes, or
// a request/response the configured template adapter can't convert. The caller is
// responsible for suspend bookkeeping; this function only ever executes a single dial, never
// recurses into the rest of the chain itself.
func (p *Policy) tryFallback(ctx context.Context, rhctx *policy.ResponseHeaderContext, group targetGroup, fb fallbackTarget, originalBody map[string]interface{}) (policy.ResponseHeaderAction, bool) {
	targetURL, err := resolveTargetURL(fb, rhctx.Upstream, rhctx.RequestPath)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: could not resolve fallback URL, skipping", "model", fb.model, "error", err)
		return nil, false
	}

	bodyBytes, requiredHeaders, err := buildTargetBody(fb, originalBody)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: could not build fallback request body, skipping", "model", fb.model, "error", err)
		return nil, false
	}

	method := rhctx.RequestMethod
	if method == "" {
		method = http.MethodPost
	}

	dialCtx, cancel := context.WithTimeout(ctx, p.dialTimeout())
	defer cancel()

	req, err := http.NewRequestWithContext(dialCtx, method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: could not build fallback request, skipping", "model", fb.model, "error", err)
		return nil, false
	}
	// Credential stripping and the loopback marker only apply to a provider (genuinely
	// different backend, own auth) — an upstreamDefinition fallback is the SAME provider, so
	// the original request's own credential is exactly what it needs, unchanged.
	cloneRequestHeaders(req.Header, rhctx.RequestHeaders, fb.provider != "")
	for name, value := range requiredHeaders {
		req.Header.Set(name, value)
	}
	if fb.provider != "" {
		req.Header.Set(internalLoopbackHeader, "1")
		// A target-level provider redirect stays in the SAME request-phase chain, so it gets
		// the provider's own conditional upstream-auth policy for free (see the package doc).
		// This response-phase dial never re-enters that chain, so the credential is set
		// directly here from gateway-controller's resolvedAuthHeader/resolvedAuthValue
		// (mirrors proxyUpstreamAuthPolicy's own header, valuePrefix already applied) — the
		// same reasoning as resolvedUpstreamURL/resolvedTransformerType above. Empty means no
		// api-key auth was declared for this provider ("none", or "other" left to the
		// operator's own attached policies).
		if fb.resolvedAuthHeader != "" {
			req.Header.Set(fb.resolvedAuthHeader, fb.resolvedAuthValue)
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: fallback dial failed, trying next", "model", fb.model, "error", err)
		return nil, false
	}
	defer resp.Body.Close()

	respBody, err := readBounded(resp.Body, p.maxResponseBytes)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: fallback response exceeded size limit or failed to read, trying next", "model", fb.model, "error", err)
		return nil, false
	}

	if _, stillFailing := p.statusCodes[resp.StatusCode]; stillFailing {
		slog.WarnContext(ctx, "ModelFailover: fallback also returned a failing status, trying next", "model", fb.model, "status", resp.StatusCode)
		return nil, false
	}

	finalBody := respBody
	if fb.resolvedTransformerType != "" {
		adapter := templateAdapters[fb.resolvedTransformerType] // parseFallbackTarget already validated this exists
		finalBody, err = adapter.FromTarget(respBody)
		if err != nil {
			slog.WarnContext(ctx, "ModelFailover: could not convert fallback response, trying next", "model", fb.model, "error", err)
			return nil, false
		}
	}

	return policy.ImmediateResponse{
		StatusCode: resp.StatusCode,
		Headers:    sanitizeResponseHeaders(resp.Header),
		Body:       finalBody,
	}, true
}

// buildTargetBody swaps "model" to fb.model and, if fb resolved to a non-empty transformer,
// converts the whole body via the registered adapter. Model rewriting always happens before
// conversion — mirrors the original policy's ordering guarantee that a template adapter never
// needs to know anything about model-name placement, just full-body conversion.
func buildTargetBody(fb fallbackTarget, originalBody map[string]interface{}) ([]byte, map[string]string, error) {
	clone := make(map[string]interface{}, len(originalBody))
	for k, v := range originalBody {
		clone[k] = v
	}
	clone["model"] = fb.model

	if fb.resolvedTransformerType == "" {
		body, err := json.Marshal(clone)
		return body, nil, err
	}

	adapter, ok := templateAdapters[fb.resolvedTransformerType]
	if !ok {
		return nil, nil, fmt.Errorf("no adapter registered for transformer %q", fb.resolvedTransformerType)
	}
	body, err := adapter.ToTarget(clone)
	if err != nil {
		return nil, nil, err
	}
	return body, adapter.RequiredHeaders(), nil
}

// resolveTargetURL determines the full URL to dial for fb. Neither provider nor
// upstreamDefinition reuses the primary's own resolved upstream (same backend — see the
// fallbackTarget doc comment); either one dials its own resolvedUpstreamURL
// (gateway-controller-injected, never operator-supplied) with the original request's own
// relative path appended, matching the operation path convention every LlmProvider shares.
func resolveTargetURL(fb fallbackTarget, upstream *policy.UpstreamResponseContext, originalPath string) (string, error) {
	if !fb.crossesProvider() {
		if upstream == nil || upstream.URL == "" {
			return "", fmt.Errorf("fallback has no provider/upstreamDefinition configured and the primary upstream is unknown")
		}
		return joinURL(upstream.URL, upstream.BasePath, originalPath)
	}
	if fb.resolvedUpstreamURL == "" {
		// parseFallbackTarget already rejects this at config-load time; unreachable in
		// practice, but must never silently dial an empty target.
		return "", fmt.Errorf("fallback has no resolved upstream URL")
	}
	return joinURL(fb.resolvedUpstreamURL, "", originalPath)
}

func joinURL(base, basePath, path string) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(base, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid or incomplete url %q", base)
	}
	segment := func(s string) string {
		if s == "" {
			return ""
		}
		if !strings.HasPrefix(s, "/") {
			s = "/" + s
		}
		return s
	}
	u.Path = u.Path + segment(basePath) + segment(path)
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

// cloneRequestHeaders copies every header from src into dst except hop-by-hop headers and
// anything that starts with ":" (HTTP/2 pseudo-headers should never appear in this SDK's
// Headers type for a downstream-phase context, but net/http.Transport rejects them outright
// if one ever did — skip defensively rather than let a single bad header fail the whole
// attempt). stripCredentials additionally drops credentialHeaders — set for a provider-loopback
// dial, where the original request's credential belongs to a different backend entirely.
func cloneRequestHeaders(dst http.Header, src *policy.Headers, stripCredentials bool) {
	if src == nil {
		return
	}
	src.Iterate(func(name string, values []string) {
		if strings.HasPrefix(name, ":") {
			return
		}
		lower := strings.ToLower(name)
		if _, hopByHop := hopByHopHeaders[lower]; hopByHop {
			return
		}
		if stripCredentials {
			if _, isCredential := credentialHeaders[lower]; isCredential {
				return
			}
		}
		for _, v := range values {
			dst.Add(name, v)
		}
	})
}

// sanitizeResponseHeaders builds the header map for ImmediateResponse from the fallback's own
// response, dropping hop-by-hop headers for the same reason cloneRequestHeaders does on the
// way out.
func sanitizeResponseHeaders(src http.Header) map[string]string {
	out := make(map[string]string, len(src))
	for name, values := range src {
		if len(values) == 0 {
			continue
		}
		if _, hopByHop := hopByHopHeaders[strings.ToLower(name)]; hopByHop {
			continue
		}
		out[name] = values[0]
	}
	return out
}

// readBounded reads at most limit+1 bytes and errors if that many were available — the "+1"
// makes an exactly-at-the-limit body indistinguishable from a real overflow, which is the
// correct conservative choice here (see file-access.md on configurable stream size limits).
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeded %d byte limit", limit)
	}
	return data, nil
}
