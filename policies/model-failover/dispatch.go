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
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// internalLoopbackHeader mirrors constants.InternalLoopbackHeader in gateway-controller's
// llm_transformer.go — this is a separate Go module with no import path to that package, so
// the literal value is duplicated here rather than shared. Set on every dial this policy
// originates itself (a provider redial or a same-provider fallback/reuse dial), matching the
// existing additionalProviders loopback convention, so the analytics system can dedupe the
// duplicate event. NOT usable as a recursion guard: gateway-controller's own
// proxyInternalLoopbackMarkerPolicy stamps this SAME header, unconditionally, on every request
// through this proxy's operation — including the client's very first, genuine request — so it
// is already present long before this policy ever runs. modelFailoverRedialHeader below is the
// dedicated marker for that purpose.
const internalLoopbackHeader = "x-wso2-internal-loopback"

// modelFailoverRedialHeader marks a self-redial (cross-provider or same-provider) as this
// policy's own re-entry into the operation, distinct from internalLoopbackHeader (see above) —
// both OnRequestBody and OnResponseHeaders check this one, and only this one, to recognize and
// skip reprocessing a request/response that's already one of this policy's own redials.
const modelFailoverRedialHeader = "x-wso2-model-failover-redial"

// providerHeaderName is the header a provider redial sets to select the target provider — the
// SAME header llm-header-router already reads by default (its own DefaultHeaderName). Setting
// it makes this dial indistinguishable from a genuine client request asking for that provider:
// llm-header-router publishes selected_provider in the request-HEADER phase (before the
// provider's own conditional upstream-auth policy's CEL gate evaluates — a header-phase-only
// policy would otherwise see stale metadata, since this policy can only ever decide a
// redirect in body phase, having to inspect the client's own "model" field first), and the
// real, already-attached translator does full bidirectional body conversion. This policy never
// resolves or applies auth/template conversion itself — see the package doc.
const providerHeaderName = "x-provider"

// retryHTTPClient abstracts the outbound call a dial makes, so tests can substitute a fake
// transport instead of hitting the network. *http.Client satisfies this directly.
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

// doDial builds and executes one outbound POST-shaped attempt at targetURL, cloning src's
// headers (always stripping hop-by-hop headers; credentials are always carried through
// unchanged — see trySelfRedial's own doc comment for why), then applying extraHeaders,
// with model swapped into a shallow clone of originalBody. It reports (response, true) on a
// non-failing status or (zero value, false) on any failure — network error, oversized/
// unreadable response body, or a response status still in p.statusCodes. logField is attached
// to warning logs only, to distinguish call sites.
func (p *Policy) doDial(ctx context.Context, targetURL, method string, src *policy.Headers, extraHeaders map[string]string, model string, originalBody map[string]interface{}, logField string) (policy.ImmediateResponse, bool) {
	clone := make(map[string]interface{}, len(originalBody))
	for k, v := range originalBody {
		clone[k] = v
	}
	clone["model"] = model
	bodyBytes, err := json.Marshal(clone)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: could not build request body, skipping", "target", logField, "error", err)
		return policy.ImmediateResponse{}, false
	}

	if method == "" {
		method = http.MethodPost
	}

	dialCtx, cancel := context.WithTimeout(ctx, p.dialTimeout())
	defer cancel()

	req, err := http.NewRequestWithContext(dialCtx, method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: could not build request, skipping", "target", logField, "error", err)
		return policy.ImmediateResponse{}, false
	}
	cloneRequestHeaders(req.Header, src)
	for name, value := range extraHeaders {
		req.Header.Set(name, value)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: dial failed, trying next", "target", logField, "error", err)
		return policy.ImmediateResponse{}, false
	}
	defer resp.Body.Close()

	respBody, err := readBounded(resp.Body, p.maxResponseBytes)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: response exceeded size limit or failed to read, trying next", "target", logField, "error", err)
		return policy.ImmediateResponse{}, false
	}

	if _, stillFailing := p.statusCodes[resp.StatusCode]; stillFailing {
		slog.WarnContext(ctx, "ModelFailover: also returned a failing status, trying next", "target", logField, "status", resp.StatusCode)
		return policy.ImmediateResponse{}, false
	}

	return policy.ImmediateResponse{
		StatusCode: resp.StatusCode,
		Headers:    sanitizeResponseHeaders(resp.Header),
		Body:       respBody,
	}, true
}

// trySelfRedial makes one self-redial attempt: it dials THIS OPERATION's own externally-facing
// URL (selfBaseURL + downstreamPath, e.g. "http://127.0.0.1:8080/mf-poc-proxy/chat/completions"),
// so Envoy treats it as a genuinely fresh inbound request and re-runs the FULL policy chain —
// rate limiting, analytics, any request/response transformation, and (when providerID is set)
// llm-header-router, the matching translator, and the provider's own conditional upstream-auth
// policy — rather than this policy dialing a backend or resolving anything itself. This is the
// ONLY dial mechanism a fallback ever uses now (see the package doc for why a same-provider
// "reuse primary" fallback is just as much a self-redial as a cross-provider one: a raw direct
// dial would silently skip every other attached policy's processing for that specific attempt,
// which is invisible and surprising for anything relying on per-request behavior — rate limits,
// audit logs, PII masking). providerID is empty for a same-provider "reuse primary" fallback: no
// providerHeaderName is set, so the redialed request just falls through to the operation's own
// default upstream — GetPolicy's own validation guarantees that's always correct, since a target
// that redirects its own primary requires every one of its own fallbacks to set a provider too
// (there being no "default upstream" left to correctly fall through to in that case). The
// modelFailoverRedialHeader guard prevents this redial from recursing back into any
// target/fallback processing on its own re-entry (see OnRequestBody and OnResponseHeaders).
func (p *Policy) trySelfRedial(ctx context.Context, selfBaseURL, downstreamPath, method string, headers *policy.Headers, providerID, model string, originalBody map[string]interface{}) (policy.ImmediateResponse, bool) {
	if selfBaseURL == "" || downstreamPath == "" {
		slog.WarnContext(ctx, "ModelFailover: no self base URL/downstream path available, cannot redial", "provider", providerID)
		return policy.ImmediateResponse{}, false
	}
	targetURL := strings.TrimSuffix(selfBaseURL, "/") + downstreamPath
	extra := map[string]string{
		internalLoopbackHeader:    "1",
		modelFailoverRedialHeader: "1",
	}
	logField := "reuse-primary"
	if providerID != "" {
		extra[providerHeaderName] = providerID
		logField = "provider:" + providerID
	}
	// Credentials are NOT stripped here (stripCredentials=false), deliberately: this redial
	// re-enters the SAME operation as a genuinely fresh downstream request, so if that
	// operation requires its own inbound auth (api-key-auth, jwt-auth, anything), the redial
	// needs the client's own credential to pass it — exactly like any other request would.
	// For a provider redial this doesn't leak that credential to the wrong backend for a
	// correctly-configured provider: the provider's own conditional upstream-auth policy runs
	// later in this SAME request-phase chain and overwrites Authorization/x-api-key with the
	// real upstream credential before the request ever leaves the gateway. The one gap this
	// doesn't cover: a provider declaring auth type none/other with nothing else attached to
	// set a credential — there the client's own credential could reach that backend unchanged.
	// That falls on the operator's own multi-provider configuration, the same as it would for
	// any other caller of that provider, not something unique to a redial. For a same-provider
	// "reuse primary" redial the credential is simply the same one that already worked, reused
	// unchanged — no auth policy needs to run differently the second time.
	return p.doDial(ctx, targetURL, method, headers, extra, model, originalBody, logField)
}

// cloneRequestHeaders copies every header from src into dst except hop-by-hop headers and
// anything that starts with ":" (HTTP/2 pseudo-headers should never appear in this SDK's
// Headers type for a downstream-phase context, but net/http.Transport rejects them outright
// if one ever did — skip defensively rather than let a single bad header fail the whole
// attempt). Credentials (Authorization, x-api-key, etc.) are always carried through unchanged
// — see trySelfRedial's own doc comment for why a provider redial needs that.
func cloneRequestHeaders(dst http.Header, src *policy.Headers) {
	if src == nil {
		return
	}
	src.Iterate(func(name string, values []string) {
		if strings.HasPrefix(name, ":") {
			return
		}
		if _, hopByHop := hopByHopHeaders[strings.ToLower(name)]; hopByHop {
			return
		}
		for _, v := range values {
			dst.Add(name, v)
		}
	})
}

// sanitizeResponseHeaders builds the header map for ImmediateResponse from the dial's own
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
