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

// Package modelfailover provides a policy that transparently retries a failed LLM request
// against an ordered fallback chain — one independently-selectable chain per target, selected
// by matching the client's own model identifier (located per requestModel, see requestmodel.go)
// against a declared target's model, and — for a multi-provider proxy where the same model name
// can legitimately arrive via more than one provider — its provider too. Provider is read from
// the primary request's own providerHeaderName header (the same header a selector like
// llm-header-router reads to route it), never configured or redirected by this policy (see
// groupByModel). A target with no provider set is a catch-all for that model: it matches when
// no more specific (model, provider) target exists, or when the primary request carried no
// provider header at all — the common case for a single-provider proxy, where this
// disambiguation never comes into play.
//
// The client's own primary request is NEVER intercepted, redirected, or otherwise modified by
// this policy. It reaches whatever upstream the rest of the operation's own policy chain (and
// Envoy's own default routing) already resolves it to, exactly as if this policy weren't
// attached at all. This policy only ever acts from OnResponseHeaders, and only once that
// primary attempt has genuinely been dialed and come back with a status in statusCodes — there
// is no "target-level" pre-dial redirect of any kind. This is a deliberate simplification: an
// earlier version of this policy also let a target redirect its own primary attempt before
// ever dialing (to avoid a wasted round-trip to a backend that could never have worked for that
// model) — that pre-dial path has been removed. What used to be a target's own primary
// override is now just its first configured fallback, tried after one real (if foreseeably
// futile) primary attempt like any other.
//
// Mechanism (response-path retry — NOT Envoy aggregate-cluster/upstream-ext_proc): every
// fallback this policy originates itself — cross-provider or same-provider — is a SELF-REDIAL
// (see below): this operation's own externally-facing URL, dialed again, so the attempt runs
// through the full policy chain like any other request. A raw direct call would silently skip
// every OTHER attached policy's processing for that one attempt — rate limiting, analytics, any
// request/response transformation — which is invisible and surprising for anything relying on
// per-request behavior. On success the attempt's response is returned via ImmediateResponse.
// A fallback's own upstreamDefinition (same-provider, different backend) has no pre-dial moment
// of its own to apply an in-process UpstreamName swap directly — the primary has already been
// dialed and failed by the time a fallback runs — so it rides the self-redial, distinguished
// from a provider fallback by which header it sets (see modelFailoverUpstreamDefHeader in
// dispatch.go), and the redialed request's own (fresh, independent) pass through OnRequestBody
// applies the UpstreamName swap for THAT dial.
//
// This policy is entirely standalone — gateway-controller has no awareness of it, injects no
// params for it, and validates nothing about its config. Everything below is a runtime
// convention between this policy and whatever else the operator has attached, not a code
// coupling.
//
// Cross-provider fallbacks (declaring provider) never carry their own url/auth/template. A
// provider reference is resolved entirely by a SELF-REDIAL: this policy dials its OWN
// operation's externally-facing URL again (selfBaseURL — defaults to defaultSelfBaseURL,
// operator-overridable via the policy's own params — plus the original downstream path) with
// the providerHeaderName header set to the chosen provider id (dispatch.go). Because that's a
// genuinely fresh inbound request as far as Envoy is concerned, it re-runs the FULL policy
// chain from scratch — PROVIDED the operator has attached a header-based provider-selector
// policy (e.g. llm-header-router) to the same operation, alongside model-failover, the same
// way any other multi-provider proxy would:
//
//   - The selector reads providerHeaderName and publishes SharedContext.Metadata
//     ["selected_provider"] — in the request-HEADER phase, not body phase. That distinction
//     matters: the provider's own conditional upstream-auth policy (a header-phase-only
//     "set-headers" instance) evaluates its ExecutionCondition during the SAME header-phase
//     pass, which completes and is sent back to Envoy before body-phase policies (this one
//     included) ever run — so a redirect signal this policy could only ever produce in body
//     phase (it has to see the client's "model" field first) would always be one phase too
//     late for that gate. Publishing via a real header sidesteps the ordering problem instead
//     of fighting it. Without a selector attached, the redial just reaches the operation's own
//     default upstream, unchanged — the provider reference silently does nothing.
//   - The matching translator and the provider's own conditional upstream-auth policy then
//     fire correctly as a result — full bidirectional body conversion and credential
//     injection, done for real by whatever already-shipped, general-purpose policies the
//     operator has attached for multi-provider routing. This policy never resolves or applies
//     either itself, and carries no per-vendor adapter of its own. The provider id this policy
//     sends just needs to match whatever the operator's own selector mappings expect —
//     model-failover neither knows nor cares how that selector or those provider ids came to
//     exist.
//
// Same-provider, different-backend routing (e.g. a backup region) is unrelated to cross-provider
// routing, and stays fully decoupled from gateway-controller in the same way: a bare name, used
// as an in-process Envoy UpstreamName redirect (no auth/template complexity since it's the same
// provider) — Envoy's own routing resolves it at runtime against this same resource's own
// already-declared spec.upstreamDefinitions, so this policy needs nothing resolved ahead of
// time and never sees a raw URL. The self-redial carries the chosen name in
// modelFailoverUpstreamDefHeader, and the redialed request's own OnRequestBody applies the
// UpstreamName redirect on its own (fresh, independent) pass.
//
// OnRequestBody's ONLY job, therefore, is routing this policy's own self-redials to the right
// same-provider upstream on their own fresh pass (modelFailoverUpstreamDefHeader) — it never
// inspects, matches, or redirects a genuine client request. OnResponseHeaders' own
// modelFailoverRedialHeader guard exists for the same reason at the response end: a self-redial
// re-enters this SAME operation, which still has this policy attached, so without the guard the
// redial's own (possibly still-failing) response would trigger a second, nested fallback walk
// from inside the first one's own processing. The guard's only job is breaking that recursion —
// a client spoofing the header themselves just means failover doesn't apply to that one
// request, never a routing or auth bypass (see dispatch.go).
package modelfailover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// defaultMaxResponseBytes bounds a dial's response body when no maxResponseBytes param is
// configured. Mirrors the network-hardening requirement that every outbound read be wrapped in
// a config-sourced ceiling (see go-network-service-hardening.md / file-access.md); 10MiB
// matches the precedent set by oauth2-generator's own self-retry response cap.
const defaultMaxResponseBytes = 10 << 20

// defaultDialTimeout is used for a dial when requestTimeout isn't configured.
const defaultDialTimeout = 10 * time.Second

// defaultSelfBaseURL is used for a self-redial when the operator doesn't set selfBaseURL
// explicitly — the router's own default listener address (router.listener_port's own default).
// This policy is standalone: gateway-controller never injects this value (see the package
// doc), so a deployment that changes the listener port away from its default must set
// selfBaseURL on the policy itself.
const defaultSelfBaseURL = "http://127.0.0.1:8080"

// originalBodyMetadataKey is where OnRequestBody stashes the request body it already decoded,
// for OnResponseHeaders to reuse later instead of re-reading rhctx.RequestBody. Namespaced
// (not a bare "body") since SharedContext.Metadata is a chain-wide bag any policy can write
// into — see the package doc for why this snapshot exists at all.
const originalBodyMetadataKey = "model-failover:original-body"

// fallbackTarget is one entry in a target group's own ordered fallback chain. provider and
// upstreamDefinition are mutually exclusive; at most one is ever set.
type fallbackTarget struct {
	model string // model name to inject into the request body for this attempt

	// provider is empty unless this fallback crosses providers. When set, it names a
	// provider id — resolved entirely via a self-redial with providerHeaderName set (see the
	// package doc and dispatch.go's trySelfRedial). Purely opaque to this policy: it's
	// whatever id the operator's own attached selector (e.g. llm-header-router) expects.
	provider string

	// upstreamDefinition is empty unless this fallback stays on the SAME provider but a
	// DIFFERENT backend of it (e.g. a backup region) — a bare name resolved against this same
	// resource's own spec.upstreamDefinitions by Envoy's own routing, never a raw URL. Applied
	// via the self-redial carrying modelFailoverUpstreamDefHeader (see the package doc and
	// dispatch.go's trySelfRedial) — unlike the target-level case, there's no pre-dial moment
	// left for a fallback to apply this directly.
	upstreamDefinition string
}

// targetGroup is one independently-selectable target: model is the client-requested value
// that selects this whole group, and fallbacks is that group's own ordered failover chain —
// entirely independent of every other group's chain (own suspend state). The primary attempt
// for this model is always the operation's own default routing, untouched by this policy;
// fallbacks is tried only after that primary attempt genuinely fails (see the package doc).
//
// provider is a MATCH qualifier, not a redirect instruction (unlike a fallback's own provider
// field — see fallbackTarget): it disambiguates which target applies when the same model name
// can legitimately reach this operation via more than one provider (e.g. a multi-provider proxy
// where "claude-3-5-sonnet" means something different depending on which provider the primary
// attempt actually went to). Read from the ACTUAL primary request's own providerHeaderName
// header at match time (see OnResponseHeaders) — never configured routing, since this policy
// never decides where the primary goes. Empty means "match this model regardless of provider",
// and is the common case for a single-provider proxy where this disambiguation never matters.
type targetGroup struct {
	model     string
	provider  string
	fallbacks []fallbackTarget
}

// targetKey is the compound lookup key for Policy.targetByModel: (model, provider). A target
// with an empty provider is a catch-all for that model, used when either the operator declared
// no provider-specific targets for it, or the primary request carried no providerHeaderName
// header at all — see groupByModel.
type targetKey struct {
	model    string
	provider string
}

// Policy holds the parsed, validated model-failover configuration consumed by OnResponseHeaders
// (the fallback retry loop after a normal primary failure) and, minimally, by OnRequestBody
// (routing this policy's own self-redials on their own fresh pass — see the package doc).
type Policy struct {
	targets          []targetGroup
	targetByModel    map[targetKey]int // (client-requested model, primary's own provider) -> index into targets
	statusCodes      map[int]struct{}
	requestTimeout   time.Duration // per-attempt dial timeout; 0 = use defaultDialTimeout
	suspendDuration  time.Duration // zero = suspend tracking disabled
	maxResponseBytes int64
	selfBaseURL      string // operator-configurable; defaults to defaultSelfBaseURL if unset
	requestModel     requestModelConfig
	suspend          suspendStore
	httpClient       retryHTTPClient
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	requestModelCfg, err := parseRequestModelConfig(params)
	if err != nil {
		return nil, err
	}

	rawTargets, ok := params["targets"].([]interface{})
	if !ok || len(rawTargets) == 0 {
		return nil, fmt.Errorf("model-failover requires a non-empty 'targets' list")
	}

	targets := make([]targetGroup, 0, len(rawTargets))
	targetByModel := make(map[targetKey]int, len(rawTargets))
	for i, raw := range rawTargets {
		t, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("model-failover: targets[%d] is not an object", i)
		}
		model, _ := t["model"].(string)
		if model == "" {
			return nil, fmt.Errorf("model-failover: targets[%d].model is required", i)
		}
		provider := getStringParam(t, "provider")
		key := targetKey{model: model, provider: provider}
		if _, exists := targetByModel[key]; exists {
			if provider == "" {
				return nil, fmt.Errorf("model-failover: targets[%d].model %q is declared more than once with no provider set", i, model)
			}
			return nil, fmt.Errorf("model-failover: targets[%d]: model %q + provider %q is declared more than once", i, model, provider)
		}

		rawFallbacks, _ := t["fallbacks"].([]interface{})
		fallbacks := make([]fallbackTarget, 0, len(rawFallbacks))
		for j, rawFb := range rawFallbacks {
			fb, err := parseFallbackTarget(rawFb, i, j)
			if err != nil {
				return nil, err
			}
			fallbacks = append(fallbacks, fb)
		}

		targetByModel[key] = len(targets)
		targets = append(targets, targetGroup{
			model:     model,
			provider:  provider,
			fallbacks: fallbacks,
		})
	}

	rawCodes, ok := params["statusCodes"].([]interface{})
	if !ok || len(rawCodes) == 0 {
		return nil, fmt.Errorf("model-failover requires a non-empty 'statusCodes' list")
	}
	statusCodes := make(map[int]struct{}, len(rawCodes))
	for _, raw := range rawCodes {
		code, ok := toInt(raw)
		if !ok {
			return nil, fmt.Errorf("model-failover: statusCodes entries must be integers")
		}
		statusCodes[code] = struct{}{}
	}

	selfBaseURL := getStringParam(params, "selfBaseURL")
	if selfBaseURL == "" {
		// Defaults to the router's own default listener address — deliberately NOT
		// gateway-controller-injected (see the package doc): this policy is fully standalone,
		// with no gateway-controller awareness of it at all. A deployment that changes
		// router.listener_port away from its default must set selfBaseURL explicitly.
		selfBaseURL = defaultSelfBaseURL
	}

	// The process-wide client built once at policy-engine startup (pooling, timeouts, TLS,
	// SSRF-guard dial behavior — see utils.SharedHTTPClient's own doc). A nil return means the
	// engine hasn't installed one yet, which is a configuration error, not something to paper
	// over with a locally-built http.Client that would bypass those hardened defaults.
	httpClient := utils.SharedHTTPClient()
	if httpClient == nil {
		return nil, fmt.Errorf("model-failover: shared outbound HTTP client not initialized")
	}

	p := &Policy{
		targets:          targets,
		targetByModel:    targetByModel,
		statusCodes:      statusCodes,
		maxResponseBytes: defaultMaxResponseBytes,
		selfBaseURL:      selfBaseURL,
		requestModel:     requestModelCfg,
		httpClient:       httpClient,
	}

	if raw := getStringParam(params, "requestTimeout"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("model-failover: invalid requestTimeout %q: %w", raw, err)
		}
		p.requestTimeout = d
	}
	if raw := getStringParam(params, "suspendDuration"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("model-failover: invalid suspendDuration %q: %w", raw, err)
		}
		p.suspendDuration = d
	}
	if raw, ok := params["maxResponseBytes"]; ok {
		n, ok := toInt(raw)
		if !ok || n <= 0 {
			return nil, fmt.Errorf("model-failover: maxResponseBytes must be a positive integer")
		}
		p.maxResponseBytes = int64(n)
	}

	// Suspend tracking is in-memory only, permanently — no cross-replica (Redis-backed) option.
	p.suspend = newMemorySuspendStore()

	return p, nil
}

// parseFallbackTarget parses and validates a single targets[i].fallbacks[j] entry.
func parseFallbackTarget(raw interface{}, i, j int) (fallbackTarget, error) {
	fb, ok := raw.(map[string]interface{})
	if !ok {
		return fallbackTarget{}, fmt.Errorf("model-failover: targets[%d].fallbacks[%d] is not an object", i, j)
	}
	model, _ := fb["model"].(string)
	if model == "" {
		return fallbackTarget{}, fmt.Errorf("model-failover: targets[%d].fallbacks[%d].model is required", i, j)
	}

	result := fallbackTarget{
		model:              model,
		provider:           getStringParam(fb, "provider"),
		upstreamDefinition: getStringParam(fb, "upstreamDefinition"),
	}
	if result.provider != "" && result.upstreamDefinition != "" {
		return fallbackTarget{}, fmt.Errorf("model-failover: targets[%d].fallbacks[%d] sets both provider and upstreamDefinition — mutually exclusive", i, j)
	}

	return result, nil
}

// toInt accepts both a real int (already-typed Go config) and float64 (the shape
// encoding/json produces for a bare JSON number) — config sources vary between the two.
func toInt(raw interface{}) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// getStringParam safely extracts a string parameter, returning "" if absent or the wrong
// type. Leading/trailing whitespace is trimmed: values pasted from config files or secret
// stores frequently carry a stray trailing newline or space, invisible in logs but able to
// silently corrupt a downstream comparison. Copied verbatim from oauth2-generator's
// convention (oauth2_generator.go).
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return strings.TrimSpace(str)
		}
	}
	return ""
}

// Mode: needs the request body buffered so it survives into ResponseHeaderContext.RequestBody,
// where OnResponseHeaders re-extracts the client's model to select a target group on a genuine
// primary failure — NOT because OnRequestBody itself needs the body; it never reads it (see the
// package doc). No request-HEADER phase hook: provider-selection publishing is
// llm-header-router's job (see the package doc), not this policy's. Never needs the response
// body — a failing response's body is discarded, an ImmediateResponse replaces it before the
// kernel forwards a single byte downstream.
func (p *Policy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// groupByModel looks up a target group by the client-requested model name and the primary
// request's own provider (empty if the primary request carried no providerHeaderName header —
// see requestedProvider in OnResponseHeaders). An exact (model, provider) match wins; if none
// exists, falls back to a provider-agnostic (model, "") target so a config that never declares
// per-provider targets — the common single-provider-proxy case — is unaffected by any of this.
func (p *Policy) groupByModel(model, provider string) (targetGroup, bool) {
	if provider != "" {
		if idx, ok := p.targetByModel[targetKey{model: model, provider: provider}]; ok {
			return p.targets[idx], true
		}
	}
	if idx, ok := p.targetByModel[targetKey{model: model}]; ok {
		return p.targets[idx], true
	}
	return targetGroup{}, false
}

// requestedProvider reads providerHeaderName off the primary request's own headers — the same
// header llm-header-router reads to decide which provider the primary attempt actually went to
// (see the package doc). Empty if absent, which groupByModel treats as "no provider to match
// against" rather than an error.
func requestedProvider(headers *policy.Headers) string {
	if headers == nil {
		return ""
	}
	if vals := headers.Get(providerHeaderName); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// dialTimeout returns the configured per-attempt timeout, or defaultDialTimeout if unset.
func (p *Policy) dialTimeout() time.Duration {
	if p.requestTimeout > 0 {
		return p.requestTimeout
	}
	return defaultDialTimeout
}

// downstreamPath returns the original, pre-mutation client-facing request path (e.g.
// "/mf-poc-proxy/chat/completions") — used to build a self-redial's own target URL, so
// Envoy re-matches it against this SAME operation. Empty if unavailable.
func downstreamPath(d *policy.DownstreamContext) string {
	if d == nil || d.Request == nil {
		return ""
	}
	return d.Request.Path
}

// downstreamHeaders returns the client's own request headers as a snapshot captured by the
// kernel BEFORE any policy's header-phase hook ran — unlike rctx.Headers/rhctx.RequestHeaders,
// which are the SAME live object every policy's own header-phase mutations apply to, this one
// is frozen at arrival and never mutated afterward. Used everywhere this policy replays the
// client's own request (every fallback/override attempt is a self-redial — see the package
// doc), so a header-phase policy's own mutation (e.g. an upstream-auth policy on the PRIMARY's
// own dispatch) is never accidentally carried into a redial meant for a completely different
// backend. nil if unavailable.
func downstreamHeaders(d *policy.DownstreamContext) *policy.Headers {
	if d == nil || d.Request == nil {
		return nil
	}
	return d.Request.Headers
}

// downstreamBody returns the client's own request body as a snapshot captured by the
// kernel BEFORE any policy's body-phase hook ran — the body-phase counterpart to
// downstreamHeaders above, and unused for the exact same reason it exists: whatever an
// earlier body-mutating policy already turned the request into (e.g. a translator or a
// prompt-decorator rewriting the payload for the PRIMARY's own dispatch) must never be
// accidentally carried into a redial meant for a completely different backend — every
// fallback/override attempt replays the client's TRUE original body, not whatever the
// live, mutable RequestContext.Body/ResponseHeaderContext.RequestBody currently holds.
// nil if unavailable (in particular: a streaming request body, where no single complete
// body ever exists to snapshot).
func downstreamBody(d *policy.DownstreamContext) []byte {
	if d == nil || d.Request == nil || d.Request.Body == nil {
		return nil
	}
	return d.Request.Body.Content
}

// OnRequestBody never touches, redirects, or even reads the body of a genuine client request —
// the client's primary attempt always reaches whatever the rest of the operation's own policy
// chain and Envoy's own default routing already resolve it to (see the package doc). Its only
// possible action is routing this policy's OWN self-redial, on that redial's fresh pass back
// through this same operation, to the same-provider upstream its originating fallback declared.
//
// The modelFailoverRedialHeader guard identifies that case: it's set on every self-redial this
// policy originates itself (see dispatch.go), so seeing it here means this IS one of this
// policy's own redials re-entering the operation, never a genuine client request. A cross-
// provider redial needs nothing further from this policy (routing is llm-header-router's job,
// via providerHeaderName, not this one's — see the package doc), so it falls through to the
// same untouched passthrough as everything else. A same-provider redial carries
// modelFailoverUpstreamDefHeader instead: that fallback's upstreamDefinition has no pre-dial
// moment of its own to apply the in-process UpstreamName swap (the primary already failed by
// the time a fallback runs), so it applies the swap here, on the redial's own fresh pass.
func (p *Policy) OnRequestBody(_ context.Context, rctx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if rctx.Headers != nil && rctx.Headers.Has(modelFailoverRedialHeader) {
		if vals := rctx.Headers.Get(modelFailoverUpstreamDefHeader); len(vals) > 0 && vals[0] != "" {
			upstreamName := vals[0]
			return policy.UpstreamRequestModifications{UpstreamName: &upstreamName}
		}
	}
	return policy.UpstreamRequestModifications{}
}

// OnResponseHeaders drives the fallback retry loop after a NORMAL primary attempt has already
// failed. On a response whose status matches statusCodes, it walks the matched target group's
// fallback chain — skipping any fallback currently suspended — making a self-redial attempt per
// candidate (see trySelfRedial in dispatch.go) until one succeeds (returned via ImmediateResponse)
// or the chain is exhausted (the original failing response passes through unchanged). A request
// whose model doesn't match any declared target, or whose status doesn't match statusCodes, is
// untouched.
//
// The modelFailoverRedialHeader guard is checked first, mirroring OnRequestBody: this response
// belongs to one of this policy's own redials, not the original client request. If a
// fallback's own model happens to coincide with an independently-declared target (or a cycle of
// them), skipping the walk here is what stops that from recursing — a redial's own failure is
// decided once, by the trySelfRedial/doDial call that originated it (which independently
// checks p.statusCodes itself against the raw response), never by a second, nested fallback walk
// triggered from inside the redial's own response processing. Without this, "whichever request
// happens to be redialed" would drive further failover instead of only ever the original one.
func (p *Policy) OnResponseHeaders(ctx context.Context, rhctx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if rhctx.RequestHeaders != nil && rhctx.RequestHeaders.Has(modelFailoverRedialHeader) {
		return policy.DownstreamResponseHeaderModifications{}
	}
	if _, failing := p.statusCodes[rhctx.ResponseStatus]; !failing {
		return policy.DownstreamResponseHeaderModifications{}
	}
	if rhctx.RequestBody == nil || !rhctx.RequestBody.Present {
		// Nothing to replay against a fallback without the original body.
		return policy.DownstreamResponseHeaderModifications{}
	}

	requestedModel, err := extractRequestedModel(p.requestModel, rhctx.RequestBody.Content, rhctx.RequestHeaders, rhctx.RequestPath)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: could not extract request model, cannot select a target", "error", err)
		return policy.DownstreamResponseHeaderModifications{}
	}

	group, matched := p.groupByModel(requestedModel, requestedProvider(rhctx.RequestHeaders))
	if !matched || len(group.fallbacks) == 0 {
		return policy.DownstreamResponseHeaderModifications{}
	}

	path := downstreamPath(rhctx.Downstream)
	headers := downstreamHeaders(rhctx.Downstream)
	body := downstreamBody(rhctx.Downstream)
	order := p.orderedFallbackIndices(ctx, rhctx.SharedContext, group)
	for _, idx := range order {
		fb := group.fallbacks[idx]

		resp, ok := p.trySelfRedial(ctx, rhctx.SharedContext, p.selfBaseURL, path, rhctx.RequestMethod, headers, fb.provider, fb.upstreamDefinition, body, fb.model)
		if !ok {
			if p.suspendDuration > 0 {
				p.suspend.Suspend(ctx, suspendKey(rhctx.SharedContext, group.model, group.provider, idx), p.suspendDuration)
			}
			continue
		}
		return resp
	}

	// Every fallback failed — let the original failing response through unchanged rather
	// than fabricating an error of our own.
	return policy.DownstreamResponseHeaderModifications{}
}

// orderedFallbackIndices returns the group's fallback indices in declared order, with any
// currently-suspended index moved after every non-suspended one — still tried eventually
// (never dropped outright), just deprioritized.
func (p *Policy) orderedFallbackIndices(ctx context.Context, shared *policy.SharedContext, group targetGroup) []int {
	n := len(group.fallbacks)
	order := make([]int, 0, n)
	if p.suspendDuration <= 0 {
		for i := 0; i < n; i++ {
			order = append(order, i)
		}
		return order
	}
	var suspended []int
	for i := 0; i < n; i++ {
		if p.suspend.IsSuspended(ctx, suspendKey(shared, group.model, group.provider, i)) {
			suspended = append(suspended, i)
			continue
		}
		order = append(order, i)
	}
	return append(order, suspended...)
}

// suspendKey scopes suspend state to this specific API/operation, target group (model +
// provider — two targets sharing a model but disambiguated by provider must never share suspend
// state either), and fallback index — two different groups (or two different operations) using
// model-failover must never share suspend state.
func suspendKey(shared *policy.SharedContext, groupModel, groupProvider string, fallbackIndex int) string {
	if shared == nil {
		return fmt.Sprintf("model-failover:unknown:unknown:%s:%s:%d", groupModel, groupProvider, fallbackIndex)
	}
	return fmt.Sprintf("model-failover:%s:%s:%s:%s:%d", shared.APIId, shared.OperationPath, groupModel, groupProvider, fallbackIndex)
}

// ─── Suspend store ─────────────────────────────────────────────────────────────

// suspendStore tracks which (route, target group, fallback index) tuples recently failed.
// The in-memory implementation here is the ONLY implementation this policy has, permanently —
// no cross-replica (Redis-backed) sharing. The interface still earns its keep as a seam for
// tests.
type suspendStore interface {
	IsSuspended(ctx context.Context, key string) bool
	Suspend(ctx context.Context, key string, ttl time.Duration)
}

type memorySuspendStore struct {
	mu      sync.Mutex
	entries map[string]time.Time // key -> expiry
}

func newMemorySuspendStore() *memorySuspendStore {
	return &memorySuspendStore{entries: make(map[string]time.Time)}
}

func (s *memorySuspendStore) IsSuspended(_ context.Context, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.entries[key]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.entries, key)
		return false
	}
	return true
}

func (s *memorySuspendStore) Suspend(_ context.Context, key string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = time.Now().Add(ttl)
}
