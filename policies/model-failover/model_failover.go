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
// against an ordered fallback chain — one independently-selectable chain per target model,
// selected by matching the client's own request.body.model against a declared target.
//
// Mechanism (response-path retry — NOT Envoy aggregate-cluster/upstream-ext_proc): Envoy's
// upstream ext_proc phase is alpha and has been ruled out for GA use. Every attempt this
// policy originates itself — a target's own primary override or a fallback retry — is driven
// from a direct outbound call and, on success, returned via ImmediateResponse. This mirrors
// oauth2-generator's own self-retry pattern, generalized into an N-long chain.
//
// Cross-provider targets/fallbacks (declaring provider) never carry their own url/auth/
// template. A provider reference is resolved entirely by a SELF-REDIAL: this policy dials its
// OWN operation's externally-facing URL again (selfBaseURL + the original downstream path,
// gateway-controller-injected — see llm_transformer.go) with the providerHeaderName header set
// to the chosen provider id (dispatch.go). Because that's a genuinely fresh inbound request as
// far as Envoy is concerned, it re-runs the FULL policy chain from scratch:
//
//   - llm-header-router reads providerHeaderName and publishes SharedContext.Metadata
//     ["selected_provider"] — in the request-HEADER phase, not body phase. That distinction
//     matters: the provider's own conditional upstream-auth policy (a header-phase-only
//     "set-headers" instance) evaluates its ExecutionCondition during the SAME header-phase
//     pass, which completes and is sent back to Envoy before body-phase policies (this one
//     included) ever run — so a redirect signal this policy could only ever produce in body
//     phase (it has to see the client's "model" field first) would always be one phase too
//     late for that gate. Publishing via a real header sidesteps the ordering problem instead
//     of fighting it.
//   - The matching openai-to-* translator and the provider's own conditional upstream-auth
//     policy fire correctly as a result — full bidirectional body conversion and credential
//     injection, done for real by the already-shipped, general-purpose policies that handle
//     it for every other multi-provider proxy too. This policy never resolves or applies
//     either itself, and carries no per-vendor adapter of its own.
//
// upstreamDefinition references (same provider, a different backend of it — e.g. a backup
// region) are unrelated to any of this: a target's own override still uses an in-process
// UpstreamName redirect (no extra hop, no auth/template complexity since it's the same
// provider), and a fallback's own reference dials its resolved URL directly, reusing the
// original request's own credential unchanged.
//
// OnRequestBody's modelFailoverRedialHeader guard exists because a provider redial re-enters
// this SAME operation, which still has this policy attached: without the guard, the redialed
// request's own OnRequestBody pass would see the SAME unchanged client model and try to
// redirect it all over again, forever. The guard's only job is breaking that recursion — a
// client spoofing the header themselves just means failover doesn't apply to that one request,
// never a routing or auth bypass (see dispatch.go).
package modelfailover

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// defaultMaxResponseBytes bounds a dial's response body when no maxResponseBytes param is
// configured. Mirrors the network-hardening requirement that every outbound read be wrapped in
// a config-sourced ceiling (see go-network-service-hardening.md / file-access.md); 10MiB
// matches the precedent set by oauth2-generator's own self-retry response cap.
const defaultMaxResponseBytes = 10 << 20

// defaultDialTimeout is used for a dial when requestTimeout isn't configured.
const defaultDialTimeout = 10 * time.Second

// noProviderAvailableBody is returned when a target's own provider override, and every one of
// its own declared fallbacks, all fail — there is no "original" primary response to let through
// unchanged (that's the whole reason this target declared an override in the first place), so
// this is an honest, generic failure rather than a fabricated one.
const noProviderAvailableBody = `{"error":{"message":"all configured providers for this model are unavailable","type":"upstream_error"}}`

// fallbackTarget is one entry in a target group's own ordered fallback chain. provider and
// upstreamDefinition are mutually exclusive; at most one is ever set.
type fallbackTarget struct {
	model string // model name to inject into the request body for this attempt

	// provider is empty unless this fallback crosses providers. When set, it names a
	// provider id — resolved entirely via a self-redial with providerHeaderName set (see the
	// package doc and dispatch.go's tryProviderRedial); gateway-controller only validates
	// that this name is a real, declared provider, nothing more.
	provider string

	// upstreamDefinition is empty unless this fallback stays on the SAME provider but a
	// DIFFERENT backend of it (e.g. a backup region) — a plain upstreamDefinition name
	// declared on the same resource. resolvedUpstreamURL below is how this reference
	// actually reaches this policy; never carries a translator, since same provider means
	// same wire format by definition.
	upstreamDefinition string

	// resolvedUpstreamURL is populated ONLY when upstreamDefinition is set, and ONLY by
	// gateway-controller at registration time (see llm_transformer.go) — never supplied
	// directly by an operator. It's upstreamDefinition's own resolved backend URL; this
	// policy appends the operation's own relative path to it.
	resolvedUpstreamURL string
}

// crossesProvider reports whether this fallback dials a genuinely different backend than the
// operation's own default upstream — true for either provider or upstreamDefinition, false
// for the bare "reuse the primary" case.
func (fb fallbackTarget) crossesProvider() bool {
	return fb.provider != "" || fb.upstreamDefinition != ""
}

// targetGroup is one independently-selectable target: model is the client-requested value
// that selects this whole group, and fallbacks is that group's own ordered failover chain —
// entirely independent of every other group's chain (own suspend state). provider and
// upstreamDefinition are mutually exclusive; at most one is ever set.
type targetGroup struct {
	model string

	// provider is empty unless this target's primary attempt itself crosses providers (no
	// same-provider default makes sense for this model at all). Resolved via the same
	// self-redial mechanism as a fallback's own provider reference (see the package doc).
	provider string

	// upstreamDefinition is empty unless this target's primary attempt should go directly to
	// a specific same-provider backend (a plain upstreamDefinition name) rather than the
	// operation's own default upstream. Redirected via an in-process UpstreamName redirect —
	// same provider, so there's no auth/template complexity to route around.
	upstreamDefinition string

	fallbacks []fallbackTarget
}

// Policy holds the parsed, validated model-failover configuration consumed by OnRequestBody
// (a target's own provider/upstreamDefinition override) and OnResponseHeaders (the fallback
// retry loop after a normal primary failure).
type Policy struct {
	targets          []targetGroup
	targetByModel    map[string]int // client-requested model name -> index into targets
	statusCodes      map[int]struct{}
	requestTimeout   time.Duration // per-attempt dial timeout; 0 = use defaultDialTimeout
	suspendDuration  time.Duration // zero = suspend tracking disabled
	maxResponseBytes int64
	selfBaseURL      string // gateway-controller-injected; required only if any provider reference is configured
	suspend          suspendStore
	httpClient       retryHTTPClient
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	rawTargets, ok := params["targets"].([]interface{})
	if !ok || len(rawTargets) == 0 {
		return nil, fmt.Errorf("model-failover requires a non-empty 'targets' list")
	}

	targets := make([]targetGroup, 0, len(rawTargets))
	targetByModel := make(map[string]int, len(rawTargets))
	usesProvider := false
	for i, raw := range rawTargets {
		t, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("model-failover: targets[%d] is not an object", i)
		}
		model, _ := t["model"].(string)
		if model == "" {
			return nil, fmt.Errorf("model-failover: targets[%d].model is required", i)
		}
		if _, exists := targetByModel[model]; exists {
			return nil, fmt.Errorf("model-failover: targets[%d].model %q is declared more than once", i, model)
		}

		rawFallbacks, _ := t["fallbacks"].([]interface{})
		fallbacks := make([]fallbackTarget, 0, len(rawFallbacks))
		for j, rawFb := range rawFallbacks {
			fb, err := parseFallbackTarget(rawFb, i, j)
			if err != nil {
				return nil, err
			}
			if fb.provider != "" {
				usesProvider = true
			}
			fallbacks = append(fallbacks, fb)
		}

		provider := getStringParam(t, "provider")
		upstreamDefinition := getStringParam(t, "upstreamDefinition")
		if provider != "" && upstreamDefinition != "" {
			return nil, fmt.Errorf("model-failover: targets[%d] sets both provider and upstreamDefinition — mutually exclusive", i)
		}
		if provider != "" {
			usesProvider = true
		}
		if provider != "" || upstreamDefinition != "" {
			// Once the target's own primary attempt is redirected, there is no primary
			// response left for a bare "reuse the primary" fallback to reuse — require every
			// one of its own fallbacks to cross providers too, rather than silently failing
			// to resolve an upstream at dial time.
			for j, fb := range fallbacks {
				if !fb.crossesProvider() {
					return nil, fmt.Errorf("model-failover: targets[%d] redirects its own primary attempt (provider/upstreamDefinition set) — targets[%d].fallbacks[%d] must also set provider or upstreamDefinition; there is no primary attempt left to reuse", i, i, j)
				}
			}
		}

		targetByModel[model] = len(targets)
		targets = append(targets, targetGroup{
			model:              model,
			provider:           provider,
			upstreamDefinition: upstreamDefinition,
			fallbacks:          fallbacks,
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

	p := &Policy{
		targets:          targets,
		targetByModel:    targetByModel,
		statusCodes:      statusCodes,
		maxResponseBytes: defaultMaxResponseBytes,
		selfBaseURL:      getStringParam(params, "selfBaseURL"),
		httpClient:       newDefaultRetryHTTPClient(),
	}
	if usesProvider && p.selfBaseURL == "" {
		// gateway-controller injects selfBaseURL unconditionally at registration time (see
		// llm_transformer.go) whenever this policy is attached — reaching GetPolicy with a
		// provider reference but no selfBaseURL means that step never ran (e.g. a hand-built
		// params blob in a test, or a genuine registration-time regression) — fail closed
		// rather than silently produce a provider redial with nowhere to dial.
		return nil, fmt.Errorf("model-failover: a provider reference is configured but no selfBaseURL was provided — this must be injected by gateway-controller at registration time")
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

	// Suspend tracking is in-memory only, permanently — there is no Redis-backed option (a
	// cross-replica store was considered and deliberately dropped from scope).
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

	field := fmt.Sprintf("targets[%d].fallbacks[%d]", i, j)
	result := fallbackTarget{
		model:               model,
		provider:            getStringParam(fb, "provider"),
		upstreamDefinition:  getStringParam(fb, "upstreamDefinition"),
		resolvedUpstreamURL: getStringParam(fb, "resolvedUpstreamURL"),
	}

	if result.provider != "" && result.upstreamDefinition != "" {
		return fallbackTarget{}, fmt.Errorf("%s sets both provider and upstreamDefinition — mutually exclusive", field)
	}
	if result.upstreamDefinition != "" && result.resolvedUpstreamURL == "" {
		// gateway-controller resolves upstreamDefinition -> resolvedUpstreamURL at
		// registration time (see llm_transformer.go) for every fallback that declares one; an
		// operator never sets resolvedUpstreamURL directly. Reaching GetPolicy with a
		// reference set but nothing resolved means that registration-time step never ran
		// (e.g. upstreamDefinition on an LlmProxy, which has no upstreamDefinitions of its
		// own) — fail closed rather than silently produce a fallback with nowhere to dial.
		return fallbackTarget{}, fmt.Errorf("%s.upstreamDefinition %q has no resolved upstream — upstreamDefinition is only resolvable against a matching declaration on this resource", field, result.upstreamDefinition)
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

// Mode: needs the request body buffered — to decide a target-level provider/upstreamDefinition
// redirect in OnRequestBody, and so it survives into ResponseHeaderContext.RequestBody for
// replay in OnResponseHeaders. No request-HEADER phase hook: provider-selection publishing is
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

// groupByModel looks up a target group by the client-requested model name.
func (p *Policy) groupByModel(model string) (targetGroup, bool) {
	idx, ok := p.targetByModel[model]
	if !ok {
		return targetGroup{}, false
	}
	return p.targets[idx], true
}

// dialTimeout returns the configured per-attempt timeout, or defaultDialTimeout if unset.
func (p *Policy) dialTimeout() time.Duration {
	if p.requestTimeout > 0 {
		return p.requestTimeout
	}
	return defaultDialTimeout
}

// downstreamPath returns the original, pre-mutation client-facing request path (e.g.
// "/mf-poc-proxy/chat/completions") — used to build a provider redial's own target URL, so
// Envoy re-matches it against this SAME operation. Empty if unavailable.
func downstreamPath(d *policy.DownstreamContext) string {
	if d == nil || d.Request == nil {
		return ""
	}
	return d.Request.Path
}

// OnRequestBody redirects a target's PRIMARY attempt to its own declared provider or
// upstreamDefinition, if any — a target with neither (the common case) is left completely
// untouched: no mutation, exactly today's default-routing behavior.
//
// The modelFailoverRedialHeader guard is checked first: it's set only on a provider redial
// this policy originates itself (see dispatch.go), so seeing it here means this IS one of this
// policy's own redials re-entering the operation, not a genuine client request — pass it
// through untouched rather than trying to redirect it all over again (see the package doc).
func (p *Policy) OnRequestBody(ctx context.Context, rctx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if rctx.Headers != nil && rctx.Headers.Has(modelFailoverRedialHeader) {
		return policy.UpstreamRequestModifications{}
	}
	if rctx.Body == nil || !rctx.Body.Present {
		return policy.UpstreamRequestModifications{}
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(rctx.Body.Content, &decoded); err != nil {
		slog.WarnContext(ctx, "ModelFailover: request body is not valid JSON, failing open (no redirect)", "error", err)
		return policy.UpstreamRequestModifications{}
	}

	requestedModel, _ := decoded["model"].(string)
	group, matched := p.groupByModel(requestedModel)
	if !matched {
		return policy.UpstreamRequestModifications{}
	}

	switch {
	case group.provider != "":
		return p.redirectTargetProvider(ctx, rctx, group, decoded)

	case group.upstreamDefinition != "":
		// Same-provider redirect — plain in-process routing, no auth/template complexity.
		upstreamName := group.upstreamDefinition
		return policy.UpstreamRequestModifications{UpstreamName: &upstreamName}

	default:
		return policy.UpstreamRequestModifications{}
	}
}

// redirectTargetProvider handles a target whose own primary attempt crosses providers: try the
// declared provider via a self-redial, and if that fails, walk the target's own fallback chain
// (GetPolicy already requires every one of those to cross providers too — see the package
// doc). If nothing succeeds, there is no sensible default to fall through to (that's why this
// target declared an override in the first place), so this returns an honest, generic failure
// rather than fabricating or silently passing through an unrelated response.
func (p *Policy) redirectTargetProvider(ctx context.Context, rctx *policy.RequestContext, group targetGroup, decoded map[string]interface{}) policy.RequestAction {
	path := downstreamPath(rctx.Downstream)
	if resp, ok := p.tryProviderRedial(ctx, p.selfBaseURL, path, rctx.Method, rctx.Headers, group.provider, group.model, decoded); ok {
		return resp
	}

	order := p.orderedFallbackIndices(ctx, rctx.SharedContext, group)
	for _, idx := range order {
		fb := group.fallbacks[idx]
		// fb always crossesProvider() here — GetPolicy rejects a bare "reuse primary"
		// fallback under a target that itself redirects.
		resp, ok := p.tryFallbackEntry(ctx, p.selfBaseURL, path, rctx.Path, rctx.Method, rctx.Headers, nil, fb, decoded)
		if !ok {
			if p.suspendDuration > 0 {
				p.suspend.Suspend(ctx, suspendKey(rctx.SharedContext, group.model, idx), p.suspendDuration)
			}
			continue
		}
		return resp
	}

	return policy.ImmediateResponse{
		StatusCode: http.StatusBadGateway,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(noProviderAvailableBody),
	}
}

// OnResponseHeaders drives the fallback retry loop after a NORMAL primary attempt has already
// failed. On a response whose status matches statusCodes, it walks the matched target group's
// fallback chain — skipping any fallback currently suspended — making a direct outbound call
// per candidate until one succeeds (returned via ImmediateResponse) or the chain is exhausted
// (the original failing response passes through unchanged). A request whose model doesn't
// match any declared target, or whose status doesn't match statusCodes, is untouched.
func (p *Policy) OnResponseHeaders(ctx context.Context, rhctx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if _, failing := p.statusCodes[rhctx.ResponseStatus]; !failing {
		return policy.DownstreamResponseHeaderModifications{}
	}
	if rhctx.RequestBody == nil || !rhctx.RequestBody.Present {
		// Nothing to replay against a fallback without the original body.
		return policy.DownstreamResponseHeaderModifications{}
	}

	var originalBody map[string]interface{}
	if err := json.Unmarshal(rhctx.RequestBody.Content, &originalBody); err != nil || originalBody == nil {
		slog.WarnContext(ctx, "ModelFailover: request body is not a JSON object, cannot select a target", "error", err)
		return policy.DownstreamResponseHeaderModifications{}
	}

	requestedModel, _ := originalBody["model"].(string)
	group, matched := p.groupByModel(requestedModel)
	if !matched || len(group.fallbacks) == 0 {
		return policy.DownstreamResponseHeaderModifications{}
	}

	path := downstreamPath(rhctx.Downstream)
	order := p.orderedFallbackIndices(ctx, rhctx.SharedContext, group)
	for _, idx := range order {
		fb := group.fallbacks[idx]

		resp, ok := p.tryFallbackEntry(ctx, p.selfBaseURL, path, rhctx.RequestPath, rhctx.RequestMethod, rhctx.RequestHeaders, rhctx.Upstream, fb, originalBody)
		if !ok {
			if p.suspendDuration > 0 {
				p.suspend.Suspend(ctx, suspendKey(rhctx.SharedContext, group.model, idx), p.suspendDuration)
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
		if p.suspend.IsSuspended(ctx, suspendKey(shared, group.model, i)) {
			suspended = append(suspended, i)
			continue
		}
		order = append(order, i)
	}
	return append(order, suspended...)
}

// suspendKey scopes suspend state to this specific API/operation, target group, and fallback
// index — two different groups (or two different operations) using model-failover must never
// share suspend state.
func suspendKey(shared *policy.SharedContext, groupModel string, fallbackIndex int) string {
	if shared == nil {
		return fmt.Sprintf("model-failover:unknown:unknown:%s:%d", groupModel, fallbackIndex)
	}
	return fmt.Sprintf("model-failover:%s:%s:%s:%d", shared.APIId, shared.OperationPath, groupModel, fallbackIndex)
}

// ─── Suspend store ─────────────────────────────────────────────────────────────

// suspendStore tracks which (route, target group, fallback index) tuples recently failed.
// The in-memory implementation here is the ONLY implementation this policy has, permanently —
// cross-replica (Redis-backed) suspend sharing was considered and deliberately dropped from
// scope. The interface still earns its keep as a seam for tests.
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
