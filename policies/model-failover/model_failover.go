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
// upstream ext_proc phase is alpha and has been ruled out for GA use. Every fallback attempt
// is instead driven from OnResponseHeaders — a stable, GA downstream-phase hook with full
// access to the original request snapshot and SharedContext — by making a direct outbound
// call to the fallback target and, on success, returning that response via ImmediateResponse.
// This mirrors oauth2-generator's own self-retry pattern, generalized into an N-long chain.
//
// Cross-provider targets (a target/fallback declaring provider) never carry their own
// url/auth/template. Every credential and wire-format conversion is sourced from the SAME
// LlmProxy's already-configured additionalProviders entry, never re-typed here:
//
//   - A TARGET's own provider (the primary attempt for that target model) is handled by
//     OnRequestBody redirecting via UpstreamName to the additionalProviders-derived
//     UpstreamDefinition — a real, already-registered Envoy cluster, so this is a normal,
//     GA-safe request-phase routing decision, not the blocked upstream-attempt mechanism.
//     Setting SharedContext.Metadata["selected_provider"] alongside the redirect activates
//     the SAME conditional auth/transformer policies gateway-controller already auto-injects
//     for additionalProviders (see llm_transformer.go's proxyUpstreamAuthPolicy/
//     proxyTransformerPolicy) — full auth AND template-conversion reuse, zero duplicated
//     config, zero code here beyond the redirect itself.
//   - A FALLBACK's own provider (a post-failure retry) can't use that trick — a response-phase
//     retry can't set UpstreamName or re-enter the downstream chain. It instead dials the
//     provider's own resolved loopback URL directly (resolvedUpstreamURL, injected by
//     gateway-controller at registration time — see llm_transformer.go — never supplied by an
//     operator). That loopback dial reaches the target provider's own fully-registered route,
//     so its own auth applies itself with no credential handling here at all. Template
//     conversion is the one piece that ISN'T free for a fallback: the conditional transformer
//     policy is attached to the PROXY's own operation, which a raw response-phase dial never
//     re-enters — so this policy still applies its own adapter (see templates.go), keyed by
//     the SAME transformer-type string (resolvedTransformerType, e.g. "openai-to-anthropic-transformer")
//     the platform already uses, not an ad hoc vendor name.
//
// Consequence worth calling out explicitly: because there is no request-phase hook redirecting
// a FALLBACK's dispatch (only a target's own primary attempt gets that), this policy cannot
// skip a known-bad fallback ahead of time — suspend tracking below only ever deprioritizes a
// recently-failed fallback within the walk that's already happening, never the primary.
package modelfailover

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// selectedProviderMetadataKey must match exactly what gateway-controller's
// selectedProviderExecutionCondition (llm_transformer.go) compiles into every conditional
// auth/transformer policy's CEL condition: request.Metadata['selected_provider'] == '<name>'.
// Setting this key in SharedContext.Metadata is what activates those already-attached policy
// instances for a target-level provider redirect.
const selectedProviderMetadataKey = "selected_provider"

// defaultMaxResponseBytes bounds a fallback dial's response body when no maxResponseBytes
// param is configured. Mirrors the network-hardening requirement that every outbound read be
// wrapped in a config-sourced ceiling (see go-network-service-hardening.md / file-access.md);
// 10MiB matches the precedent set by oauth2-generator's own self-retry response cap.
const defaultMaxResponseBytes = 10 << 20

// defaultDialTimeout is used for a fallback dial when requestTimeout isn't configured.
const defaultDialTimeout = 10 * time.Second

// fallbackTarget is one entry in a target group's own ordered fallback chain. provider and
// upstreamDefinition are mutually exclusive; at most one is ever set.
type fallbackTarget struct {
	model string // model name to inject into the request body for this attempt

	// provider is empty unless this fallback crosses providers. When set, it names an
	// additionalProviders entry (id or `as` alias) on the SAME LlmProxy —
	// resolvedUpstreamURL/resolvedTransformerType below are how that reference actually
	// reaches this policy. Only resolvable on an LlmProxy.
	provider string

	// upstreamDefinition is empty unless this fallback stays on the SAME provider but a
	// DIFFERENT backend of it (e.g. a backup region) — a plain upstreamDefinition name
	// declared on the same LlmProvider/LlmProxy. Same resolution mechanism as provider
	// (resolvedUpstreamURL, gateway-controller-injected) but never carries a transformer:
	// same provider means same wire format, by definition. Only resolvable on an LlmProvider
	// (an LlmProxy has no native upstreamDefinitions of its own — see llm_transformer.go).
	upstreamDefinition string

	// resolvedUpstreamURL/resolvedTransformerType are populated ONLY when provider or
	// upstreamDefinition is set, and ONLY by gateway-controller at registration time (see
	// llm_transformer.go) — never supplied directly by an operator. resolvedUpstreamURL is
	// the target's own base URL (e.g. "http://127.0.0.1:9090/anthropic-provider/latest" for a
	// provider, or a plain upstream URL for an upstreamDefinition); this policy appends the
	// operation's own relative path to it. resolvedTransformerType is only ever set for a
	// provider (an upstreamDefinition is same-template by definition — no conversion needed).
	resolvedUpstreamURL     string
	resolvedTransformerType string

	// resolvedAuthHeader/resolvedAuthValue carry a provider's own additionalProviders[].auth
	// credential (api-key type only), gateway-controller-injected exactly like
	// resolvedUpstreamURL/resolvedTransformerType above — never supplied directly by an
	// operator. Only ever set for provider (an upstreamDefinition fallback reuses the original
	// request's own credential unchanged, since same provider means same auth — see
	// dispatch.go). Both empty means no api-key auth is declared for this provider (e.g. "none"
	// or "other", the latter handled entirely by the operator's own attached policies).
	resolvedAuthHeader string
	resolvedAuthValue  string
}

// crossesProvider reports whether this fallback dials a genuinely different backend than the
// operation's own default upstream — true for either provider or upstreamDefinition, false
// for the bare "reuse the primary" case. Used to decide whether the original request's
// credential should be stripped before replay (see dispatch.go).
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
	// same-provider default makes sense for this model at all). When set, it names an
	// additionalProviders entry — OnRequestBody redirects the PRIMARY attempt itself via
	// UpstreamName plus SharedContext.Metadata["selected_provider"] (see the package doc).
	// Only resolvable on an LlmProxy.
	provider string

	// upstreamDefinition is empty unless this target's primary attempt should go directly to
	// a specific same-provider backend (a plain upstreamDefinition name) rather than the
	// operation's own default upstream. Redirected via UpstreamName exactly like provider,
	// but with no metadata write — there's no conditional auth/transformer policy to
	// activate for a same-provider target. Only resolvable on an LlmProvider.
	upstreamDefinition string

	fallbacks []fallbackTarget
}

// Policy holds the parsed, validated model-failover configuration consumed by OnRequestBody
// (target-level provider redirect only) and OnResponseHeaders (the fallback retry loop).
type Policy struct {
	targets          []targetGroup
	targetByModel    map[string]int // client-requested model name -> index into targets
	statusCodes      map[int]struct{}
	requestTimeout   time.Duration // per-fallback-dial timeout; 0 = use defaultDialTimeout
	suspendDuration  time.Duration // zero = suspend tracking disabled
	maxResponseBytes int64
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
			fallbacks = append(fallbacks, fb)
		}

		provider := getStringParam(t, "provider")
		upstreamDefinition := getStringParam(t, "upstreamDefinition")
		if provider != "" && upstreamDefinition != "" {
			return nil, fmt.Errorf("model-failover: targets[%d] sets both provider and upstreamDefinition — mutually exclusive", i)
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
		httpClient:       newDefaultRetryHTTPClient(),
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
		model:                   model,
		provider:                getStringParam(fb, "provider"),
		upstreamDefinition:      getStringParam(fb, "upstreamDefinition"),
		resolvedUpstreamURL:     getStringParam(fb, "resolvedUpstreamURL"),
		resolvedTransformerType: getStringParam(fb, "resolvedTransformerType"),
		resolvedAuthHeader:      getStringParam(fb, "resolvedAuthHeader"),
		resolvedAuthValue:       getStringParam(fb, "resolvedAuthValue"),
	}

	if result.provider != "" && result.upstreamDefinition != "" {
		return fallbackTarget{}, fmt.Errorf("%s sets both provider and upstreamDefinition — mutually exclusive", field)
	}
	if (result.provider != "" || result.upstreamDefinition != "") && result.resolvedUpstreamURL == "" {
		// gateway-controller resolves provider/upstreamDefinition -> resolvedUpstreamURL at
		// registration time (see llm_transformer.go) for every fallback that declares one; an
		// operator never sets resolvedUpstreamURL directly. Reaching GetPolicy with a
		// reference set but nothing resolved means that registration-time step never ran
		// (e.g. provider on an LlmProvider, or upstreamDefinition on an LlmProxy — neither has
		// anything to resolve the reference against) — fail closed rather than silently
		// produce a fallback with nowhere to dial.
		name, kind := result.provider, "provider"
		if result.upstreamDefinition != "" {
			name, kind = result.upstreamDefinition, "upstreamDefinition"
		}
		return fallbackTarget{}, fmt.Errorf("%s.%s %q has no resolved upstream — %s is only resolvable against a matching declaration on this resource", field, kind, name, kind)
	}
	if result.resolvedTransformerType != "" {
		if _, ok := templateAdapters[result.resolvedTransformerType]; !ok {
			return fallbackTarget{}, fmt.Errorf("%s: transformer %q is not supported by this policy", field, result.resolvedTransformerType)
		}
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

// Mode: needs the request body buffered — both to decide a target-level provider redirect in
// OnRequestBody, and so it survives into ResponseHeaderContext.RequestBody for replay in
// OnResponseHeaders. Never needs the response body — a failing response's body is discarded,
// an ImmediateResponse replaces it before the kernel forwards a single byte downstream, so
// this stays safe even when the primary's response would otherwise have been streamed.
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

// OnRequestBody redirects a target's PRIMARY attempt to its own declared provider, if any —
// the request-phase half of provider reuse (see the package doc). A target with no provider
// (the common case) is left completely untouched: no mutation, no metadata write, exactly
// today's default-routing behavior.
func (p *Policy) OnRequestBody(ctx context.Context, rctx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
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
		if rctx.SharedContext != nil {
			if rctx.SharedContext.Metadata == nil {
				rctx.SharedContext.Metadata = make(map[string]interface{})
			}
			// Activates gateway-controller's already-attached conditional auth/transformer
			// policies for this provider (see llm_transformer.go's
			// selectedProviderExecutionCondition) — this policy never resolves auth or
			// applies a transform itself for a target-level redirect.
			rctx.SharedContext.Metadata[selectedProviderMetadataKey] = group.provider
		}
		upstreamName := group.provider
		return policy.UpstreamRequestModifications{UpstreamName: &upstreamName}

	case group.upstreamDefinition != "":
		// Same-provider redirect — no conditional policy to activate, so no metadata write.
		upstreamName := group.upstreamDefinition
		return policy.UpstreamRequestModifications{UpstreamName: &upstreamName}

	default:
		return policy.UpstreamRequestModifications{}
	}
}

// OnResponseHeaders drives the fallback retry loop. On a response whose status matches
// statusCodes, it walks the matched target group's fallback chain — skipping any fallback
// currently suspended — making a direct outbound call per candidate until one succeeds
// (returned via ImmediateResponse) or the chain is exhausted (the original failing response
// passes through unchanged). A request whose model doesn't match any declared target, or
// whose status doesn't match statusCodes, is untouched.
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

	order := p.orderedFallbackIndices(ctx, rhctx.SharedContext, group)
	for _, idx := range order {
		fb := group.fallbacks[idx]

		resp, ok := p.tryFallback(ctx, rhctx, group, fb, originalBody)
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
// (never dropped outright), just deprioritized. Suspend tracking only ever applies to
// fallbacks, never the primary: see the package doc for why a fallback (unlike a target's own
// provider) can't be redirected ahead of time under this mechanism.
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
