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
// selected by matching the client's own requested model against a declared target. The
// requested model is read from (and rewritten at) the JSONPath the API's own LlmProvider
// template declares via requestModel (see Policy.modelIdentifier), not a hardcoded "model"
// key — only a payload-located model identity is supported today (see GetPolicy). A request
// for a model that isn't declared passes through completely untouched (no body mutation, no
// redirect); if that then fails, no failover applies — this policy only ever engages for
// models it explicitly knows about.
package modelfailover

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	sdkutils "github.com/wso2/api-platform/sdk/core/utils"
)

// fallbackTarget is one fallback entry within a target group's own chain. upstreamDefinition
// == "" means the API's own main upstream (the same backend used with no model-failover
// configured at all) — most APIs have exactly one upstream, so most fallbacks need nothing
// here.
type fallbackTarget struct {
	model              string
	upstreamDefinition string
}

// targetGroup is one independently-selectable target: model is the client-requested value
// that selects this whole group, and fallbacks is that group's own ordered failover chain —
// entirely independent of every other group's chain (own suspend state, own starting point).
// A group with zero fallbacks is legal: it's just "route this one model name, no failover."
// upstreamDefinition == "" means the API's own main upstream, same as fallbackTarget above.
type targetGroup struct {
	model              string
	upstreamDefinition string
	fallbacks          []fallbackTarget
}

// modelAt returns the model name and upstreamDefinition for index i within this group:
// i==0 is the group's own primary, i in [1, len(fallbacks)] is fallbacks[i-1].
func (g targetGroup) modelAt(i int) (model, upstreamDefinition string, ok bool) {
	if i == 0 {
		return g.model, g.upstreamDefinition, true
	}
	idx := i - 1
	if idx < 0 || idx >= len(g.fallbacks) {
		return "", "", false
	}
	return g.fallbacks[idx].model, g.fallbacks[idx].upstreamDefinition, true
}

// Policy holds the parsed, validated model-failover configuration consumed by the
// request/response processing hooks below.
type Policy struct {
	routeName       string
	targets         []targetGroup
	targetByModel   map[string]int // client-requested model name -> index into targets
	statusCodes     map[int]struct{}
	requestTimeout  time.Duration
	suspendDuration time.Duration // zero = suspend tracking disabled
	suspend         suspendStore

	// requestModelIdentifier is the JSONPath (per the LlmProvider's own template, see
	// modelIdentifier's doc comment) at which the client's requested/resolved model lives
	// in the request payload. Left "" when GetPolicy wasn't given a requestModel param at
	// all (e.g. a Policy built directly by a test) - modelIdentifier() is what applies the
	// "$.model" default in that case, not this field directly.
	requestModelIdentifier string
}

// modelIdentifier returns the JSONPath used to read/write the model name in the request
// payload: the LlmProvider template's own declared requestModel.identifier when GetPolicy
// was given one (gateway-controller auto-injects requestModel: {location, identifier} into
// every LLM-attached policy's params - see buildTemplateParams/mergeParams in
// llm_transformer.go), or "$.model" otherwise - the same top-level field every payload-based
// template shipped today happens to use, so this default matches what this policy hardcoded
// before it read the template at all. Hardcoding "model" as a flat map key was wrong even for
// the payload-only case: a template is free to declare a NESTED payload path, and this policy
// must follow it rather than assuming top-level placement.
func (p *Policy) modelIdentifier() string {
	if p.requestModelIdentifier != "" {
		return p.requestModelIdentifier
	}
	return "$.model"
}

// extractModel reads the model identity out of decoded at this policy's configured
// JSONPath (see modelIdentifier), returning "" on any miss (wrong type, path not present) -
// the same fail-open shape the two previous callers' `decoded["model"].(string)` type
// assertions already had (a failed assertion silently yields "").
func (p *Policy) extractModel(decoded map[string]interface{}) string {
	val, err := sdkutils.ExtractValueFromJsonpath(decoded, p.modelIdentifier())
	if err != nil {
		return ""
	}
	s, _ := val.(string)
	return s
}

// setModel writes model into decoded at this policy's configured JSONPath (see
// modelIdentifier). Returns an error rather than panicking/silently no-op'ing when the path's
// intermediate segments don't exist in decoded - callers must fail open on that (log +
// leave the request unmutated), never let a mutation failure become a new failure mode of
// its own (the fail-open convention this whole file already follows for a non-JSON or null
// body).
func (p *Policy) setModel(decoded map[string]interface{}, model string) error {
	return sdkutils.SetValueAtJSONPath(decoded, p.modelIdentifier(), model)
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
		// upstreamDefinition is optional: absent/empty means the API's own main upstream.
		upstreamDef, _ := t["upstreamDefinition"].(string)
		if _, exists := targetByModel[model]; exists {
			return nil, fmt.Errorf("model-failover: targets[%d].model %q is declared more than once", i, model)
		}

		rawFallbacks, _ := t["fallbacks"].([]interface{})
		fallbacks := make([]fallbackTarget, 0, len(rawFallbacks))
		for j, rawFb := range rawFallbacks {
			fb, ok := rawFb.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("model-failover: targets[%d].fallbacks[%d] is not an object", i, j)
			}
			fbModel, _ := fb["model"].(string)
			if fbModel == "" {
				return nil, fmt.Errorf("model-failover: targets[%d].fallbacks[%d].model is required", i, j)
			}
			// upstreamDefinition is optional here too: absent/empty means main upstream.
			fbUpstreamDef, _ := fb["upstreamDefinition"].(string)
			fallbacks = append(fallbacks, fallbackTarget{model: fbModel, upstreamDefinition: fbUpstreamDef})
		}

		targetByModel[model] = len(targets)
		targets = append(targets, targetGroup{model: model, upstreamDefinition: upstreamDef, fallbacks: fallbacks})
	}

	rawCodes, ok := params["statusCodes"].([]interface{})
	if !ok || len(rawCodes) == 0 {
		return nil, fmt.Errorf("model-failover requires a non-empty 'statusCodes' list")
	}
	statusCodes := make(map[int]struct{}, len(rawCodes))
	for _, raw := range rawCodes {
		code, ok := raw.(int)
		if !ok {
			if f, ok := raw.(float64); ok {
				code = int(f)
			} else {
				return nil, fmt.Errorf("model-failover: statusCodes entries must be integers")
			}
		}
		statusCodes[code] = struct{}{}
	}

	p := &Policy{routeName: metadata.RouteName, targets: targets, targetByModel: targetByModel, statusCodes: statusCodes}

	// requestModel: {location, identifier} is auto-injected by gateway-controller into every
	// LLM-attached policy's params, sourced from the API's own LlmProvider template (see
	// buildTemplateParams/mergeParams in llm_transformer.go) - absent here only for params
	// built by hand (a test, or a config path that predates this policy reading it at all),
	// in which case modelIdentifier()'s own "$.model" default applies and nothing below runs.
	if raw, ok := params["requestModel"]; ok {
		rm, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("model-failover: requestModel must be an object")
		}
		// This policy's core mechanism only supports a payload-located model identity:
		// OnRequestBody rewrites the request BODY, and OnUpstreamAttemptRequest's reverse
		// lookup (see that method's own doc comment) recovers which group was selected by
		// reading the replayed baseline BODY - neither has anywhere to read/write a
		// header/queryParam/pathParam-located model (e.g. AWS Bedrock's and Gemini's own
		// templates, which put the model in the URL instead of the JSON body). Rejecting
		// outright here is deliberate: silently matching/rewriting nothing against such a
		// template would be a much worse failure mode than refusing to register at all.
		if location, _ := rm["location"].(string); location != "" && location != "payload" {
			return nil, fmt.Errorf("model-failover: this LlmProvider's template declares requestModel.location %q, but model-failover only supports a payload-located model identity today (the model name must be a JSON field in the request body) - a path/header/query-param-based model identity is not yet supported", location)
		}
		if identifier, _ := rm["identifier"].(string); identifier != "" {
			p.requestModelIdentifier = identifier
		}
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

	// Suspend tracking is in-memory only, permanently — there is no
	// Redis-backed option (a cross-replica store was considered and
	// deliberately dropped from scope).
	p.suspend = newMemorySuspendStore()

	return p, nil
}

// Mode: needs the request body buffered (OnRequestBody) to read the client's requested
// model, pick a target group, rewrite "model," and decide on a suspend-driven UpstreamName
// redirect; needs response headers (OnResponseHeaders) to read the final
// x-envoy-attempt-count and record suspend state. Never needs response body or request
// headers alone. Mirrors oauth2-generator's own Mode() (oauth2_generator.go:641), which
// returns the same ProcessingMode struct shape with different phase selections for its own
// needs.
func (p *Policy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// getStringParam safely extracts a string parameter, returning "" if absent
// or the wrong type. Leading/trailing whitespace is trimmed: values pasted
// from config files or secret stores frequently carry a stray trailing
// newline or space, which is invisible in logs but can silently corrupt a
// downstream comparison (e.g. time.ParseDuration on requestTimeout/
// suspendDuration). Copied verbatim from oauth2-generator's
// oauth2_generator.go:659.
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return strings.TrimSpace(str)
		}
	}
	return ""
}

// suspendStore tracks which (route, target group, index-within-group) tuples recently
// failed. The in-memory implementation here is the ONLY implementation this policy has,
// permanently — cross-replica (Redis-backed) suspend sharing was considered and deliberately
// dropped from scope. The interface still earns its keep as a seam between "the policy's
// suspend logic" and "how suspend state is stored," even with a single implementation.
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

// suspendKey scopes suspend state to this specific route/operation, target group, and index
// within that group — two different groups (or two different operations) using
// model-failover must never share suspend state, and suspending index 0 of one group must
// never affect index 0 of another. Guards a nil shared context (should not happen with the
// current kernel wiring, but every other hook in this file fails open on unexpected input,
// and a nil-pointer panic here would be the one exception).
func suspendKey(shared *policy.SharedContext, groupModel string, indexWithinGroup int) string {
	if shared == nil {
		return fmt.Sprintf("model-failover:unknown:unknown:%s:%d", groupModel, indexWithinGroup)
	}
	return fmt.Sprintf("model-failover:%s:%s:%s:%d", shared.APIId, shared.OperationPath, groupModel, indexWithinGroup)
}

// groupByModel looks up a target group by its own dispatch model name — the SAME lookup
// OnRequestBody uses to select a group in the first place, reused by the upstream-attempt
// and response-header phases (which only know the group by the model name stashed in
// SharedContext.Metadata, not by index).
func (p *Policy) groupByModel(model string) (targetGroup, bool) {
	idx, ok := p.targetByModel[model]
	if !ok {
		return targetGroup{}, false
	}
	return p.targets[idx], true
}

// firstAvailableIndexInGroup walks group's own chain (itself, then its fallbacks, in order)
// and returns the first index whose suspend state (if suspendDuration is configured at all)
// isn't currently active. When suspendDuration is zero (disabled — see GetPolicy), or when
// every index is currently suspended (nothing better to do), it returns index 0
// unconditionally — always trying the group's own primary is strictly better than refusing
// to route at all.
func (p *Policy) firstAvailableIndexInGroup(ctx context.Context, shared *policy.SharedContext, group targetGroup) int {
	if p.suspendDuration == 0 {
		return 0
	}
	for i := 0; i <= len(group.fallbacks); i++ {
		if !p.suspend.IsSuspended(ctx, suspendKey(shared, group.model, i)) {
			return i
		}
	}
	return 0
}

// metaGroupModelKey/metaStartIndexKey stash, in policy.SharedContext.Metadata (which
// persists from the request phase through the response phase — see the SDK's own doc
// comment on that field), which target group OnRequestBody selected and which index within
// it the request actually started at. This is read back ONLY by OnResponseHeaders — the
// upstream-attempt phase runs in a genuinely separate ext_proc server that never receives
// SharedContext at all (see OnUpstreamAttemptRequest's own doc comment for how that
// hook recovers the group instead). Without this, OnResponseHeaders would have no way to
// tell "this request started at fallback 2 because 0 and 1 were suspended" apart from "this
// request started at the group's own primary and walked the aggregate cluster's priority
// chain normally" — collapsing that distinction would misattribute which target actually
// failed.
const (
	metaGroupModelKey = "model-failover:group-model"
	metaStartIndexKey = "model-failover:start-index"
)

// OnRequestBody runs once per client request, before anything is sent. It is the ONLY point
// that selects a target group (by matching the client's own requested model, read via
// modelIdentifier, against a declared target) and can redirect ahead of time to a non-primary
// index within that group
// (the upstream-attempt phase can only react to an index Envoy already committed to dialing
// for that retry, and only within the group's own aggregate cluster). A model that doesn't
// match any declared target is sent completely as-is — no mutation, no redirect — falling
// through to the route's plain default (the API's main upstream); if that then fails, no
// failover applies, by design.
func (p *Policy) OnRequestBody(ctx context.Context, rctx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if rctx.Body == nil || !rctx.Body.Present {
		return policy.UpstreamRequestModifications{}
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(rctx.Body.Content, &decoded); err != nil {
		slog.WarnContext(ctx, "ModelFailover: request body is not valid JSON, failing open (no mutation)", "error", err)
		return policy.UpstreamRequestModifications{}
	}
	if decoded == nil {
		// encoding/json decodes the JSON literal "null" into a nil map with no error -
		// indistinguishable from a successful decode by err alone. Writing into a nil map
		// panics; a request body of exactly "null" is valid JSON any client can send, so
		// this must fail open, not crash the worker handling this stream.
		decoded = make(map[string]interface{})
	}

	requestedModel := p.extractModel(decoded)
	group, matched := p.groupByModel(requestedModel)
	if !matched {
		return policy.UpstreamRequestModifications{}
	}

	idx := p.firstAvailableIndexInGroup(ctx, rctx.SharedContext, group)
	resolvedModel, resolvedUpstreamDef, ok := group.modelAt(idx)
	if !ok {
		// Defensive only: firstAvailableIndexInGroup always returns an index in range for
		// this group. Never trust that blindly — fail open to the group's own primary.
		resolvedModel, resolvedUpstreamDef, idx = group.model, group.upstreamDefinition, 0
	}

	if err := p.setModel(decoded, resolvedModel); err != nil {
		slog.WarnContext(ctx, "ModelFailover: failed to set model in request body at configured path, failing open (no mutation)", "path", p.modelIdentifier(), "error", err)
		return policy.UpstreamRequestModifications{}
	}
	mutated, err := json.Marshal(decoded)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: failed to re-marshal request body, failing open", "error", err)
		return policy.UpstreamRequestModifications{}
	}

	if rctx.SharedContext != nil {
		if rctx.SharedContext.Metadata == nil {
			rctx.SharedContext.Metadata = make(map[string]interface{})
		}
		rctx.SharedContext.Metadata[metaGroupModelKey] = group.model
		rctx.SharedContext.Metadata[metaStartIndexKey] = idx
	}

	mods := policy.UpstreamRequestModifications{Body: mutated}
	if idx == 0 && len(group.fallbacks) > 0 {
		// Primary attempt of a group THAT HAS FALLBACKS: route through this group's own
		// aggregate cluster (built by gateway-controller specifically for this group) for
		// native retry_priority failover across the group's own chain — reusing the SAME
		// UpstreamName mechanism a real upstreamDefinition uses, just pointed at the
		// reserved logical name gateway-controller registers that aggregate cluster under.
		//
		// A zero-fallback group never gets this treatment: gateway-controller's translator
		// only builds an aggregate cluster when len(target.Fallbacks) > 0 (nothing to
		// fail over to otherwise), so routing a zero-fallback group's idx==0 through
		// modelFailoverGroupUpstreamName would point UpstreamName at a cluster that was
		// never created — confirmed live as a 503 (no such cluster) before this check was
		// added. Fall through to the direct-upstream branch below instead.
		name := policy.RetrySourceUpstreamName(p.routeName, group.model)
		mods.UpstreamName = &name
	} else if resolvedUpstreamDef != "" {
		// Either a skip-ahead within the group (idx > 0 — redirect DIRECTLY to that specific
		// fallback's own upstream, bypassing the aggregate entirely, since Envoy has no way
		// to "start" an aggregate cluster's priority walk partway through) or a zero-fallback
		// group's only attempt (idx == 0, no aggregate cluster exists to route through).
		// Both cases resolve to the same thing: dial resolvedUpstreamDef directly.
		name := resolvedUpstreamDef
		mods.UpstreamName = &name
	}
	// resolvedUpstreamDef == "" means "this API's own main upstream" — the same backend used
	// with no model-failover at all. Leave UpstreamName unset entirely rather than trying to
	// resolve a cluster name for it: main is NOT registered under the
	// UpstreamDefinitionClusterPrefix scheme resolveUpstreamRedirect requires (only named
	// upstreamDefinitions and this policy's own aggregate clusters are), so setting
	// UpstreamName="main" or any other literal would resolve to a cluster that doesn't exist,
	// or worse, collide with an operator-declared upstreamDefinition actually named "main".
	// Leaving it unset reuses the kernel's own existing default-upstream-cluster mechanism
	// (UpstreamExternalProcessorServer's caller falls back to the route's configured default
	// cluster whenever no policy sets UpstreamName) — the exact same path a route with no
	// model-failover policy at all already relies on, so main resolves correctly with zero
	// new cluster-registration machinery needed on either side.
	return mods
}

// OnUpstreamAttemptRequest implements policy.UpstreamAttemptPolicy. This only ever
// fires for a request routed through a target group's own aggregate cluster (the idx==0,
// no-skip-ahead case in OnRequestBody) — a skip-ahead redirect bypasses the aggregate
// entirely, so its single attempt never reaches this hook, and OnRequestBody's own rewrite
// already set the correct body for it.
//
// It CANNOT use SharedContext to recover which group was selected: the kernel's
// UpstreamExternalProcessorServer (gateway-runtime/policy-engine/internal/kernel/
// upstream_extproc.go) is a genuinely separate ext_proc server/stream from the downstream
// one OnRequestBody and OnResponseHeaders run in, and never populates UpstreamAttemptContext
// SharedContext at all — confirmed live (a real e2e run silently never rewrote a fallback
// attempt's body until this was fixed) and by reading that server's own Process()
// implementation, which constructs a bare UpstreamAttemptContext{AttemptCount, Body} with no
// shared-metadata bridge. Instead, this uses actx.Body's own BASELINE "model" value as the
// group's identity: per the SDK's own doc on UpstreamAttemptContext.Body, Envoy replays the
// SAME pre-attempt-1 baseline body on every attempt, never carrying forward a previous
// attempt's mutation — so for the idx==0 path (the only path that ever reaches this hook),
// that baseline value is always exactly group.model (OnRequestBody set it to
// group.modelAt(0), i.e. group.model, before the first dial), giving a reliable reverse
// lookup with no extra plumbing needed. AttemptCount N then corresponds directly to
// group.modelAt(N-1) (verified sufficient in the design spec: the translator builds each
// group's own aggregate cluster's member list in this exact order). Fails open (nil Body, no
// mutation) if the baseline model doesn't match any known group, or AttemptCount is out of
// range, or actx.Body is unavailable — this must only ever help a retry succeed, never add a
// new failure mode.
func (p *Policy) OnUpstreamAttemptRequest(ctx context.Context, actx *policy.UpstreamAttemptContext) policy.UpstreamAttemptAction {
	if actx.Body == nil || !actx.Body.Present {
		return policy.UpstreamAttemptRequestModifications{}
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(actx.Body.Content, &decoded); err != nil {
		slog.WarnContext(ctx, "ModelFailover: upstream-attempt body is not valid JSON, failing open", "attempt", actx.AttemptCount, "error", err)
		return policy.UpstreamAttemptRequestModifications{}
	}
	if decoded == nil {
		decoded = make(map[string]interface{})
	}
	baselineModel := p.extractModel(decoded)
	group, ok := p.groupByModel(baselineModel)
	if !ok {
		return policy.UpstreamAttemptRequestModifications{}
	}
	resolvedModel, _, ok := group.modelAt(actx.AttemptCount - 1)
	if !ok {
		return policy.UpstreamAttemptRequestModifications{}
	}

	if err := p.setModel(decoded, resolvedModel); err != nil {
		slog.WarnContext(ctx, "ModelFailover: failed to set model in upstream-attempt body at configured path, failing open", "attempt", actx.AttemptCount, "path", p.modelIdentifier(), "error", err)
		return policy.UpstreamAttemptRequestModifications{}
	}
	mutated, err := json.Marshal(decoded)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: failed to re-marshal upstream-attempt body, failing open", "attempt", actx.AttemptCount, "error", err)
		return policy.UpstreamAttemptRequestModifications{}
	}

	return policy.UpstreamAttemptRequestModifications{Body: mutated}
}

// OnResponseHeaders infers which index within the selected group failed this request from
// the FINAL response's x-envoy-attempt-count, in one of two shapes depending on whether
// OnRequestBody redirected via UpstreamName (see metaStartIndexKey):
//
//   - No redirect (started at index 0, the group's own primary): the request walked the
//     group's own aggregate cluster priority chain sequentially, so a final count of N means
//     indices [0, N-2] all failed in order (each had to fail to trigger the next retry).
//   - Redirected to a non-zero start index: UpstreamName sent EVERY attempt this request
//     made straight at that one fallback's own single upstream cluster (bypassing the
//     aggregate/priority chain entirely — see OnRequestBody), so a final count > 1 means
//     only THAT index failed, possibly after one native retry against itself — never a
//     sequential range starting at 0. Treating it as a range would both re-suspend an
//     unrelated (likely already-suspended) index and fail to record the one that actually
//     just failed again.
//
// A missing/unparseable header is treated as 1 (nothing failed), matching the same
// fail-toward-"first attempt" convention as the upstream-attempt phase. A no-op entirely
// when suspendDuration is 0 (suspend tracking disabled), or when no group was selected for
// this request at all (unmatched client model, passthrough — nothing to attribute a failure
// to).
func (p *Policy) OnResponseHeaders(ctx context.Context, rhctx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if p.suspendDuration == 0 || rhctx.SharedContext == nil {
		return policy.DownstreamResponseHeaderModifications{}
	}
	groupModel, matched := rhctx.SharedContext.Metadata[metaGroupModelKey].(string)
	if !matched {
		return policy.DownstreamResponseHeaderModifications{}
	}
	group, ok := p.groupByModel(groupModel)
	if !ok {
		return policy.DownstreamResponseHeaderModifications{}
	}
	startIdx, _ := rhctx.SharedContext.Metadata[metaStartIndexKey].(int)

	finalAttemptCount := 1
	if vals := rhctx.ResponseHeaders.Get("x-envoy-attempt-count"); len(vals) > 0 {
		if n, err := strconv.Atoi(vals[0]); err == nil && n > 0 {
			finalAttemptCount = n
		}
	}

	if startIdx == 0 {
		for i := 0; i < finalAttemptCount-1 && i <= len(group.fallbacks); i++ {
			p.suspend.Suspend(ctx, suspendKey(rhctx.SharedContext, group.model, i), p.suspendDuration)
		}
	} else if finalAttemptCount > 1 {
		p.suspend.Suspend(ctx, suspendKey(rhctx.SharedContext, group.model, startIdx), p.suspendDuration)
	}

	return policy.DownstreamResponseHeaderModifications{}
}
