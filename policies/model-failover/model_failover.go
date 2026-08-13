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

// Package modelfailover provides a policy that transparently retries a
// failed LLM request against an ordered list of fallback model+endpoint
// targets declared as upstreamDefinitions on the same API.
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

// modelTarget is one entry in the ordered fallback chain: the model name to
// inject into the request body for this attempt, and the upstreamDefinition
// (declared on the same API/LlmProvider spec) to route that attempt to.
type modelTarget struct {
	name               string
	upstreamDefinition string
}

// Policy holds the parsed, validated model-failover configuration consumed
// by the request/response processing hooks added in later tasks.
type Policy struct {
	models          []modelTarget
	statusCodes     map[int]struct{}
	requestTimeout  time.Duration
	suspendDuration time.Duration // zero = suspend tracking disabled
	cacheStrategy   string
	suspend         suspendStore
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	rawModels, ok := params["models"].([]interface{})
	if !ok || len(rawModels) < 2 {
		return nil, fmt.Errorf("model-failover requires at least 2 entries in 'models', got %d", len(rawModels))
	}
	models := make([]modelTarget, 0, len(rawModels))
	for i, raw := range rawModels {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("model-failover: models[%d] is not an object", i)
		}
		name, _ := m["name"].(string)
		def, _ := m["upstreamDefinition"].(string)
		if name == "" || def == "" {
			return nil, fmt.Errorf("model-failover: models[%d] requires both name and upstreamDefinition", i)
		}
		models = append(models, modelTarget{name: name, upstreamDefinition: def})
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

	p := &Policy{models: models, statusCodes: statusCodes, cacheStrategy: "memory"}

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
	if cache, ok := params["cache"].(map[string]interface{}); ok {
		if strategy := getStringParam(cache, "strategy"); strategy != "" {
			p.cacheStrategy = strategy
		}
	}

	// In-memory only for now — a Redis-backed suspendStore (for cross-replica
	// suspend sharing, keyed off p.cacheStrategy == "redis") is added in Task
	// 10, following oauth2-generator/token_cache.go's cache pattern.
	p.suspend = newMemorySuspendStore()

	return p, nil
}

// Mode: needs the request body buffered (OnRequestBody, Task 8) to rewrite
// "model" and decide on a suspend-driven UpstreamName redirect; needs
// response headers (OnResponseHeaders, Task 10) to read the final
// x-envoy-attempt-count and record suspend state. Never needs response body
// or request headers alone. Mirrors oauth2-generator's own Mode()
// (oauth2_generator.go:641), which returns the same ProcessingMode struct
// shape with different phase selections for its own needs.
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

// suspendStore tracks which (route, target-index) pairs recently failed.
// The in-memory implementation here is intentionally the ONLY implementation
// this task adds — a Redis-backed one (for cross-replica suspend sharing) is
// added in Task 10, following oauth2-generator/token_cache.go's cache
// pattern; this interface is what makes that swap possible without touching
// OnRequestBody/OnResponseHeaders again.
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

// suspendKey scopes suspend state to this specific route/operation and
// target index — two different operations using model-failover must never
// share suspend state, and suspending target 0 must never affect target 1's
// own independent state.
func suspendKey(shared *policy.SharedContext, targetIndex int) string {
	return fmt.Sprintf("model-failover:%s:%s:%d", shared.APIId, shared.OperationPath, targetIndex)
}

// firstAvailableTarget walks p.models in order and returns the first whose
// suspend state (if suspendDuration is configured at all) isn't currently
// active. When suspendDuration is zero (disabled — see GetPolicy), or when
// every target is currently suspended (nothing better to do), it returns
// index 0 unconditionally — always trying the primary is strictly better
// than refusing to route at all.
func (p *Policy) firstAvailableTarget(ctx context.Context, shared *policy.SharedContext) (int, modelTarget) {
	if p.suspendDuration == 0 {
		return 0, p.models[0]
	}
	for i, m := range p.models {
		if !p.suspend.IsSuspended(ctx, suspendKey(shared, i)) {
			return i, m
		}
	}
	return 0, p.models[0]
}

// OnRequestBody runs once per client request, before anything is sent —
// this is the ONLY point that can redirect to a non-primary target ahead of
// time (the upstream-attempt phase, Task 9, can only react to a target
// Envoy already committed to dialing for that retry). It always rewrites
// "model" to the chosen target's configured name — this policy never
// passes through whatever model name the client sent, matching the old
// APIM UI's explicit "target model" selection semantics (see design spec).
func (p *Policy) OnRequestBody(ctx context.Context, rctx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if rctx.Body == nil || !rctx.Body.Present {
		return policy.UpstreamRequestModifications{}
	}

	idx, target := p.firstAvailableTarget(ctx, rctx.SharedContext)

	var decoded map[string]interface{}
	if err := json.Unmarshal(rctx.Body.Content, &decoded); err != nil {
		slog.WarnContext(ctx, "ModelFailover: request body is not valid JSON, failing open (no mutation)", "error", err)
		return policy.UpstreamRequestModifications{}
	}
	decoded["model"] = target.name
	mutated, err := json.Marshal(decoded)
	if err != nil {
		slog.WarnContext(ctx, "ModelFailover: failed to re-marshal request body, failing open", "error", err)
		return policy.UpstreamRequestModifications{}
	}

	mods := policy.UpstreamRequestModifications{Body: mutated}
	if idx != 0 {
		name := target.upstreamDefinition
		mods.UpstreamName = &name
	}
	return mods
}
