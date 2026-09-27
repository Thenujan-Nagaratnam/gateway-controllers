/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Package modelfailover walks an ordered chain of LLM targets using Envoy's
// native retry policy.
//
// gateway-controller attaches this policy twice for every route it is
// configured on. The front instance runs once per client request on the
// LlmProxy route: it builds the attempt plan and cleans up the final
// response. The route's Envoy retry policy then re-sends the request to an
// internal-listener dispatch route, once per attempt, where the dispatch
// instance picks the plan's next target and tags failures Envoy should retry.
package modelfailover

import (
	"context"
	"fmt"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Internal headers exchanged between the front and dispatch hops. None of
// them reach the client or a provider.
const (
	headerPrefix          = "x-wso2-failover-"
	headerChain           = "x-wso2-failover-chain"
	headerPlan            = "x-wso2-failover-plan"
	headerHop             = "x-wso2-failover-hop"
	headerRetry           = "x-wso2-failover-retry"
	headerExhausted       = "x-wso2-failover-exhausted"
	headerUpstreamFailure = "x-wso2-upstream-failure"
)

// Metadata keys. selectedProviderKey is the engine-level contract consumed by
// the provider-scoped transformer and credential policies' CEL conditions.
const (
	selectedProviderKey = "selected_provider"
	metaNonce           = "model_failover.nonce"
	metaAttempt         = "model_failover.attempt"
)

// Failure reasons (bounded; used as metric label values).
const (
	reasonConnectFailure = "connect_failure"
	reasonReset          = "reset"
	reasonTimeout        = "timeout"
)

// Policy is a model-failover instance in either role.
type Policy struct {
	cfg    *Config
	plans  *planRegistry
	health *healthRegistry
	now    func() time.Time
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(_ policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	cfg, err := parseConfig(params)
	if err != nil {
		return nil, fmt.Errorf("invalid model-failover params: %w", err)
	}
	globalPlans.startSweeper(time.Second)
	return newPolicy(cfg, globalPlans, globalHealth, time.Now), nil
}

func newPolicy(cfg *Config, plans *planRegistry, health *healthRegistry, now func() time.Time) *Policy {
	return &Policy{cfg: cfg, plans: plans, health: health, now: now}
}

// Mode is computed per instance: the dispatch role buffers the request body
// so it can rewrite "model" for targets that need no transformer.
func (p *Policy) Mode() policy.ProcessingMode {
	mode := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeProcess,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if p.cfg.Role == RoleDispatch && p.cfg.hasNativeTarget() {
		mode.RequestBodyMode = policy.BodyModeBuffer
	}
	return mode
}

func (c *Config) hasNativeTarget() bool {
	for _, t := range c.Targets {
		if t.Native {
			return true
		}
	}
	return false
}

// OnRequestHeaders routes to the role's handler.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	if p.cfg.Role == RoleDispatch {
		return p.dispatchRequestHeaders(ctx, reqCtx)
	}
	return p.frontRequestHeaders(ctx, reqCtx)
}

// OnRequestBody is used by the dispatch role only.
func (p *Policy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if p.cfg.Role == RoleDispatch {
		return p.dispatchRequestBody(ctx, reqCtx)
	}
	return policy.UpstreamRequestModifications{}
}

// OnResponseHeaders routes to the role's handler.
func (p *Policy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if p.cfg.Role == RoleDispatch {
		return p.dispatchResponseHeaders(ctx, respCtx)
	}
	return p.frontResponseHeaders(ctx, respCtx)
}

func firstHeader(h *policy.Headers, name string) string {
	if h == nil {
		return ""
	}
	if v := h.Get(name); len(v) > 0 {
		return v[0]
	}
	return ""
}

func setMetadata(shared *policy.SharedContext, key string, value interface{}) {
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = make(map[string]interface{})
	}
	shared.Metadata[key] = value
}

func getMetadata(shared *policy.SharedContext, key string) (interface{}, bool) {
	if shared == nil || shared.Metadata == nil {
		return nil, false
	}
	v, ok := shared.Metadata[key]
	return v, ok
}
