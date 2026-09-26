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

package modelfailover

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// frontRequestHeaders builds the attempt plan for this request and hands its
// nonce to the dispatch hop. Client-supplied internal headers are removed
// here rather than by route config, because a route's request_headers_to_remove
// runs in the router after ext_proc and would also strip the plan header.
func (p *Policy) frontRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext) policy.RequestHeaderAction {
	targets, probes, transitions := p.health.admit(p.cfg)
	logTransitions(ctx, transitionPtrs(transitions)...)
	if len(targets) == 0 {
		// Every target is suspended and none can take a probe: answer now
		// without contacting any upstream.
		logExhausted(ctx, requestID(reqCtx.SharedContext), p.cfg.ChainID, "all_suspended", 0)
		return exhaustionResponse()
	}

	cfg, health := p.cfg, p.health
	nonce, err := p.plans.create(p.cfg.ChainID, targets, probes, p.cfg.planTTL(), func(plan *attemptPlan) {
		for _, idx := range plan.unrecordedProbes() {
			health.release(cfg, idx)
		}
	})
	if err != nil {
		for idx := range probes {
			p.health.release(p.cfg, idx)
		}
		slog.ErrorContext(ctx, "model_failover: failed to create attempt plan", "chain", p.cfg.ChainID, "error", err)
		return exhaustionResponse()
	}
	setMetadata(reqCtx.SharedContext, metaNonce, nonce)

	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet:    map[string]string{headerPlan: nonce},
		HeadersToRemove: clientSuppliedInternalHeaders(reqCtx.Headers),
	}
}

// frontResponseHeaders sees only the final response: Envoy's router has
// already discarded every retried one. It attributes a final per-attempt
// timeout, turns a chain that ran out of targets into the fixed exhaustion
// response, and strips every internal header from what the client sees.
func (p *Policy) frontResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext) policy.ResponseHeaderAction {
	strip := policy.DownstreamResponseHeaderModifications{
		HeadersToRemove: []string{headerRetry, headerExhausted, headerUpstreamFailure},
	}
	v, _ := getMetadata(respCtx.SharedContext, metaNonce)
	nonce, _ := v.(string)
	if nonce == "" {
		return strip
	}
	plan := p.plans.peek(nonce)
	if plan == nil {
		return strip
	}
	defer p.plans.close(nonce)

	reqID := requestID(respCtx.SharedContext)
	pos, targetIdx, recorded, attempted := plan.lastAttempted()

	// The last attempt never reported back: Envoy abandoned it on its
	// per-attempt timeout and answered with its own 504.
	// When timeouts are not a failover condition, the 504 goes to the client
	// as it is and says nothing about the target's health.
	timedOut := attempted && !recorded && respCtx.ResponseStatus == http.StatusGatewayTimeout
	if timedOut && p.cfg.FailoverOn.Timeout {
		o := Outcome{Class: OutcomeEligibleFailure, Reason: reasonTimeout, Probe: plan.probes[targetIdx]}
		if plan.record(pos, o) {
			logTransitions(ctx, p.health.record(p.cfg, targetIdx, o))
			logAttemptFailed(ctx, reqID, p.cfg.ChainID, p.cfg.Targets[targetIdx], pos, reasonTimeout, p.cfg.PerAttemptTimeout)
		}
	}

	exhausted := firstHeader(respCtx.ResponseHeaders, headerRetry) != "" ||
		firstHeader(respCtx.ResponseHeaders, headerExhausted) != "" ||
		(timedOut && p.cfg.FailoverOn.Timeout)
	if exhausted {
		logExhausted(ctx, reqID, p.cfg.ChainID, "all_failed", plan.attempts())
		return exhaustionResponse()
	}
	if attempted {
		logServed(ctx, reqID, p.cfg.ChainID, p.cfg.Targets[targetIdx], pos, plan.attempts())
	}
	return strip
}

// clientSuppliedInternalHeaders lists every internal header present on the
// incoming request except the plan header, which is overwritten instead.
func clientSuppliedInternalHeaders(h *policy.Headers) []string {
	var remove []string
	if h == nil {
		return remove
	}
	h.Iterate(func(name string, _ []string) {
		lower := strings.ToLower(name)
		if lower == headerPlan {
			return
		}
		if strings.HasPrefix(lower, headerPrefix) || lower == headerUpstreamFailure {
			remove = append(remove, name)
		}
	})
	return remove
}

// exhaustionBody is the fixed client-facing response when no target can serve
// the request (contracts/exhaustion-response.md). It never varies with the
// failures that occurred.
var exhaustionBody = []byte(`{"error":{"message":"All configured model targets are currently unavailable. Please retry later.","type":"model_failover_exhausted","param":null,"code":"all_targets_unavailable"}}`)

func exhaustionResponse() policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode: http.StatusServiceUnavailable,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       exhaustionBody,
	}
}
