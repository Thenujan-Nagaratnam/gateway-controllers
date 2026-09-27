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
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// attemptState is what the dispatch hop remembers between the request and
// response phases of one attempt.
type attemptState struct {
	nonce     string
	position  int
	targetIdx int
	probe     bool
	started   time.Time
	// passThrough attempts forward the request unchanged and are never
	// classified, tagged or counted towards health.
	passThrough bool
}

// passThroughTimeoutBody answers a pass-through attempt that ran past the
// per-attempt timeout.
var passThroughTimeoutBody = []byte(`{"error":{"message":"The upstream did not respond in time.","type":"server_error","param":null,"code":"upstream_timeout"}}`)

// planRejectedBody is returned when a dispatch-hop request carries no usable
// plan. It is not tagged, so Envoy does not retry it.
var planRejectedBody = []byte(`{"error":{"message":"The request could not be routed.","type":"server_error","param":null,"code":"internal_error"}}`)

// dispatchRequestHeaders picks the plan's next target for this attempt and
// routes the request to that target's loopback upstream. Setting
// selected_provider makes exactly that target's transformer and credential
// policies run further down the dispatch chain.
func (p *Policy) dispatchRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext) policy.RequestHeaderAction {
	nonce := firstHeader(reqCtx.Headers, headerPlan)
	a, plan, err := p.plans.advance(nonce, p.cfg.ChainID)
	switch {
	case errors.Is(err, errPlanExhausted) && plan.isPassThrough():
		// Envoy abandoned the single pass-through attempt on its per-attempt
		// timeout. Answer as a route timeout would, untagged, so nothing
		// retries it and the front hop passes it through.
		return policy.ImmediateResponse{
			StatusCode: http.StatusGatewayTimeout,
			Headers:    map[string]string{"content-type": "application/json"},
			Body:       passThroughTimeoutBody,
		}
	case errors.Is(err, errPlanExhausted):
		if a.timedOutTarget >= 0 {
			o := Outcome{Class: OutcomeEligibleFailure, Reason: reasonTimeout, Probe: plan.probes[a.timedOutTarget]}
			logTransitions(ctx, p.health.record(p.cfg, a.timedOutTarget, o))
		}
		// Envoy's num_retries is fixed per route, but the plan skips
		// suspended targets and may be shorter. Stop the chain here.
		return policy.ImmediateResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    map[string]string{"content-type": "application/json", headerExhausted: "true"},
			Body:       planRejectedBody,
		}
	case err != nil:
		slog.ErrorContext(ctx, "model_failover.plan_rejected", "request_id", requestID(reqCtx.SharedContext), "chain", p.cfg.ChainID, "cause", planRejectCause(err))
		return policy.ImmediateResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    map[string]string{"content-type": "application/json"},
			Body:       planRejectedBody,
		}
	}

	reqID := requestID(reqCtx.SharedContext)
	if a.timedOutTarget >= 0 {
		// The previous attempt never reported back before this one arrived:
		// Envoy abandoned it on its per-attempt timeout.
		o := Outcome{Class: OutcomeEligibleFailure, Reason: reasonTimeout, Probe: plan.probes[a.timedOutTarget]}
		logAttemptFailed(ctx, reqID, p.cfg.ChainID, p.cfg.Targets[a.timedOutTarget], a.position-1, reasonTimeout, p.cfg.PerAttemptTimeout)
		logTransitions(ctx, p.health.record(p.cfg, a.timedOutTarget, o))
	}

	target := p.cfg.Targets[a.targetIdx]
	passThrough := plan.isPassThrough()
	setMetadata(reqCtx.SharedContext, metaAttempt, attemptState{nonce: nonce, position: a.position, targetIdx: a.targetIdx, probe: a.probe, started: p.now(), passThrough: passThrough})

	// The chain header is left in place: a transformer's path rewrite clears
	// the route cache, and the dispatch route must still match on re-lookup.
	// The dispatch route's own request_headers_to_remove strips it at the router.
	mods := policy.UpstreamRequestHeaderModifications{
		HeadersToSet:    map[string]string{headerHop: p.cfg.HopSecret},
		HeadersToRemove: []string{headerPlan},
	}
	// On an LlmProvider every target is the route's own upstream: the route
	// already goes there, and only the model changes, here for a header,
	// query or path model and in dispatchRequestBody for a body model.
	if p.cfg.RouteToTarget {
		upstream := target.UpstreamName()
		setMetadata(reqCtx.SharedContext, selectedProviderKey, upstream)
		mods.UpstreamName = &upstream
	} else if target.Native && !passThrough {
		p.setModelOutsideBody(&mods, reqCtx.Path, target.Model)
	}
	return mods
}

// setModelOutsideBody writes the attempt's model into a header, query
// parameter or path segment, as the template's requestModel says. A path
// the identifier doesn't match is forwarded unchanged.
func (p *Policy) setModelOutsideBody(mods *policy.UpstreamRequestHeaderModifications, path, model string) {
	rm := p.cfg.RequestModel
	switch rm.Location {
	case LocationHeader:
		mods.HeadersToSet[rm.Identifier] = model
	case LocationQueryParam:
		if newPath, ok := replaceQueryParam(path, rm.Identifier, model); ok {
			mods.Path = &newPath
		}
	case LocationPathParam:
		if newPath, ok := replacePathCapture(path, rm.pathRe, model); ok {
			mods.Path = &newPath
		}
	}
}

// replaceQueryParam sets one query parameter, leaving the path and the other
// parameters as they are.
func replaceQueryParam(path, name, value string) (string, bool) {
	base, rawQuery, _ := strings.Cut(path, "?")
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", false
	}
	if cur, ok := q[name]; ok && len(cur) == 1 && cur[0] == value {
		return "", false
	}
	q.Set(name, value)
	return base + "?" + q.Encode(), true
}

// replacePathCapture replaces the first capture group of re in the path
// (the query string is left alone). The model is path-escaped so it can't
// add a segment.
func replacePathCapture(path string, re *regexp.Regexp, model string) (string, bool) {
	base, rawQuery, hasQuery := strings.Cut(path, "?")
	m := re.FindStringSubmatchIndex(base)
	if len(m) < 4 || m[2] < 0 {
		return "", false
	}
	escaped := url.PathEscape(model)
	if base[m[2]:m[3]] == escaped || base[m[2]:m[3]] == model {
		return "", false
	}
	out := base[:m[2]] + escaped + base[m[3]:]
	if hasQuery {
		out += "?" + rawQuery
	}
	return out, true
}

// dispatchRequestBody writes the attempt's model into the body for every chain
// target. A transformer target gets it too, so the translated request names
// the target's model whichever of the body or its own param the transformer
// reads. A pass-through attempt keeps the request's model.
func (p *Policy) dispatchRequestBody(_ context.Context, reqCtx *policy.RequestContext) policy.RequestAction {
	st, ok := currentAttempt(reqCtx.SharedContext)
	if !ok {
		return policy.UpstreamRequestModifications{}
	}
	target := p.cfg.Targets[st.targetIdx]
	if st.passThrough || !p.cfg.RequestModel.inBody() || reqCtx.Body == nil || !reqCtx.Body.Present || len(reqCtx.Body.Content) == 0 {
		return policy.UpstreamRequestModifications{}
	}
	body, changed, err := setBodyModel(reqCtx.Body.Content, p.cfg.RequestModel.Identifier, target.Model)
	if err != nil || !changed {
		// A non-JSON body is forwarded unchanged; the provider rejects it
		// with its own (non-eligible) 4xx.
		return policy.UpstreamRequestModifications{}
	}
	return policy.UpstreamRequestModifications{Body: body}
}

// dispatchResponseHeaders classifies the attempt's response. An eligible
// failure is tagged so the front route's retriable_headers matcher makes
// Envoy retry; everything else passes through untouched.
func (p *Policy) dispatchResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext) policy.ResponseHeaderAction {
	mods := policy.DownstreamResponseHeaderModifications{HeadersToRemove: []string{headerUpstreamFailure}}
	st, ok := currentAttempt(respCtx.SharedContext)
	if !ok || st.passThrough {
		return mods
	}
	outcome := classify(p.cfg.FailoverOn, respCtx.ResponseStatus, firstHeader(respCtx.ResponseHeaders, headerUpstreamFailure))
	outcome.Probe = st.probe
	// The plan is looked up even past its expiry so a slow final attempt is
	// still attributed; record reports false if a timeout was already inferred.
	if plan := p.plans.peek(st.nonce); plan != nil && plan.record(st.position, outcome) {
		logTransitions(ctx, p.health.record(p.cfg, st.targetIdx, outcome))
		if outcome.Class == OutcomeEligibleFailure {
			logAttemptFailed(ctx, requestID(respCtx.SharedContext), p.cfg.ChainID, p.cfg.Targets[st.targetIdx], st.position, outcome.Reason, p.now().Sub(st.started))
		}
	}
	if outcome.Class == OutcomeEligibleFailure {
		mods.HeadersToSet = map[string]string{headerRetry: outcome.Reason}
	}
	return mods
}

// classify maps a response to an outcome. flags is the Envoy response-flags
// value the provider hop's local-reply mapper attaches to transport failures.
func classify(on FailoverOn, status int, flags string) Outcome {
	if flags != "" {
		reason := flagsReason(flags)
		if reason != "" {
			if transportEnabled(on, reason) {
				return Outcome{Class: OutcomeEligibleFailure, Reason: reason}
			}
			return Outcome{Class: OutcomeNonEligible, Reason: reason}
		}
	}
	if on.StatusCodes[status] {
		return Outcome{Class: OutcomeEligibleFailure, Reason: "status_" + strconv.Itoa(status)}
	}
	if status >= 200 && status < 300 {
		return Outcome{Class: OutcomeSuccess}
	}
	return Outcome{Class: OutcomeNonEligible}
}

// flagsReason maps Envoy response flags to a failure reason. The flags value
// is a comma-separated list of short flag names.
func flagsReason(flags string) string {
	reason := ""
	for _, f := range strings.Split(flags, ",") {
		switch strings.TrimSpace(f) {
		case "UT":
			return reasonTimeout
		case "UC", "DC", "UR":
			reason = reasonReset
		case "UF", "URX", "UH", "UO", "LR":
			if reason == "" {
				reason = reasonConnectFailure
			}
		}
	}
	return reason
}

func transportEnabled(on FailoverOn, reason string) bool {
	switch reason {
	case reasonConnectFailure:
		return on.ConnectFailure
	case reasonReset:
		return on.Reset
	case reasonTimeout:
		return on.Timeout
	}
	return false
}

// setBodyModel sets the model at a JSONPath in a JSON object body. The
// common top-level "$.model" keeps every other member's exact encoding.
func setBodyModel(body []byte, jsonPath, model string) ([]byte, bool, error) {
	if jsonPath == defaultRequestModel.Identifier {
		return replaceModel(body, model)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, false, err
	}
	if cur, err := utils.ExtractValueFromJsonpath(obj, jsonPath); err == nil && cur == model {
		return body, false, nil
	}
	if err := utils.SetValueAtJSONPath(obj, jsonPath, model); err != nil {
		return nil, false, err
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// replaceModel sets the top-level "model" of a JSON object body. Other members
// keep their exact encoded values; only key order may change.
func replaceModel(body []byte, model string) ([]byte, bool, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, false, err
	}
	encoded, err := json.Marshal(model)
	if err != nil {
		return nil, false, err
	}
	if current, ok := obj["model"]; ok && string(current) == string(encoded) {
		return body, false, nil
	}
	obj["model"] = encoded
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func currentAttempt(shared *policy.SharedContext) (attemptState, bool) {
	v, ok := getMetadata(shared, metaAttempt)
	if !ok {
		return attemptState{}, false
	}
	st, ok := v.(attemptState)
	return st, ok
}

func planRejectCause(err error) string {
	if errors.Is(err, errChainMismatch) {
		return "chain_mismatch"
	}
	return "unknown_nonce"
}

func requestID(shared *policy.SharedContext) string {
	if shared == nil {
		return ""
	}
	return shared.RequestID
}
