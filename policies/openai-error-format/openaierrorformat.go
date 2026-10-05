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

// Package openaierrorformat is a fault policy that returns the gateway-produced errors of
// an LlmProvider or LlmProxy API in the OpenAI error envelope, so OpenAI SDK clients can
// parse them. It runs only on the fault path and changes nothing on a successful request.
package openaierrorformat

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	policyName = "openai-error-format"

	// defaultMaxInspectBytes bounds how much of an error body is parsed to recover the
	// rejecting policy's message.
	defaultMaxInspectBytes = 64 * 1024
)

// Policy renders gateway-produced errors on LLM APIs in the OpenAI error envelope.
type Policy struct {
	maxInspectBytes int
}

var _ policy.FaultPolicy = (*Policy)(nil)

// GetPolicy creates a policy instance from its parameters.
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return newPolicy(params)
}

// Mode skips every request and response phase: the policy only runs through OnFault, so
// it adds no work to a successful request.
func (p *Policy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

func newPolicy(params map[string]interface{}) (*Policy, error) {
	p := &Policy{maxInspectBytes: defaultMaxInspectBytes}

	rawFault, ok := params["fault"]
	if !ok || rawFault == nil {
		return p, nil
	}
	faultParams, ok := rawFault.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("'fault' must be an object")
	}

	if raw, ok := faultParams["maxInspectBytes"]; ok && raw != nil {
		n, err := toNonNegativeInt(raw)
		if err != nil {
			return nil, fmt.Errorf("'fault.maxInspectBytes' %w", err)
		}
		p.maxInspectBytes = n
	}
	return p, nil
}

func toNonNegativeInt(v interface{}) (int, error) {
	var n float64
	switch t := v.(type) {
	case int:
		n = float64(t)
	case int64:
		n = float64(t)
	case float64:
		n = t
	default:
		return 0, fmt.Errorf("must be an integer")
	}
	if n != math.Trunc(n) || n > math.MaxInt32 {
		return 0, fmt.Errorf("must be an integer")
	}
	if n < 0 {
		return 0, fmt.Errorf("must be >= 0")
	}
	return int(n), nil
}

// OnFault replaces a gateway-produced error body on an LLM API with the OpenAI envelope.
// Returning nil leaves the client's error exactly as it was.
//
// It must never make the client's response worse. The engine does not recover a panic on
// the fault path, so any panic here is recovered and the original error is kept.
func (p *Policy) OnFault(
	ctx context.Context,
	faultCtx *policy.FaultContext,
	params map[string]interface{},
) (resp *policy.FaultResponse) {
	if faultCtx == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			slog.ErrorContext(ctx, "openai-error-format: recovered from panic, keeping the original error",
				"policy", policyName, "route", faultCtx.RouteKey, "panic", fmt.Sprint(r))
			resp = nil
		}
	}()
	return p.format(faultCtx)
}

// format decides whether the error is one this policy owns and, if so, builds the
// replacement response.
//
// The gates run in a fixed order and each one returns nil, which keeps the error as it is.
func (p *Policy) format(faultCtx *policy.FaultContext) *policy.FaultResponse {
	// Only LLM APIs, whose callers are OpenAI SDKs. Checked before anything else is read.
	if faultCtx.APIKind != policy.APIKindLlmProvider && faultCtx.APIKind != policy.APIKindLlmProxy {
		return nil
	}
	// A streamed response whose headers already went out can be observed but not changed.
	if faultCtx.ResponseCommitted {
		return nil
	}
	if !gatewayProduced(faultCtx) {
		return nil
	}
	// Already the OpenAI envelope — written by another fault policy, or by this one attached
	// at a second level. Leaving it makes the policy idempotent.
	if b := faultCtx.ResponseBody; b != nil && b.Present && !isEncoded(faultCtx.ResponseHeaders) &&
		isOpenAIEnvelope(b.Content) {
		return nil
	}

	status := faultCtx.ResponseStatus
	var found bodyInfo
	if b := faultCtx.ResponseBody; b != nil && b.Present {
		found = inspectBody(b.Content, faultCtx.ResponseHeaders, p.maxInspectBytes)
	}

	// The message, in priority order: what the failing policy described, what it wrote in
	// its own body, then the status text.
	message := ""
	if faultCtx.Fault != nil {
		message = faultCtx.Fault.Message
	}
	if message == "" {
		message = found.message
	}
	if message == "" {
		message = http.StatusText(status)
	}
	if message == "" {
		message = "Request failed"
	}

	body, err := buildEnvelope(faultCtx.Fault, status, message, found.guardrail)
	if err != nil {
		slog.Error("openai-error-format: could not render the envelope, keeping the original error",
			"policy", policyName, "route", faultCtx.RouteKey, "error", err)
		return nil
	}

	resp := &policy.FaultResponse{
		Body:         body,
		HeadersToSet: map[string]string{"content-type": "application/json"},
	}
	// The replacement body is plain JSON, so an encoding the original carried no longer applies.
	if faultCtx.ResponseHeaders.Has("content-encoding") {
		resp.HeadersToRemove = []string{"content-encoding"}
	}
	return resp
}

// gatewayProduced reports whether the gateway wrote this error, as opposed to the backend.
//
// A policy rejection or engine failure (gateway) and a reply the proxy generated because
// the attempt failed (router) are the gateway's. The backend's own error is passed through:
// it is the provider's real error, and OpenAI-compatible providers already use this shape.
// When provenance is missing, only a failure a policy is named for is known to be the
// gateway's; anything else may be a backend error from a router that reports no source.
func gatewayProduced(faultCtx *policy.FaultContext) bool {
	switch faultCtx.Source {
	case policy.FaultSourceGateway, policy.FaultSourceRouter:
		return true
	case policy.FaultSourceBackend, policy.FaultSourceNoRoute:
		return false
	default:
		return faultCtx.Policy != ""
	}
}
