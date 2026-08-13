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
	"fmt"
	"strings"
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
