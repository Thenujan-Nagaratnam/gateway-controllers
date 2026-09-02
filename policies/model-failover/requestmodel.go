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

package modelfailover

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

// requestModelConfig locates the client's own model identifier in the request — the SAME
// systemParameters convention model-round-robin and model-weighted-round-robin already consume,
// injected by gateway-controller from the LlmProvider/LlmProxy's own template (never
// operator-configured directly). Every current built-in template uses {location: payload,
// identifier: $.model}, but this policy supports the same four locations those sibling policies
// do, so a future template using a different shape doesn't silently mismatch.
type requestModelConfig struct {
	Location   string // payload | header | queryParam | pathParam
	Identifier string
}

// parseRequestModelConfig parses requestModel exactly as model-round-robin's own parseParams
// does — required, since gateway-controller injects it unconditionally for any policy on an
// LlmProvider/LlmProxy.
func parseRequestModelConfig(params map[string]interface{}) (requestModelConfig, error) {
	raw, ok := params["requestModel"]
	if !ok {
		return requestModelConfig{}, fmt.Errorf("model-failover: 'requestModel' configuration is required")
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return requestModelConfig{}, fmt.Errorf("model-failover: 'requestModel' must be an object")
	}

	location, ok := m["location"].(string)
	if !ok || location == "" {
		return requestModelConfig{}, fmt.Errorf("model-failover: 'requestModel.location' is required")
	}
	validLocations := map[string]bool{"payload": true, "header": true, "queryParam": true, "pathParam": true}
	if !validLocations[location] {
		return requestModelConfig{}, fmt.Errorf("model-failover: 'requestModel.location' must be one of: payload, header, queryParam, pathParam")
	}

	identifier, ok := m["identifier"].(string)
	if !ok || identifier == "" {
		return requestModelConfig{}, fmt.Errorf("model-failover: 'requestModel.identifier' is required")
	}

	return requestModelConfig{Location: location, Identifier: identifier}, nil
}

// extractRequestedModel reads the client's own model identifier per cfg.Location — the read-side
// counterpart to buildFallbackRequest's write side. bodyBytes/headers/path are whichever of the
// three the location actually needs; the other two may be nil/empty.
func extractRequestedModel(cfg requestModelConfig, bodyBytes []byte, headers *policy.Headers, path string) (string, error) {
	switch cfg.Location {
	case "payload":
		if len(bodyBytes) == 0 {
			return "", fmt.Errorf("request body is empty")
		}
		return utils.ExtractStringValueFromJsonpath(bodyBytes, cfg.Identifier)
	case "header":
		if headers == nil {
			return "", fmt.Errorf("no headers available")
		}
		vals := headers.Get(cfg.Identifier)
		if len(vals) == 0 || vals[0] == "" {
			return "", fmt.Errorf("header %q not present", cfg.Identifier)
		}
		return vals[0], nil
	case "queryParam":
		val, ok := extractQueryParam(path, cfg.Identifier)
		if !ok {
			return "", fmt.Errorf("query param %q not present", cfg.Identifier)
		}
		return val, nil
	case "pathParam":
		val, ok := extractPathParam(path, cfg.Identifier)
		if !ok {
			return "", fmt.Errorf("path does not match pattern %q", cfg.Identifier)
		}
		return val, nil
	default:
		return "", fmt.Errorf("unsupported requestModel.location %q", cfg.Location)
	}
}

// buildFallbackRequest computes the final path/body/extra-header for a fallback or override
// attempt with model injected per cfg.Location — the write-side counterpart to
// extractRequestedModel. Only the location actually being used is modified; everything else
// (the body for header/queryParam/pathParam, the path for payload/header) passes through
// unchanged, since the model doesn't live there.
func buildFallbackRequest(cfg requestModelConfig, basePath string, originalBody []byte, model string) (path string, body []byte, extraHeaders map[string]string, err error) {
	switch cfg.Location {
	case "payload":
		if len(originalBody) == 0 {
			return "", nil, nil, fmt.Errorf("request body is empty")
		}
		var decoded map[string]interface{}
		if err := json.Unmarshal(originalBody, &decoded); err != nil {
			return "", nil, nil, fmt.Errorf("request body is not valid JSON: %w", err)
		}
		if err := utils.SetValueAtJSONPath(decoded, cfg.Identifier, model); err != nil {
			return "", nil, nil, fmt.Errorf("could not set model at %q: %w", cfg.Identifier, err)
		}
		newBody, err := json.Marshal(decoded)
		if err != nil {
			return "", nil, nil, fmt.Errorf("could not re-encode request body: %w", err)
		}
		return basePath, newBody, nil, nil
	case "header":
		return basePath, originalBody, map[string]string{cfg.Identifier: model}, nil
	case "queryParam":
		return modifyQueryParamInPath(basePath, cfg.Identifier, model), originalBody, nil, nil
	case "pathParam":
		newPath := modifyPathParamInPath(basePath, cfg.Identifier, model)
		if newPath == basePath {
			return "", nil, nil, fmt.Errorf("path does not match pattern %q", cfg.Identifier)
		}
		return newPath, originalBody, nil, nil
	default:
		return "", nil, nil, fmt.Errorf("unsupported requestModel.location %q", cfg.Location)
	}
}

// extractQueryParam reads a query parameter's value out of a raw request path (path + query
// string together, as this SDK's Path fields carry it).
func extractQueryParam(rawPath, paramName string) (string, bool) {
	if rawPath == "" {
		return "", false
	}
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		decodedPath = rawPath
	}
	parts := strings.SplitN(decodedPath, "?", 2)
	if len(parts) != 2 {
		return "", false
	}
	values, err := url.ParseQuery(parts[1])
	if err != nil {
		return "", false
	}
	val := values.Get(paramName)
	if val == "" {
		return "", false
	}
	return val, true
}

// extractPathParam matches regexPattern against the path portion (query string stripped) and
// returns its first capture group — the model segment, per model-round-robin's own
// pathParam convention (e.g. "/models/([^/]+)").
func extractPathParam(rawPath, regexPattern string) (string, bool) {
	if rawPath == "" {
		return "", false
	}
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		decodedPath = rawPath
	}
	pathWithoutQuery := strings.SplitN(decodedPath, "?", 2)[0]
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return "", false
	}
	matches := re.FindStringSubmatch(pathWithoutQuery)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}

// modifyQueryParamInPath and modifyPathParamInPath are ported from model-round-robin's own
// write-side helpers (roundrobin.go) so both policies rewrite a query/path param identically.

func modifyQueryParamInPath(rawPath, paramName, newValue string) string {
	if rawPath == "" {
		return rawPath
	}
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		return rawPath
	}
	parts := strings.SplitN(decodedPath, "?", 2)
	pathBase := parts[0]
	var queryValues url.Values
	if len(parts) == 2 {
		queryValues, err = url.ParseQuery(parts[1])
		if err != nil {
			return rawPath
		}
	} else {
		queryValues = make(url.Values)
	}
	queryValues.Set(paramName, newValue)
	return pathBase + "?" + queryValues.Encode()
}

func modifyPathParamInPath(rawPath, regexPattern, newValue string) string {
	if rawPath == "" {
		return rawPath
	}
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		return rawPath
	}
	parts := strings.SplitN(decodedPath, "?", 2)
	pathWithoutQuery := parts[0]
	queryString := ""
	if len(parts) == 2 {
		queryString = parts[1]
	}
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return rawPath
	}
	matchIndices := re.FindStringSubmatchIndex(pathWithoutQuery)
	if len(matchIndices) < 4 || matchIndices[2] == -1 || matchIndices[3] == -1 {
		return rawPath
	}
	updatedPath := pathWithoutQuery[:matchIndices[2]] + newValue + pathWithoutQuery[matchIndices[3]:]
	if queryString != "" {
		return updatedPath + "?" + queryString
	}
	return updatedPath
}
