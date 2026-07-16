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

// Package azuremanagedidentity authenticates outbound requests to an
// Azure-hosted backend using a User-Assigned Managed Identity (UMI), obtained
// via the Azure Instance Metadata Service (IMDS) rather than a configured
// client secret. See policy-definition.yaml for the full picture, including
// why this only works when gateway-runtime actually runs on Azure compute.
package azuremanagedidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	xoauth2 "golang.org/x/oauth2"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// AuthType is the AuthContext.AuthType value recorded by this policy.
	AuthType = "azure-managed-identity"

	// defaultIMDSEndpoint is Azure's well-known Instance Metadata Service
	// token endpoint - a link-local address only reachable from inside
	// Azure's own virtualization host. Never derived from a user-facing
	// param; see policy-definition.yaml's systemParameters.imdsEndpoint for
	// why an override, when needed at all, is a system parameter only.
	defaultIMDSEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"

	// imdsAPIVersion is the Azure IMDS token endpoint's api-version query
	// parameter. Not configurable - tied to the response shape this policy
	// parses.
	imdsAPIVersion = "2018-02-01"

	defaultRequestTimeout = 2 * time.Second

	// maxIMDSResponseBytes bounds how much of the IMDS response body this
	// policy will read, regardless of what the server claims or sends - a
	// real token response is at most a few KB.
	maxIMDSResponseBytes = 64 * 1024
)

// Policy injects an Authorization: Bearer header obtained from a
// user-assigned managed identity via IMDS before the request is forwarded
// upstream.
type Policy struct {
	clientID string
	resource string

	// tokenSource supplies a cached, automatically-refreshed access token.
	// Built once in GetPolicy and reused across requests. Always a
	// *redisCachingTokenSource (see token_cache.go) wrapping imdsTokenSource.
	tokenSource xoauth2.TokenSource

	// Test seam - production code calls tokenSource.Token() directly; unit
	// tests override this to avoid a real IMDS call, mirroring the pattern
	// used by the oauth2 and aws-authentication policies.
	tokenFunc func() (*xoauth2.Token, error)
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	slog.Debug("AzureManagedIdentity: constructing policy from params")

	clientID, err := getRequiredStringParam(params, "clientId")
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	resource, err := getRequiredStringParam(params, "resource")
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	sp := extractSystemParams(params)

	inner := &imdsTokenSource{
		httpClient: &http.Client{Timeout: sp.requestTimeout},
		endpoint:   sp.imdsEndpoint,
		clientID:   clientID,
		resource:   resource,
	}
	tokenSource := newRedisCachingTokenSource(inner, sp.redis, metadata, clientID, resource)

	pol := &Policy{
		clientID:    clientID,
		resource:    resource,
		tokenSource: tokenSource,
	}
	pol.tokenFunc = pol.tokenSource.Token

	slog.Debug("AzureManagedIdentity: policy initialized", "clientId", pol.clientID, "resource", pol.resource)

	return pol, nil
}

// imdsTokenSource implements xoauth2.TokenSource by calling Azure's Instance
// Metadata Service directly. Unlike a standard OAuth2 token endpoint, this
// is a plain GET with a required "Metadata: true" header and no request
// body - Azure's platform authenticates the identity on the gateway's
// behalf, so there is no client secret to present here at all.
type imdsTokenSource struct {
	httpClient *http.Client
	endpoint   string
	clientID   string
	resource   string
}

// imdsTokenResponse mirrors Azure IMDS's actual response shape. Note that
// expires_in/expires_on/ext_expires_in/not_before are quoted JSON strings,
// not native numbers, unlike a standard RFC 6749 token response's
// expires_in - decoding them into Go string fields (rather than int) avoids
// a type-mismatch unmarshal error and lets this policy parse them
// explicitly where it actually needs them (expires_on only).
type imdsTokenResponse struct {
	AccessToken string `json:"access_token"`
	ClientID    string `json:"client_id,omitempty"`
	ExpiresOn   string `json:"expires_on"`
	Resource    string `json:"resource,omitempty"`
	TokenType   string `json:"token_type"`
}

func (s *imdsTokenSource) Token() (*xoauth2.Token, error) {
	req, err := http.NewRequest(http.MethodGet, s.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build IMDS request: %w", err)
	}
	req.Header.Set("Metadata", "true")

	q := req.URL.Query()
	q.Set("api-version", imdsAPIVersion)
	q.Set("resource", s.resource)
	if s.clientID != "" {
		q.Set("client_id", s.clientID)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("IMDS request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIMDSResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read IMDS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IMDS returned status %d", resp.StatusCode)
	}

	var parsed imdsTokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("failed to decode IMDS response: %w", err)
	}
	if parsed.AccessToken == "" {
		return nil, fmt.Errorf("IMDS response missing access_token")
	}

	expiryUnix, err := strconv.ParseInt(strings.TrimSpace(parsed.ExpiresOn), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IMDS expires_on %q: %w", parsed.ExpiresOn, err)
	}

	tokenType := parsed.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	return &xoauth2.Token{
		AccessToken: parsed.AccessToken,
		TokenType:   tokenType,
		Expiry:      time.Unix(expiryUnix, 0),
	}, nil
}

// Mode returns the processing mode for this policy. Injecting a bearer token
// needs no request body inspection, so this implements the lighter
// header-phase hook only, same as the oauth2 policy.
func (p *Policy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// getStringParam safely extracts a string parameter, returning "" if absent
// or the wrong type. Leading/trailing whitespace is trimmed.
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return strings.TrimSpace(str)
		}
	}
	return ""
}

// getRequiredStringParam extracts a required, non-empty string parameter,
// trimmed per getStringParam.
func getRequiredStringParam(params map[string]interface{}, key string) (string, error) {
	val, ok := params[key]
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	str = strings.TrimSpace(str)
	if str == "" {
		return "", fmt.Errorf("'%s' cannot be empty", key)
	}
	return str, nil
}

// OnRequestHeaders fetches (or reuses a cached) access token and injects it
// as an Authorization: Bearer header before the request is forwarded to the
// upstream backend.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	slog.Debug("AzureManagedIdentity: authenticating outbound request", "method", reqCtx.Method, "path", reqCtx.Path,
		"clientId", p.clientID, "resource", p.resource)

	tok, err := p.retrieveToken()
	if err != nil {
		return p.authFailure(reqCtx.SharedContext, "failed to obtain managed identity access token", err)
	}

	p.authSuccess(reqCtx.SharedContext)

	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{
			"Authorization": "Bearer " + tok.AccessToken,
		},
	}
}

// retrieveToken fetches the current (possibly cached/refreshed) access token
// from the token source built once in GetPolicy.
func (p *Policy) retrieveToken() (*xoauth2.Token, error) {
	fetch := p.tokenFunc
	if fetch == nil {
		fetch = p.tokenSource.Token
	}
	return fetch()
}

// authFailure builds a 502 Bad Gateway ImmediateResponse for gateway-side
// token-acquisition failures. 502 (not 401) is deliberate: the caller's
// request was fine - it is the gateway's own managed-identity setup or IMDS
// itself that failed, a gateway-to-backend problem rather than a
// client-auth rejection. Mirrors the oauth2/aws-authentication policies'
// own error shape exactly, so callers see one consistent failure contract
// across every outbound-auth policy.
func (p *Policy) authFailure(shared *policy.SharedContext, reason string, cause error) policy.RequestHeaderAction {
	slog.Error("AzureManagedIdentity: token acquisition failed", "reason", reason, "error", cause,
		"clientId", p.clientID, "resource", p.resource)

	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		CredentialID:  p.clientID,
		Properties: map[string]string{
			"resource": p.resource,
		},
		Previous: shared.AuthContext,
	}

	body, _ := json.Marshal(map[string]string{
		"error":   "Bad Gateway",
		"message": "failed to authenticate request to upstream service",
	})
	return policy.ImmediateResponse{
		StatusCode: http.StatusBadGateway,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}

// authSuccess records a successful authentication in the shared AuthContext,
// preserving any existing chain (e.g. an earlier inbound auth policy) via
// Previous.
func (p *Policy) authSuccess(shared *policy.SharedContext) {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		CredentialID:  p.clientID,
		Properties: map[string]string{
			"resource": p.resource,
		},
		Previous: shared.AuthContext,
	}
}
