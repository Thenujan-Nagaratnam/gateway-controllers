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

package oauth2authentication

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// ClientAuthMethodBasic sends the client ID/secret as HTTP Basic auth on
	// the token request.
	ClientAuthMethodBasic = "client_secret_basic"
	// ClientAuthMethodPost sends the client ID/secret as form fields in the
	// token request body.
	ClientAuthMethodPost = "client_secret_post"

	// AuthType is the AuthContext.AuthType value recorded by this policy.
	AuthType = "oauth2-client-credentials"
)

// OAuth2AuthenticationPolicy authenticates outbound requests to an upstream
// backend using the OAuth2 Client Credentials grant (RFC 6749 Section 4.4)
// before they are forwarded.
type OAuth2AuthenticationPolicy struct {
	tokenEndpoint    string
	clientID         string
	clientAuthMethod string

	// tokenSource supplies a cached, automatically-refreshed access token.
	// Built once in GetPolicy and reused across requests. oauth2.ReuseTokenSource
	// guards its cached token with its own internal mutex, so concurrent
	// Token() calls are safe and a refresh in flight is not duplicated by a
	// second concurrent caller (they block on the same lock and observe the
	// freshly-refreshed token instead of firing a second request).
	tokenSource oauth2.TokenSource

	// Test seam — production code calls tokenSource.Token() directly; unit
	// tests override this to avoid a real network call to a token endpoint,
	// mirroring the retrieveCredentialsFunc pattern used in the
	// aws-authentication policy. oauth2.TokenSource.Token() takes no context —
	// the context passed to clientcredentials.Config.TokenSource(ctx) at
	// construction time is what an eventual HTTP call would use.
	tokenFunc func() (*oauth2.Token, error)
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	slog.Debug("OAuth2Authentication: constructing policy from params")

	tokenEndpoint, clientID, clientSecret, scope, clientAuthMethod, err := validateAndExtractParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	slog.Debug("OAuth2Authentication: validated params",
		"tokenEndpoint", tokenEndpoint, "clientId", clientID, "clientAuthMethod", clientAuthMethod)

	cfg := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenEndpoint,
		AuthStyle:    authStyleFor(clientAuthMethod),
	}
	if scope != "" {
		cfg.Scopes = strings.Fields(scope)
	}

	p := &OAuth2AuthenticationPolicy{
		tokenEndpoint:    tokenEndpoint,
		clientID:         clientID,
		clientAuthMethod: clientAuthMethod,
		tokenSource:      cfg.TokenSource(context.Background()),
	}
	p.tokenFunc = p.tokenSource.Token

	slog.Debug("OAuth2Authentication: policy initialized",
		"tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID, "clientAuthMethod", p.clientAuthMethod)

	return p, nil
}

// authStyleFor maps the required, no-default clientAuthMethod param onto the
// oauth2 package's AuthStyle constant. validateAndExtractParams already
// rejects any value other than the two constants below, so the default case
// here is unreachable in practice — it exists only to satisfy the compiler.
func authStyleFor(clientAuthMethod string) oauth2.AuthStyle {
	switch clientAuthMethod {
	case ClientAuthMethodPost:
		return oauth2.AuthStyleInParams
	case ClientAuthMethodBasic:
		return oauth2.AuthStyleInHeader
	default:
		return oauth2.AuthStyleAutoDetect
	}
}

// Mode returns the processing mode for the OAuth2 authentication policy.
// Injecting a bearer token needs no request body inspection, so this
// implements the lighter header-phase hook rather than buffering the body
// the way aws-authentication must for SigV4 payload hashing.
func (p *OAuth2AuthenticationPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// getStringParam safely extracts a string parameter, returning "" if absent
// or the wrong type. Leading/trailing whitespace is trimmed: credential
// values pasted from config files or secret stores frequently carry a stray
// trailing newline or space, which is invisible in logs but silently
// corrupts a client-secret comparison at the token endpoint.
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

// validateAndExtractParams validates and extracts all policy params.
// clientAuthMethod is deliberately required with no default (see
// policy-definition.yaml): a wrong silent default would fail at request
// time against the token endpoint instead of failing loudly at
// configuration time.
func validateAndExtractParams(params map[string]interface{}) (tokenEndpoint, clientID, clientSecret, scope, clientAuthMethod string, err error) {
	tokenEndpoint, err = getRequiredStringParam(params, "tokenEndpoint")
	if err != nil {
		return "", "", "", "", "", err
	}
	clientID, err = getRequiredStringParam(params, "clientId")
	if err != nil {
		return "", "", "", "", "", err
	}
	clientSecret, err = getRequiredStringParam(params, "clientSecret")
	if err != nil {
		return "", "", "", "", "", err
	}
	clientAuthMethod, err = getRequiredStringParam(params, "clientAuthMethod")
	if err != nil {
		return "", "", "", "", "", err
	}
	if clientAuthMethod != ClientAuthMethodBasic && clientAuthMethod != ClientAuthMethodPost {
		return "", "", "", "", "", fmt.Errorf("'clientAuthMethod' must be one of %q, %q", ClientAuthMethodBasic, ClientAuthMethodPost)
	}
	scope = getStringParam(params, "scope")

	return tokenEndpoint, clientID, clientSecret, scope, clientAuthMethod, nil
}

// OnRequestHeaders fetches (or reuses a cached) access token and injects it
// as an Authorization: Bearer header before the request is forwarded to the
// upstream backend.
func (p *OAuth2AuthenticationPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	slog.Debug("OAuth2Authentication: authenticating outbound request", "method", reqCtx.Method, "path", reqCtx.Path,
		"tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID)

	tok, err := p.retrieveToken()
	if err != nil {
		return p.authFailure(reqCtx.SharedContext, "failed to obtain OAuth2 access token", err)
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
func (p *OAuth2AuthenticationPolicy) retrieveToken() (*oauth2.Token, error) {
	fetch := p.tokenFunc
	if fetch == nil {
		fetch = p.tokenSource.Token
	}
	return fetch()
}

// authFailure builds a 502 Bad Gateway ImmediateResponse for gateway-side
// token-acquisition failures. 502 (not 401) is deliberate: the caller's
// request was fine — it is the gateway's own OAuth2 client credentials or
// the token endpoint that failed, a gateway-to-backend problem rather than a
// client-auth rejection.
func (p *OAuth2AuthenticationPolicy) authFailure(shared *policy.SharedContext, reason string, cause error) policy.RequestHeaderAction {
	slog.Error("OAuth2Authentication: token acquisition failed", "reason", reason, "error", cause,
		"tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID)

	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		CredentialID:  p.clientID,
		Properties: map[string]string{
			"tokenEndpoint": p.tokenEndpoint,
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

// authSuccess records a successful OAuth2 authentication in the shared
// AuthContext, preserving any existing chain (e.g. an earlier inbound auth
// policy) via Previous.
func (p *OAuth2AuthenticationPolicy) authSuccess(shared *policy.SharedContext) {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		CredentialID:  p.clientID,
		Properties: map[string]string{
			"tokenEndpoint": p.tokenEndpoint,
		},
		Previous: shared.AuthContext,
	}
}
