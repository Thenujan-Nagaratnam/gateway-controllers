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

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	xoauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// GrantTypeClientCredentials (RFC 6749 Section 4.4) is the standard
	// machine-to-machine grant and should be preferred whenever the
	// upstream identity provider supports it.
	GrantTypeClientCredentials = "client_credentials"

	// GrantTypePassword (RFC 6749 Section 4.3, Resource Owner Password
	// Credentials) is supported for bridging to legacy identity providers
	// that only expose this grant. Current OAuth2 security guidance
	// discourages it for new integrations, since it requires the client to
	// handle the resource owner's raw username/password directly — see
	// policy-definition.yaml's security note.
	GrantTypePassword = "password"

	// AuthType is the AuthContext.AuthType value recorded by this policy.
	// Grant-agnostic by design: it identifies "authenticated via OAuth2",
	// not which grant was used. The grant is available separately via
	// AuthContext.Properties["grantType"] for anyone who needs it.
	AuthType = "oauth2"
)

// oauth2Params bundles all extracted, validated policy params. Passed as a
// single struct (rather than positional args) now that the set has grown
// with grantType-conditional fields (username/password) — positional args
// for six-plus mostly-string fields invite mixed-up-order bugs.
type oauth2Params struct {
	grantType     string
	tokenEndpoint string
	clientID      string
	clientSecret  string
	username      string
	password      string
	scope         string
}

// Policy authenticates outbound requests to an upstream backend using
// OAuth2 before they are forwarded. It is grant-type agnostic: grantType
// selects which grant is used to obtain a token. client_credentials
// (RFC 6749 Section 4.4) and password (RFC 6749 Section 4.3) are both
// implemented.
type Policy struct {
	grantType     string
	tokenEndpoint string
	clientID      string

	// tokenSource supplies a cached, automatically-refreshed access token.
	// Built once in GetPolicy and reused across requests. xoauth2.ReuseTokenSource
	// guards its cached token with its own internal mutex, so concurrent
	// Token() calls are safe and a refresh in flight is not duplicated by a
	// second concurrent caller (they block on the same lock and observe the
	// freshly-refreshed token instead of firing a second request).
	tokenSource xoauth2.TokenSource

	// Test seam — production code calls tokenSource.Token() directly; unit
	// tests override this to avoid a real network call to a token endpoint,
	// mirroring the retrieveCredentialsFunc pattern used in the
	// aws-authentication policy. xoauth2.TokenSource.Token() takes no context —
	// the context passed at token-source construction time is what an
	// eventual HTTP call would use.
	tokenFunc func() (*xoauth2.Token, error)
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	slog.Debug("OAuth2: constructing policy from params")

	p, err := validateAndExtractParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	slog.Debug("OAuth2: validated params",
		"grantType", p.grantType, "tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID)

	tokenSource, err := buildTokenSource(p)
	if err != nil {
		return nil, err
	}

	pol := &Policy{
		grantType:     p.grantType,
		tokenEndpoint: p.tokenEndpoint,
		clientID:      p.clientID,
		tokenSource:   tokenSource,
	}
	pol.tokenFunc = pol.tokenSource.Token

	slog.Debug("OAuth2: policy initialized",
		"grantType", pol.grantType, "tokenEndpoint", pol.tokenEndpoint, "clientId", pol.clientID)

	return pol, nil
}

// buildTokenSource constructs the token source for the given grantType.
// This is the extension point for future grants: each grant gets its own
// case here, building whatever xoauth2.TokenSource fits that grant's flow.
func buildTokenSource(p oauth2Params) (xoauth2.TokenSource, error) {
	var scopes []string
	if p.scope != "" {
		scopes = strings.Fields(p.scope)
	}

	switch p.grantType {
	case GrantTypeClientCredentials:
		cfg := &clientcredentials.Config{
			ClientID:     p.clientID,
			ClientSecret: p.clientSecret,
			TokenURL:     p.tokenEndpoint,
			AuthStyle:    xoauth2.AuthStyleInHeader,
			Scopes:       scopes,
		}
		return cfg.TokenSource(context.Background()), nil

	case GrantTypePassword:
		cfg := &xoauth2.Config{
			ClientID:     p.clientID,
			ClientSecret: p.clientSecret,
			Endpoint: xoauth2.Endpoint{
				TokenURL:  p.tokenEndpoint,
				AuthStyle: xoauth2.AuthStyleInHeader,
			},
			Scopes: scopes,
		}
		// oauth2.Config.TokenSource(ctx, initialToken) only knows how to
		// refresh via a refresh_token grant, which the password grant's
		// response may not include. passwordTokenSource re-authenticates
		// with username/password every time the cached token is invalid,
		// which is correct regardless of whether a refresh_token was
		// issued. Wrapping it in xoauth2.ReuseTokenSource gives it the same
		// caching/mutex-safety property clientcredentials.Config.TokenSource
		// gets for free internally.
		src := &passwordTokenSource{
			ctx:      context.Background(),
			cfg:      cfg,
			username: p.username,
			password: p.password,
		}
		return xoauth2.ReuseTokenSource(nil, src), nil

	default:
		// Unreachable in practice — validateAndExtractParams already rejects
		// any value other than the constants above — but kept as an
		// explicit guard for when a further grant is added and this switch
		// needs a matching new case.
		return nil, fmt.Errorf("unsupported grantType %q", p.grantType)
	}
}

// passwordTokenSource implements the Resource Owner Password Credentials
// grant (RFC 6749 Section 4.3) as an xoauth2.TokenSource. Token() performs a
// full re-authentication (POSTing username/password to the token endpoint)
// on every call; it is intended to be wrapped in xoauth2.ReuseTokenSource,
// which only calls through to it when the cached token is missing or
// expired.
type passwordTokenSource struct {
	ctx      context.Context
	cfg      *xoauth2.Config
	username string
	password string
}

func (s *passwordTokenSource) Token() (*xoauth2.Token, error) {
	return s.cfg.PasswordCredentialsToken(s.ctx, s.username, s.password)
}

// Mode returns the processing mode for the OAuth2 policy. Injecting a
// bearer token needs no request body inspection, so this implements the
// lighter header-phase hook rather than buffering the body the way
// aws-authentication must for SigV4 payload hashing.
func (p *Policy) Mode() policy.ProcessingMode {
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
// grantType defaults to GrantTypeClientCredentials when omitted. Fields that
// only apply to one grant (username/password for the password grant) are
// validated conditionally on the resolved grantType, since JSON Schema's
// static `required` array in policy-definition.yaml can't express
// "required only when grantType is X" (the same limitation the
// aws-authentication policy documents for its own conditional fields).
// Client authentication always uses HTTP Basic auth (RFC 6749's preferred
// client_secret_basic convention) — there is no configurable auth style.
func validateAndExtractParams(params map[string]interface{}) (oauth2Params, error) {
	var p oauth2Params

	p.grantType = getStringParam(params, "grantType")
	if p.grantType == "" {
		p.grantType = GrantTypeClientCredentials
	}
	if p.grantType != GrantTypeClientCredentials && p.grantType != GrantTypePassword {
		return oauth2Params{}, fmt.Errorf("'grantType' must be one of %q, %q", GrantTypeClientCredentials, GrantTypePassword)
	}

	var err error
	p.tokenEndpoint, err = getRequiredStringParam(params, "tokenEndpoint")
	if err != nil {
		return oauth2Params{}, err
	}
	p.clientID, err = getRequiredStringParam(params, "clientId")
	if err != nil {
		return oauth2Params{}, err
	}
	p.clientSecret, err = getRequiredStringParam(params, "clientSecret")
	if err != nil {
		return oauth2Params{}, err
	}
	p.scope = getStringParam(params, "scope")

	if p.grantType == GrantTypePassword {
		p.username, err = getRequiredStringParam(params, "username")
		if err != nil {
			return oauth2Params{}, err
		}
		p.password, err = getRequiredStringParam(params, "password")
		if err != nil {
			return oauth2Params{}, err
		}
	}

	return p, nil
}

// OnRequestHeaders fetches (or reuses a cached) access token and injects it
// as an Authorization: Bearer header before the request is forwarded to the
// upstream backend.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	slog.Debug("OAuth2: authenticating outbound request", "method", reqCtx.Method, "path", reqCtx.Path,
		"grantType", p.grantType, "tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID)

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
func (p *Policy) retrieveToken() (*xoauth2.Token, error) {
	fetch := p.tokenFunc
	if fetch == nil {
		fetch = p.tokenSource.Token
	}
	return fetch()
}

// authFailure builds a 502 Bad Gateway ImmediateResponse for gateway-side
// token-acquisition failures. 502 (not 401) is deliberate: the caller's
// request was fine — it is the gateway's own OAuth2 credentials or the
// token endpoint that failed, a gateway-to-backend problem rather than a
// client-auth rejection.
func (p *Policy) authFailure(shared *policy.SharedContext, reason string, cause error) policy.RequestHeaderAction {
	slog.Error("OAuth2: token acquisition failed", "reason", reason, "error", cause,
		"grantType", p.grantType, "tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID)

	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		CredentialID:  p.clientID,
		Properties: map[string]string{
			"grantType":     p.grantType,
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
func (p *Policy) authSuccess(shared *policy.SharedContext) {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		CredentialID:  p.clientID,
		Properties: map[string]string{
			"grantType":     p.grantType,
			"tokenEndpoint": p.tokenEndpoint,
		},
		Previous: shared.AuthContext,
	}
}
