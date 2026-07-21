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

package upstreamoauth2authentication

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	xoauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// defaultTokenRequestTimeout bounds how long a single token-endpoint
	// HTTP call is allowed to take. Without this, golang.org/x/oauth2 falls
	// back to http.DefaultClient, which has no timeout at all, so a hung
	// IdP would block a token fetch indefinitely.
	defaultTokenRequestTimeout = 10 * time.Second

	// defaultTokenTTLFallback is applied when the token endpoint's response
	// omits expires_in. golang.org/x/oauth2 leaves Token.Expiry as the zero
	// value in that case, which Token.Valid() always treats as
	// already-expired - without this fallback, the token would never be
	// cached and every request would refetch it.
	defaultTokenTTLFallback = time.Hour
)

// defaultPurgeStatusCodes is applied when tokenPurgeStatusCodes is
// omitted. 401 is the standard signal (RFC 6750 Section 3) that a bearer
// token was rejected as invalid - as opposed to e.g. 403, which usually
// means insufficient scope for an otherwise-valid token and would gain
// nothing from a purge.
var defaultPurgeStatusCodes = []int{http.StatusUnauthorized}

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
	// Grant-agnostic by design: it identifies authentication via OAuth2 in
	// general. The specific grant used is available separately via
	// AuthContext.Properties["grantType"].
	AuthType = "oauth2"

	// ClientAuthMethodBasic (client_secret_basic) presents the client ID and
	// secret via the HTTP Basic Authorization header. RFC 6749's preferred
	// convention when the identity provider supports it, and this policy's
	// default.
	ClientAuthMethodBasic = "client_secret_basic"

	// ClientAuthMethodPost (client_secret_post) presents the client ID and
	// secret as client_id/client_secret fields in the token request's form
	// body instead of the Basic header - some identity providers require
	// this instead of (or as well as) client_secret_basic.
	ClientAuthMethodPost = "client_secret_post"
)

// oauth2Params bundles all extracted, validated policy params. Passed as a
// single struct (rather than positional args) now that the set has grown
// with grantType-conditional fields (username/password) — positional args
// for six-plus mostly-string fields invite mixed-up-order bugs.
type oauth2Params struct {
	grantType        string
	tokenEndpoint    string
	clientID         string
	clientSecret     string
	clientAuthMethod string
	username         string
	password         string

	// customParams comes from the "params" policy parameter. For
	// client_credentials, golang.org/x/oauth2/clientcredentials exposes an
	// EndpointParams hook that carries the whole map into the token request
	// body. For password, only a "scope" entry has any effect - mapped to
	// xoauth2.Config.Scopes, the one extensibility point
	// PasswordCredentialsToken actually has; every other key is ignored for
	// this grant - see buildTokenSource.
	customParams map[string]string

	// requestTimeout bounds the token-endpoint HTTP call - see
	// defaultTokenRequestTimeout.
	requestTimeout time.Duration

	// tokenTTLFallback is applied by the caching layer when the token
	// endpoint's response omits expires_in - see defaultTokenTTLFallback.
	tokenTTLFallback time.Duration

	// purgeStatusCodes are the upstream response status codes that purge the
	// cached token - see OnResponseHeaders and defaultPurgeStatusCodes.
	purgeStatusCodes map[int]struct{}
}

// Policy authenticates outbound requests to an upstream backend using
// OAuth2 before they are forwarded. It is grant-type agnostic: grantType
// selects which grant is used to obtain a token. client_credentials
// (RFC 6749 Section 4.4) and password (RFC 6749 Section 4.3) are both
// implemented.
type Policy struct {
	grantType        string
	tokenEndpoint    string
	clientID         string
	clientAuthMethod string

	// tokenSource supplies a cached, automatically-refreshed access token.
	// Built once in GetPolicy: a *redisCachingTokenSource (token_cache.go)
	// wrapping the grant-specific fetch logic from buildTokenSource with a
	// two-tier cache (in-process, then Redis) in front of the token
	// endpoint.
	tokenSource tokenProvider

	// Test seam — production code calls tokenSource.Token() directly; unit
	// tests override this to avoid a real network call to a token endpoint,
	// mirroring the retrieveCredentialsFunc pattern used in the
	// aws-authentication policy.
	tokenFunc func() (*xoauth2.Token, error)

	// purgeStatusCodes are the upstream response status codes that purge the
	// cached token via tokenSource.Purge() - see OnResponseHeaders. Empty
	// (explicitly set to []) disables response-phase processing entirely -
	// see Mode().
	purgeStatusCodes map[int]struct{}
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
// metadata is part of the v1alpha2 factory signature but unused here: the
// Redis cache key is derived entirely from params (see
// oauth2ConfigDiscriminator in token_cache.go).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	slog.Debug("OAuth2: constructing policy from params")

	p, err := validateAndExtractParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	slog.Debug("OAuth2: validated params",
		"grantType", p.grantType, "tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID,
		"clientAuthMethod", p.clientAuthMethod)

	innerSource, err := buildTokenSource(p)
	if err != nil {
		return nil, err
	}
	tokenSource := newRedisCachingTokenSource(innerSource, extractRedisParams(params), p)

	pol := &Policy{
		grantType:        p.grantType,
		tokenEndpoint:    p.tokenEndpoint,
		clientID:         p.clientID,
		clientAuthMethod: p.clientAuthMethod,
		tokenSource:      tokenSource,
		purgeStatusCodes: p.purgeStatusCodes,
	}
	pol.tokenFunc = pol.tokenSource.Token

	slog.Debug("OAuth2: policy initialized",
		"grantType", pol.grantType, "tokenEndpoint", pol.tokenEndpoint, "clientId", pol.clientID,
		"clientAuthMethod", pol.clientAuthMethod)

	return pol, nil
}

// buildTokenSource constructs the token source for the given grantType.
// This is the extension point for future grants: each grant gets its own
// case here, building whatever xoauth2.TokenSource fits that grant's flow.
func buildTokenSource(p oauth2Params) (xoauth2.TokenSource, error) {
	authStyle := authStyleFor(p.clientAuthMethod)

	// Both clientcredentials.Config.TokenSource and
	// xoauth2.Config.PasswordCredentialsToken forward their ctx down to
	// internal.RetrieveToken, which resolves the *http.Client to use via
	// internal.ContextClient(ctx) - falling back to http.DefaultClient (no
	// timeout) if nothing is set on the context. Injecting a bounded client
	// here, once, covers both grants identically.
	ctx := context.WithValue(context.Background(), xoauth2.HTTPClient, &http.Client{Timeout: p.requestTimeout})

	switch p.grantType {
	case GrantTypeClientCredentials:
		cfg := &clientcredentials.Config{
			ClientID:     p.clientID,
			ClientSecret: p.clientSecret,
			TokenURL:     p.tokenEndpoint,
			AuthStyle:    authStyle,
			// EndpointParams carries customParams (e.g. scope) verbatim into
			// the token request body - golang.org/x/oauth2/clientcredentials
			// exposes this hook directly, so client_credentials keeps using
			// the library's own request/response handling untouched.
			EndpointParams: toURLValues(p.customParams),
		}
		return cfg.TokenSource(ctx), nil

	case GrantTypePassword:
		cfg := &xoauth2.Config{
			ClientID:     p.clientID,
			ClientSecret: p.clientSecret,
			Endpoint: xoauth2.Endpoint{
				TokenURL:  p.tokenEndpoint,
				AuthStyle: authStyle,
			},
		}
		// oauth2.Config.PasswordCredentialsToken has no EndpointParams-style
		// hook for arbitrary extra fields - its form body is hardcoded to
		// grant_type/username/password, plus scope if Config.Scopes is set.
		// scope is therefore the one customParams entry this grant can
		// honor; anything else in customParams (audience, resource, tenant,
		// ...) has no effect here - see oauth2Params.customParams. Space-
		// delimited per RFC 6749 Section 3.3.
		if scope := p.customParams["scope"]; scope != "" {
			cfg.Scopes = strings.Fields(scope)
		}
		src := &passwordTokenSource{
			ctx:      ctx,
			cfg:      cfg,
			username: p.username,
			password: p.password,
		}
		// oauth2.Config.TokenSource(ctx, initialToken) only refreshes via a
		// refresh_token grant, which the password grant's response may not
		// include, so passwordTokenSource re-authenticates with
		// username/password instead. Wrapping it in xoauth2.ReuseTokenSource
		// gives it the same caching/mutex-safety clientcredentials gets for
		// free internally.
		return xoauth2.ReuseTokenSource(nil, src), nil

	default:
		// Unreachable in practice — validateAndExtractParams already rejects
		// any value other than the constants above — but kept as an
		// explicit guard for when a further grant is added and this switch
		// needs a matching new case.
		return nil, fmt.Errorf("unsupported grantType %q", p.grantType)
	}
}

// authStyleFor maps clientAuthMethod to the xoauth2.AuthStyle both
// clientcredentials.Config.AuthStyle and xoauth2.Config.Endpoint.AuthStyle
// consume identically under the hood (see golang.org/x/oauth2/internal's
// newTokenRequest): AuthStyleInHeader sends the client ID/secret via HTTP
// Basic auth (client_secret_basic); AuthStyleInParams sends them as
// client_id/client_secret fields in the token request's form body
// (client_secret_post). Since both grants delegate to the same internal
// function, this single mapping covers both without any hand-built HTTP
// code. validateAndExtractParams already rejects any value other than the
// two ClientAuthMethod* constants, so the default case is unreachable.
func authStyleFor(method string) xoauth2.AuthStyle {
	switch method {
	case ClientAuthMethodPost:
		return xoauth2.AuthStyleInParams
	default:
		return xoauth2.AuthStyleInHeader
	}
}

// toURLValues converts a flat string map into url.Values, the shape
// golang.org/x/oauth2/clientcredentials.Config.EndpointParams expects.
// Returns nil (not an empty, non-nil map) when there's nothing to add, so
// EndpointParams stays unset rather than an empty-but-present value.
func toURLValues(m map[string]string) url.Values {
	if len(m) == 0 {
		return nil
	}
	v := make(url.Values, len(m))
	for key, val := range m {
		v.Set(key, val)
	}
	return v
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
// aws-authentication must for SigV4 payload hashing. Response headers are
// processed only when purgeStatusCodes is non-empty (see OnResponseHeaders)
// - the status code is available at the response-header phase, so neither
// case needs the response body, keeping this safe for streamed upstream
// responses.
func (p *Policy) Mode() policy.ProcessingMode {
	responseHeaderMode := policy.HeaderModeSkip
	if len(p.purgeStatusCodes) > 0 {
		responseHeaderMode = policy.HeaderModeProcess
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: responseHeaderMode,
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

// getDurationParam extracts an optional Go-duration-formatted string
// parameter (e.g. "10s", "1h"), falling back to def if the key is absent,
// the wrong type, or unparsable - matching this policy's other optional
// fields' permissive, best-effort extraction style.
func getDurationParam(params map[string]interface{}, key string, def time.Duration) time.Duration {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(str)); err == nil {
				return d
			}
		}
	}
	return def
}

// getCustomParams extracts the "params" map - additional form fields (e.g.
// scope) sent verbatim to the token endpoint alongside grant_type and the
// grant's own fields. Absent or wrong-shaped input just yields no extra
// params rather than an error, matching how the other optional fields in
// this policy behave.
func getCustomParams(params map[string]interface{}) map[string]string {
	raw, ok := params["params"]
	if !ok {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				out[k] = trimmed
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getPurgeStatusCodesParam extracts "tokenPurgeStatusCodes" - the
// upstream response status codes that purge the cached token (see
// OnResponseHeaders). Absent or wrong-shaped input falls back to def
// (defaultPurgeStatusCodes), matching this policy's other optional fields.
// An explicit empty list ([]), unlike an absent key, is honored as-is - it
// disables response-phase purging entirely rather than falling back to the
// default, since that's the only way to opt out.
func getPurgeStatusCodesParam(params map[string]interface{}, key string, def []int) map[int]struct{} {
	codes := def
	if raw, ok := params[key]; ok {
		if arr, ok := raw.([]interface{}); ok {
			parsed := make([]int, 0, len(arr))
			for _, v := range arr {
				switch n := v.(type) {
				case int:
					parsed = append(parsed, n)
				case int64:
					parsed = append(parsed, int(n))
				case float64:
					parsed = append(parsed, int(n))
				case string:
					if code, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
						parsed = append(parsed, code)
					}
				}
			}
			codes = parsed
		}
	}
	set := make(map[int]struct{}, len(codes))
	for _, c := range codes {
		set[c] = struct{}{}
	}
	return set
}

// validateAndExtractParams validates and extracts all policy params.
// grantType defaults to GrantTypeClientCredentials when omitted. Fields that
// only apply to one grant (username/password for the password grant) are
// validated conditionally on the resolved grantType, since JSON Schema's
// static `required` array in policy-definition.yaml can't express
// "required only when grantType is X" (the same limitation the
// aws-authentication policy documents for its own conditional fields).
// clientAuthMethod defaults to client_secret_basic (RFC 6749's preferred
// convention) and applies identically to both grants.
func validateAndExtractParams(params map[string]interface{}) (oauth2Params, error) {
	var p oauth2Params

	p.grantType = getStringParam(params, "grantType")
	if p.grantType == "" {
		p.grantType = GrantTypeClientCredentials
	}
	if p.grantType != GrantTypeClientCredentials && p.grantType != GrantTypePassword {
		return oauth2Params{}, fmt.Errorf("'grantType' must be one of %q, %q", GrantTypeClientCredentials, GrantTypePassword)
	}

	p.clientAuthMethod = getStringParam(params, "clientAuthMethod")
	if p.clientAuthMethod == "" {
		p.clientAuthMethod = ClientAuthMethodBasic
	}
	if p.clientAuthMethod != ClientAuthMethodBasic && p.clientAuthMethod != ClientAuthMethodPost {
		return oauth2Params{}, fmt.Errorf("'clientAuthMethod' must be one of %q, %q", ClientAuthMethodBasic, ClientAuthMethodPost)
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
	p.customParams = getCustomParams(params)
	p.requestTimeout = getDurationParam(params, "tokenRequestTimeout", defaultTokenRequestTimeout)
	p.tokenTTLFallback = getDurationParam(params, "defaultTokenTTL", defaultTokenTTLFallback)
	p.purgeStatusCodes = getPurgeStatusCodesParam(params, "tokenPurgeStatusCodes", defaultPurgeStatusCodes)

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

// OnResponseHeaders purges the cached token when the upstream backend
// responds with one of purgeStatusCodes (default: 401) - a signal that the
// token this policy just injected was rejected, e.g. revoked out-of-band at
// the identity provider. This does not retry the current request, which
// still completes with whatever the upstream returned; purging only
// guarantees the next request fetches a fresh token instead of reusing the
// same one that just failed. Only reached when Mode() enables response
// header processing, i.e. purgeStatusCodes is non-empty.
func (p *Policy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if _, purge := p.purgeStatusCodes[respCtx.ResponseStatus]; purge {
		slog.Warn("OAuth2: upstream rejected the cached token, purging it for the next request",
			"status", respCtx.ResponseStatus, "grantType", p.grantType, "tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID)
		p.tokenSource.Purge()
	}
	return policy.DownstreamResponseHeaderModifications{}
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
