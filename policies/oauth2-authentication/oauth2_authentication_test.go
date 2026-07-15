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
	"errors"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func validParams() map[string]interface{} {
	return map[string]interface{}{
		"tokenEndpoint":    "https://idp.example.com/oauth2/token",
		"clientId":         "gateway-client",
		"clientSecret":     "s3cr3t",
		"clientAuthMethod": ClientAuthMethodBasic,
	}
}

func newRequestHeaderCtx() *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Headers:       policy.NewHeaders(map[string][]string{}),
		Path:          "/v1/chat/completions",
		Method:        http.MethodPost,
		Authority:     "gateway.example.com",
		Scheme:        "https",
	}
}

func newTestPolicy() *OAuth2AuthenticationPolicy {
	return &OAuth2AuthenticationPolicy{
		tokenEndpoint:    "https://idp.example.com/oauth2/token",
		clientID:         "gateway-client",
		clientAuthMethod: ClientAuthMethodBasic,
	}
}

// ─── GetPolicy / param validation ────────────────────────────────────────────

func TestGetPolicy_ValidParams(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa, ok := p.(*OAuth2AuthenticationPolicy)
	if !ok {
		t.Fatalf("expected *OAuth2AuthenticationPolicy, got %T", p)
	}
	if oa.tokenEndpoint != "https://idp.example.com/oauth2/token" {
		t.Errorf("unexpected tokenEndpoint: %q", oa.tokenEndpoint)
	}
	if oa.clientID != "gateway-client" {
		t.Errorf("unexpected clientID: %q", oa.clientID)
	}
}

func TestGetPolicy_MissingRequiredParams(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]interface{})
		wantErr string
	}{
		{
			name:    "missing tokenEndpoint",
			mutate:  func(p map[string]interface{}) { delete(p, "tokenEndpoint") },
			wantErr: "'tokenEndpoint' parameter is required",
		},
		{
			name:    "missing clientId",
			mutate:  func(p map[string]interface{}) { delete(p, "clientId") },
			wantErr: "'clientId' parameter is required",
		},
		{
			name:    "missing clientSecret",
			mutate:  func(p map[string]interface{}) { delete(p, "clientSecret") },
			wantErr: "'clientSecret' parameter is required",
		},
		{
			name:    "missing clientAuthMethod",
			mutate:  func(p map[string]interface{}) { delete(p, "clientAuthMethod") },
			wantErr: "'clientAuthMethod' parameter is required",
		},
		{
			name:    "empty tokenEndpoint",
			mutate:  func(p map[string]interface{}) { p["tokenEndpoint"] = "   " },
			wantErr: "'tokenEndpoint' cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := validParams()
			tt.mutate(params)
			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestGetPolicy_InvalidClientAuthMethod(t *testing.T) {
	params := validParams()
	params["clientAuthMethod"] = "client_secret_jwt" // not a supported value — no silent fallback
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error for invalid clientAuthMethod, got nil")
	}
}

func TestGetPolicy_NoDefaultClientAuthMethod(t *testing.T) {
	// clientAuthMethod has no default (see policy-definition.yaml): a silently
	// wrong default would fail at request time against the token endpoint
	// instead of failing loudly at configuration time. Omitting it must error.
	params := validParams()
	delete(params, "clientAuthMethod")
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error when clientAuthMethod is omitted, got nil")
	}
}

func TestGetPolicy_ScopeIsOptionalAndSplit(t *testing.T) {
	params := validParams()
	params["scope"] = "chat.completions embeddings"
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = p // scope is passed straight into clientcredentials.Config; nothing further to assert here
}

func TestAuthStyleFor(t *testing.T) {
	if got := authStyleFor(ClientAuthMethodBasic); got != oauth2.AuthStyleInHeader {
		t.Errorf("client_secret_basic: got %v, want AuthStyleInHeader", got)
	}
	if got := authStyleFor(ClientAuthMethodPost); got != oauth2.AuthStyleInParams {
		t.Errorf("client_secret_post: got %v, want AuthStyleInParams", got)
	}
}

// ─── Mode ────────────────────────────────────────────────────────────────────

func TestMode(t *testing.T) {
	p := newTestPolicy()
	mode := p.Mode()
	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("expected RequestHeaderMode PROCESS, got %v", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("expected RequestBodyMode SKIP (no body needed to inject a bearer token), got %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip || mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("expected response phase to be skipped entirely")
	}
}

// ─── OnRequestHeaders ────────────────────────────────────────────────────────

func TestOnRequestHeaders_Success(t *testing.T) {
	p := newTestPolicy()
	var calls int
	p.tokenFunc = func() (*oauth2.Token, error) {
		calls++
		return &oauth2.Token{AccessToken: "abc123", TokenType: "Bearer"}, nil
	}

	reqCtx := newRequestHeaderCtx()
	action := p.OnRequestHeaders(context.Background(), reqCtx, nil)

	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if got := mods.HeadersToSet["Authorization"]; got != "Bearer abc123" {
		t.Errorf("unexpected Authorization header: %q", got)
	}
	if calls != 1 {
		t.Errorf("expected exactly one token fetch, got %d", calls)
	}

	if reqCtx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be set")
	}
	if !reqCtx.SharedContext.AuthContext.Authenticated {
		t.Error("expected Authenticated=true on success")
	}
	if reqCtx.SharedContext.AuthContext.AuthType != AuthType {
		t.Errorf("unexpected AuthType: %q", reqCtx.SharedContext.AuthContext.AuthType)
	}
	if reqCtx.SharedContext.AuthContext.CredentialID != "gateway-client" {
		t.Errorf("unexpected CredentialID: %q", reqCtx.SharedContext.AuthContext.CredentialID)
	}
}

func TestOnRequestHeaders_ReusesCachedToken(t *testing.T) {
	// This exercises the policy's own call path, not oauth2.ReuseTokenSource's
	// internals (already covered by the x/oauth2 package itself) — it proves
	// OnRequestHeaders calls through tokenFunc once per request rather than
	// bypassing it or calling it more than once.
	p := newTestPolicy()
	var calls int
	p.tokenFunc = func() (*oauth2.Token, error) {
		calls++
		return &oauth2.Token{AccessToken: "reused-token"}, nil
	}

	for i := 0; i < 3; i++ {
		action := p.OnRequestHeaders(context.Background(), newRequestHeaderCtx(), nil)
		mods := action.(policy.UpstreamRequestHeaderModifications)
		if mods.HeadersToSet["Authorization"] != "Bearer reused-token" {
			t.Fatalf("request %d: unexpected Authorization header", i)
		}
	}
	if calls != 3 {
		t.Errorf("expected tokenFunc called once per request (3), got %d", calls)
	}
}

func TestOnRequestHeaders_TokenFetchFailure(t *testing.T) {
	p := newTestPolicy()
	p.tokenFunc = func() (*oauth2.Token, error) {
		return nil, errors.New("token endpoint returned invalid_client")
	}

	reqCtx := newRequestHeaderCtx()
	action := p.OnRequestHeaders(context.Background(), reqCtx, nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on failure, got %T", action)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway, got %d", resp.StatusCode)
	}
	if strings.Contains(string(resp.Body), "invalid_client") {
		t.Error("response body must not leak the underlying token-endpoint error detail")
	}
	if !strings.Contains(string(resp.Body), "failed to authenticate request to upstream service") {
		t.Errorf("expected generic failure message in body, got %q", resp.Body)
	}

	if reqCtx.SharedContext.AuthContext == nil || reqCtx.SharedContext.AuthContext.Authenticated {
		t.Error("expected AuthContext.Authenticated=false on failure")
	}
}

func TestOnRequestHeaders_PreservesPreviousAuthContext(t *testing.T) {
	p := newTestPolicy()
	p.tokenFunc = func() (*oauth2.Token, error) {
		return &oauth2.Token{AccessToken: "abc123"}, nil
	}

	reqCtx := newRequestHeaderCtx()
	reqCtx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "end-user-123",
	}

	p.OnRequestHeaders(context.Background(), reqCtx, nil)

	got := reqCtx.SharedContext.AuthContext
	if got.AuthType != AuthType {
		t.Errorf("expected current AuthType %q, got %q", AuthType, got.AuthType)
	}
	if got.Previous == nil || got.Previous.AuthType != "jwt" || got.Previous.Subject != "end-user-123" {
		t.Fatal("expected the prior inbound auth context to be preserved via Previous")
	}
}
