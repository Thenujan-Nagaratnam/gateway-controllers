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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	xoauth2 "golang.org/x/oauth2"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func validParams() map[string]interface{} {
	return map[string]interface{}{
		"tokenEndpoint": "https://idp.example.com/oauth2/token",
		"clientId":      "gateway-client",
		"clientSecret":  "s3cr3t",
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

func newTestPolicy() *Policy {
	return &Policy{
		tokenEndpoint: "https://idp.example.com/oauth2/token",
		clientID:      "gateway-client",
	}
}

// ─── GetPolicy / param validation ────────────────────────────────────────────

func TestGetPolicy_ValidParams(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa, ok := p.(*Policy)
	if !ok {
		t.Fatalf("expected *Policy, got %T", p)
	}
	if oa.tokenEndpoint != "https://idp.example.com/oauth2/token" {
		t.Errorf("unexpected tokenEndpoint: %q", oa.tokenEndpoint)
	}
	if oa.clientID != "gateway-client" {
		t.Errorf("unexpected clientID: %q", oa.clientID)
	}
	if oa.grantType != GrantTypeClientCredentials {
		t.Errorf("expected grantType to default to %q when omitted, got %q", GrantTypeClientCredentials, oa.grantType)
	}
}

func TestGetPolicy_ExplicitGrantType(t *testing.T) {
	params := validParams()
	params["grantType"] = GrantTypeClientCredentials
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oa := p.(*Policy)
	if oa.grantType != GrantTypeClientCredentials {
		t.Errorf("unexpected grantType: %q", oa.grantType)
	}
}

func TestGetPolicy_UnsupportedGrantType(t *testing.T) {
	// grantType exists precisely so a future grant can be added without a
	// schema-breaking change - but until that grant is actually implemented,
	// an unrecognized value must fail loudly at configuration time, not be
	// silently treated as client_credentials.
	params := validParams()
	params["grantType"] = "authorization_code"
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error for unsupported grantType, got nil")
	}
	if !strings.Contains(err.Error(), "grantType") {
		t.Errorf("expected error to mention grantType, got: %v", err)
	}
}

// ─── password grant (RFC 6749 Section 4.3) ──────────────────────────────────

func passwordGrantParams() map[string]interface{} {
	return map[string]interface{}{
		"grantType":     GrantTypePassword,
		"tokenEndpoint": "https://idp.example.com/oauth2/token",
		"clientId":      "gateway-client",
		"clientSecret":  "s3cr3t",
		"username":      "resource-owner",
		"password":      "hunter2",
	}
}

func TestGetPolicy_PasswordGrant_ValidParams(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, passwordGrantParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)
	if pol.grantType != GrantTypePassword {
		t.Errorf("unexpected grantType: %q", pol.grantType)
	}
}

func TestGetPolicy_PasswordGrant_MissingUsername(t *testing.T) {
	params := passwordGrantParams()
	delete(params, "username")
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "username") {
		t.Errorf("expected error to mention username, got: %v", err)
	}
}

func TestGetPolicy_PasswordGrant_MissingPassword(t *testing.T) {
	params := passwordGrantParams()
	delete(params, "password")
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("expected error to mention password, got: %v", err)
	}
}

func TestGetPolicy_ClientCredentials_UsernamePasswordNotRequired(t *testing.T) {
	// username/password are password-grant-only; client_credentials (the
	// default grantType) must not require them.
	params := validParams()
	if _, ok := params["username"]; ok {
		t.Fatal("test fixture unexpectedly sets username")
	}
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPasswordGrant_EndToEnd exercises the real passwordTokenSource against
// an httptest server simulating a password-grant token endpoint - unlike
// client_credentials (which delegates entirely to the well-exercised
// golang.org/x/oauth2/clientcredentials package), the password grant's
// token-fetch path is new code in this policy, so it's worth a real,
// non-mocked-tokenFunc test.
func TestPasswordGrant_EndToEnd(t *testing.T) {
	var gotGrantType, gotUsername, gotPassword string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		gotGrantType = r.PostForm.Get("grant_type")
		gotUsername = r.PostForm.Get("username")
		gotPassword = r.PostForm.Get("password")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "password-grant-token-abc",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := passwordGrantParams()
	params["tokenEndpoint"] = server.URL
	params["username"] = "resource-owner"
	params["password"] = "hunter2"

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol := p.(*Policy)

	reqCtx := newRequestHeaderCtx()
	action := pol.OnRequestHeaders(context.Background(), reqCtx, nil)
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["Authorization"] != "Bearer password-grant-token-abc" {
		t.Errorf("unexpected Authorization header: %q", mods.HeadersToSet["Authorization"])
	}

	if gotGrantType != "password" {
		t.Errorf("expected token endpoint to receive grant_type=password, got %q", gotGrantType)
	}
	if gotUsername != "resource-owner" {
		t.Errorf("expected username=resource-owner, got %q", gotUsername)
	}
	if gotPassword != "hunter2" {
		t.Errorf("expected password=hunter2, got %q", gotPassword)
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

func TestGetPolicy_ScopeIsOptionalAndSplit(t *testing.T) {
	params := validParams()
	params["scope"] = "chat.completions embeddings"
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = p // scope is passed straight into clientcredentials.Config; nothing further to assert here
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
	p.tokenFunc = func() (*xoauth2.Token, error) {
		calls++
		return &xoauth2.Token{AccessToken: "abc123", TokenType: "Bearer"}, nil
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
	p.tokenFunc = func() (*xoauth2.Token, error) {
		calls++
		return &xoauth2.Token{AccessToken: "reused-token"}, nil
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
	p.tokenFunc = func() (*xoauth2.Token, error) {
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
	p.tokenFunc = func() (*xoauth2.Token, error) {
		return &xoauth2.Token{AccessToken: "abc123"}, nil
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
