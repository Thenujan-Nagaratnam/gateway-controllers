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

package azuremanagedidentity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xoauth2 "golang.org/x/oauth2"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func validParams() map[string]interface{} {
	return map[string]interface{}{
		"clientId": "11111111-1111-1111-1111-111111111111",
		"resource": "https://cognitiveservices.azure.com/",
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
		clientID: "11111111-1111-1111-1111-111111111111",
		resource: "https://cognitiveservices.azure.com/",
	}
}

// ─── GetPolicy / param validation ────────────────────────────────────────────

func TestGetPolicy_ValidParams(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, validParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, ok := p.(*Policy)
	if !ok {
		t.Fatalf("expected *Policy, got %T", p)
	}
	if pol.clientID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("unexpected clientID: %q", pol.clientID)
	}
	if pol.resource != "https://cognitiveservices.azure.com/" {
		t.Errorf("unexpected resource: %q", pol.resource)
	}
}

func TestGetPolicy_MissingClientId(t *testing.T) {
	params := validParams()
	delete(params, "clientId")
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "clientId") {
		t.Errorf("expected error to mention clientId, got: %v", err)
	}
}

func TestGetPolicy_MissingResource(t *testing.T) {
	params := validParams()
	delete(params, "resource")
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "resource") {
		t.Errorf("expected error to mention resource, got: %v", err)
	}
}

func TestGetPolicy_EmptyClientId(t *testing.T) {
	params := validParams()
	params["clientId"] = "   "
	_, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err == nil {
		t.Fatal("expected error for empty clientId, got nil")
	}
}

// ─── imdsTokenSource ─────────────────────────────────────────────────────────

func TestImdsTokenSource_Success(t *testing.T) {
	var gotMetadataHeader, gotAPIVersion, gotResource, gotClientID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMetadataHeader = r.Header.Get("Metadata")
		gotAPIVersion = r.URL.Query().Get("api-version")
		gotResource = r.URL.Query().Get("resource")
		gotClientID = r.URL.Query().Get("client_id")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "imds-token-abc",
			"client_id": "11111111-1111-1111-1111-111111111111",
			"expires_on": "` + fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()) + `",
			"resource": "https://cognitiveservices.azure.com/",
			"token_type": "Bearer"
		}`))
	}))
	defer server.Close()

	src := &imdsTokenSource{
		httpClient: &http.Client{Timeout: time.Second},
		endpoint:   server.URL,
		clientID:   "11111111-1111-1111-1111-111111111111",
		resource:   "https://cognitiveservices.azure.com/",
	}

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "imds-token-abc" {
		t.Errorf("unexpected access token: %q", tok.AccessToken)
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("unexpected token type: %q", tok.TokenType)
	}
	if !tok.Expiry.After(time.Now()) {
		t.Errorf("expected expiry in the future, got %v", tok.Expiry)
	}

	if gotMetadataHeader != "true" {
		t.Errorf("expected Metadata: true header, got %q", gotMetadataHeader)
	}
	if gotAPIVersion != imdsAPIVersion {
		t.Errorf("expected api-version=%q, got %q", imdsAPIVersion, gotAPIVersion)
	}
	if gotResource != "https://cognitiveservices.azure.com/" {
		t.Errorf("unexpected resource sent: %q", gotResource)
	}
	if gotClientID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("unexpected client_id sent: %q", gotClientID)
	}
}

func TestImdsTokenSource_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
	}))
	defer server.Close()

	src := &imdsTokenSource{
		httpClient: &http.Client{Timeout: time.Second},
		endpoint:   server.URL,
		clientID:   "id",
		resource:   "res",
	}
	_, err := src.Token()
	if err == nil {
		t.Fatal("expected error for non-200 IMDS response, got nil")
	}
}

func TestImdsTokenSource_MissingAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_on":"9999999999"}`))
	}))
	defer server.Close()

	src := &imdsTokenSource{
		httpClient: &http.Client{Timeout: time.Second},
		endpoint:   server.URL,
		clientID:   "id",
		resource:   "res",
	}
	_, err := src.Token()
	if err == nil {
		t.Fatal("expected error for response missing access_token, got nil")
	}
}

func TestImdsTokenSource_InvalidExpiresOn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_on":"not-a-number"}`))
	}))
	defer server.Close()

	src := &imdsTokenSource{
		httpClient: &http.Client{Timeout: time.Second},
		endpoint:   server.URL,
		clientID:   "id",
		resource:   "res",
	}
	_, err := src.Token()
	if err == nil {
		t.Fatal("expected error for unparseable expires_on, got nil")
	}
}

func TestImdsTokenSource_Unreachable(t *testing.T) {
	src := &imdsTokenSource{
		httpClient: &http.Client{Timeout: 200 * time.Millisecond},
		endpoint:   "http://127.0.0.1:1", // nothing listens here
		clientID:   "id",
		resource:   "res",
	}
	_, err := src.Token()
	if err == nil {
		t.Fatal("expected error for unreachable IMDS endpoint, got nil")
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
		t.Errorf("expected RequestBodyMode SKIP, got %v", mode.RequestBodyMode)
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
}

func TestOnRequestHeaders_TokenFetchFailure(t *testing.T) {
	p := newTestPolicy()
	p.tokenFunc = func() (*xoauth2.Token, error) {
		return nil, errors.New("IMDS returned status 400")
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
	if strings.Contains(string(resp.Body), "IMDS returned status") {
		t.Error("response body must not leak the underlying IMDS error detail")
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
