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

package oauth2generator

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/wso2/api-platform/sdk/core/utils/redisclient"
	xoauth2 "golang.org/x/oauth2"
)

// ─── test helpers ────────────────────────────────────────────────────────────

// stubTokenSource is a fake "real" token source (standing in for
// buildTokenSource's clientcredentials/password fetch) that counts calls so
// tests can assert the Redis/local cache actually prevented a fetch, rather
// than just happening to return the right value.
type stubTokenSource struct {
	calls int
	token *xoauth2.Token
	err   error
}

func (s *stubTokenSource) Token() (*xoauth2.Token, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.token, nil
}

// mustNewRedisCachingTokenSource wraps newRedisCachingTokenSource for tests
// that expect construction to succeed - the vast majority, since a cacheParams
// fixture normally sets either redisOverride or nothing at all (memory
// strategy, which never calls redisclient.Resolve in the first place).
func mustNewRedisCachingTokenSource(t *testing.T, inner xoauth2.TokenSource, cp cacheParams, p oauth2Params) tokenProvider {
	t.Helper()
	src, err := newRedisCachingTokenSource(inner, cp, p)
	if err != nil {
		t.Fatalf("unexpected error constructing token source: %v", err)
	}
	return src
}

// testRedisParams returns a cacheParams fixture with strategy: redis,
// policy-level-overridden to point at mr - for tests that specifically
// exercise the Redis tier. Tests that only care about the in-process tier
// (the default) use testParams() alone and never call this.
func testRedisParams(mr *miniredis.Miniredis, failureMode string) cacheParams {
	return cacheParams{
		strategy: CacheStrategyRedis,
		redisOverride: &redis.Options{
			Addr:         mr.Addr(),
			DialTimeout:  time.Second,
			ReadTimeout:  time.Second,
			WriteTimeout: time.Second,
		},
		keyPrefix:   "oauth2-generator:token:v1:",
		failureMode: failureMode,
	}
}

// testParams returns a baseline, valid oauth2Params fixture for tests that
// only care about the cache-key/caching behavior, not param validation.
// Pass mutate funcs to override individual fields for a specific case.
func testParams(mutate ...func(*oauth2Params)) oauth2Params {
	p := oauth2Params{
		grantType:        GrantTypeClientCredentials,
		tokenEndpoint:    "https://idp.example.com/token",
		clientID:         "client-a",
		clientSecret:     "s3cr3t",
		clientAuthMethod: ClientAuthMethodBasic,
		tokenTTLFallback: defaultTokenTTLFallback,
	}
	for _, m := range mutate {
		m(&p)
	}
	return p
}

// ─── oauth2ConfigDiscriminator ──────────────────────────────────────────────

func TestOauth2ConfigDiscriminator_IdenticalConfig_ProducesSameKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams())
	b := oauth2ConfigDiscriminator(testParams())
	if a != b {
		t.Errorf("expected identical oauth2 config to produce the same discriminator, got %q vs %q", a, b)
	}
}

func TestOauth2ConfigDiscriminator_DifferentClientID_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams())
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.clientID = "client-b" }))
	if a == b {
		t.Error("expected a different clientId to produce a different discriminator")
	}
}

func TestOauth2ConfigDiscriminator_DifferentTokenEndpoint_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams())
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.tokenEndpoint = "https://idp-b.example.com/token" }))
	if a == b {
		t.Error("expected a different tokenEndpoint to produce a different discriminator")
	}
}

func TestOauth2ConfigDiscriminator_DifferentGrantType_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.grantType = GrantTypeClientCredentials }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) {
		p.grantType = GrantTypePassword
		p.username = "bob"
	}))
	if a == b {
		t.Error("expected a different grantType to produce a different discriminator")
	}
}

func TestOauth2ConfigDiscriminator_DifferentUsername_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.username = "alice" }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.username = "bob" }))
	if a == b {
		t.Error("expected a different username (password grant) to produce a different discriminator")
	}
}

// TestOauth2ConfigDiscriminator_DifferentClientAuthMethod_ProducesDifferentKey
// locks in that clientAuthMethod (client_secret_basic vs client_secret_post)
// is part of the discriminator: it's plausible for two configs to share
// every other field yet differ only in how credentials are presented to the
// token endpoint (e.g. one IdP integration migrating from Basic auth to
// POST body auth) - those requests aren't necessarily equivalent from the
// IdP's perspective, so treating them as separate cache entries is the safe
// default.
func TestOauth2ConfigDiscriminator_DifferentClientAuthMethod_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.clientAuthMethod = ClientAuthMethodBasic }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.clientAuthMethod = ClientAuthMethodPost }))
	if a == b {
		t.Error("expected a different clientAuthMethod to produce a different discriminator")
	}
}

// TestOauth2ConfigDiscriminator_NilVsEmptyCustomParams_ProducesSameKey locks
// in that a config with no "tokenRequestParams" set at all (customParams ==
// nil, the client_credentials/no-scope common case) and one with an
// explicitly empty "tokenRequestParams": {} are indistinguishable - both
// mean "no extra token-request fields" and must land on the same cache
// entry, not two different ones for what is operationally the same
// configuration.
func TestOauth2ConfigDiscriminator_NilVsEmptyCustomParams_ProducesSameKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.tokenRequestParams = nil }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.tokenRequestParams = map[string]string{} }))
	if a != b {
		t.Error("expected nil and empty customParams to produce the same discriminator")
	}
}

// TestOauth2ConfigDiscriminator_DifferentScope_ProducesDifferentKey locks in
// the exact bug this discriminator fixes: a proxy's primary provider and an
// additionalProviders entry can share clientId/tokenEndpoint but request
// different scopes (or point at genuinely different providers) - those must
// never share a cached token.
func TestOauth2ConfigDiscriminator_DifferentScope_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.tokenRequestParams = map[string]string{"scope": "read"} }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.tokenRequestParams = map[string]string{"scope": "write"} }))
	if a == b {
		t.Error("expected different scope (via customParams) to produce a different discriminator")
	}
}

func TestOauth2ConfigDiscriminator_ParamsKeyOrder_ProducesSameKey(t *testing.T) {
	// encoding/json sorts map keys when marshaling - locks in that the
	// discriminator doesn't depend on incidental map iteration order.
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) {
		p.tokenRequestParams = map[string]string{"scope": "read", "audience": "api-a"}
	}))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) {
		p.tokenRequestParams = map[string]string{"audience": "api-a", "scope": "read"}
	}))
	if a != b {
		t.Error("expected customParams map iteration order not to affect the discriminator")
	}
}

// TestOauth2ConfigDiscriminator_DifferentClientSecret_ProducesDifferentKey is
// the regression test for a real bug found via a live end-to-end run: a
// second LlmProvider registered with the same clientId/tokenEndpoint as an
// existing one but a deliberately wrong clientSecret (to test that bad
// credentials are rejected) was instead served the OTHER provider's
// legitimately-cached token from Redis and spuriously succeeded - because an
// earlier version of oauth2ConfigDiscriminator deliberately left clientSecret
// out of the key. clientId and tokenEndpoint alone do not prove two configs
// are the same authorized caller.
func TestOauth2ConfigDiscriminator_DifferentClientSecret_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.clientSecret = "secret-1" }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.clientSecret = "secret-2" }))
	if a == b {
		t.Error("expected a different clientSecret to produce a different discriminator")
	}
}

// TestOauth2ConfigDiscriminator_DifferentPassword_ProducesDifferentKey is the
// password-grant equivalent of the clientSecret regression above: a wrong
// resource-owner password must not be able to borrow a cached token obtained
// with the correct one.
func TestOauth2ConfigDiscriminator_DifferentPassword_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.password = "hunter2" }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.password = "wrong-password" }))
	if a == b {
		t.Error("expected a different password to produce a different discriminator")
	}
}

// ─── buildRedisKey ───────────────────────────────────────────────────────────

func TestBuildRedisKey(t *testing.T) {
	key := buildRedisKey("oauth2-generator:token:v1:", "abc123")
	want := "oauth2-generator:token:v1:abc123"
	if key != want {
		t.Errorf("got %q, want %q", key, want)
	}
}

func TestBuildRedisKey_OmitsEmptyDiscriminator(t *testing.T) {
	key := buildRedisKey("oauth2-generator:token:v1:", "")
	want := "oauth2-generator:token:v1"
	if key != want {
		t.Errorf("got %q, want %q", key, want)
	}
}

// ─── redisCachingTokenSource ─────────────────────────────────────────────────

func TestRedisCachingTokenSource_CacheMiss_FetchesFromInnerAndStores(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "fresh-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(mr, FailureModeOpen), testParams())

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "fresh-token" {
		t.Errorf("unexpected access token: %q", tok.AccessToken)
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch on cache miss, got %d", inner.calls)
	}

	key := buildRedisKey("oauth2-generator:token:v1:", oauth2ConfigDiscriminator(testParams()))
	if !mr.Exists(key) {
		t.Errorf("expected token to be written to redis under key %q", key)
	}
}

// TestRedisCachingTokenSource_Purge_ClearsLocalAndRedis locks in that Purge
// clears both cache tiers AND rebuilds inner via buildTokenSource, not just
// local/Redis: inner is typically an xoauth2.ReuseTokenSource that keeps
// reusing its own cached token until that token's own Expiry regardless of
// local/Redis, so a stub inner (which has no such internal cache) would
// pass even if Purge() only cleared local/Redis and left the real
// buildTokenSource-shaped bug in place - this uses a real httptest server
// through the real buildTokenSource path specifically to catch that.
func TestRedisCachingTokenSource_Purge_ClearsLocalAndRedis(t *testing.T) {
	mr := miniredis.RunT(t)

	var idpCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idpCalls++
		accessToken := "token-1"
		if idpCalls > 1 {
			accessToken = "token-2"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := testParams(func(p *oauth2Params) { p.tokenEndpoint = server.URL })
	inner, err := buildTokenSource(params)
	if err != nil {
		t.Fatalf("unexpected error building token source: %v", err)
	}
	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(mr, FailureModeOpen), params)

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("unexpected error priming the cache: %v", err)
	}
	if tok.AccessToken != "token-1" {
		t.Fatalf("unexpected primed access token: %q", tok.AccessToken)
	}
	if idpCalls != 1 {
		t.Fatalf("expected exactly 1 token-endpoint call to prime the cache, got %d", idpCalls)
	}
	key := buildRedisKey("oauth2-generator:token:v1:", oauth2ConfigDiscriminator(params))
	if !mr.Exists(key) {
		t.Fatal("expected the primed token to be present in redis")
	}

	src.Purge()

	if mr.Exists(key) {
		t.Error("expected Purge to delete the redis cache entry")
	}

	tok, err = src.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "token-2" {
		t.Errorf("expected Purge to force a fresh token-endpoint call, got access token %q", tok.AccessToken)
	}
	if idpCalls != 2 {
		t.Errorf("expected exactly 2 token-endpoint calls total (primed + post-purge), got %d", idpCalls)
	}
}

// TestRedisCachingTokenSource_MissingExpiry_AppliesDefaultTTLFallback locks
// in the fallback for IdPs that omit expires_in entirely: golang.org/x/oauth2
// leaves Token.Expiry as the zero value in that case, which Token.Valid()
// always treats as already-expired - without the fallback, this would mean
// caching silently never engages (see the comment at its use site in
// token_cache.go's Token()) and every request would refetch from the IdP.
func TestRedisCachingTokenSource_MissingExpiry_AppliesDefaultTTLFallback(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "no-expiry-token", TokenType: "Bearer"}} // Expiry left zero-value

	const fallbackTTL = 42 * time.Minute
	params := testParams(func(p *oauth2Params) { p.tokenTTLFallback = fallbackTTL })
	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(mr, FailureModeOpen), params)

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.Expiry.IsZero() {
		t.Fatal("expected the fallback TTL to give the token a non-zero Expiry")
	}
	wantExpiry := time.Now().Add(fallbackTTL)
	if diff := wantExpiry.Sub(tok.Expiry); diff < -time.Second || diff > time.Second {
		t.Errorf("expected Expiry within 1s of now+%s, got %s away", fallbackTTL, diff)
	}

	key := buildRedisKey("oauth2-generator:token:v1:", oauth2ConfigDiscriminator(params))
	ttl := mr.TTL(key)
	if ttl <= 0 {
		t.Fatalf("expected a positive TTL on the redis key, got %s - the fallback should make this token cacheable", ttl)
	}
	if ttl > fallbackTTL || ttl < fallbackTTL-time.Second {
		t.Errorf("expected redis TTL within 1s of %s, got %s", fallbackTTL, ttl)
	}

	// Second call should be served from the (now-valid) local cache, not
	// trigger a second inner fetch - proving the fallback actually restored
	// caching rather than just avoiding a crash.
	if _, err := src.Token(); err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch (second call served from cache), got %d", inner.calls)
	}
}

func TestRedisCachingTokenSource_RedisCacheHit_SkipsInnerFetch(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "should-not-be-used", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	key := buildRedisKey("oauth2-generator:token:v1:", oauth2ConfigDiscriminator(testParams()))
	cached, _ := json.Marshal(cachedToken{AccessToken: "cached-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)})
	if err := mr.Set(key, string(cached)); err != nil {
		t.Fatalf("failed to seed miniredis: %v", err)
	}

	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(mr, FailureModeOpen), testParams())

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "cached-token" {
		t.Errorf("expected the redis-cached token to be returned, got %q", tok.AccessToken)
	}
	if inner.calls != 0 {
		t.Errorf("expected 0 inner fetches on a redis cache hit, got %d", inner.calls)
	}
}

func TestRedisCachingTokenSource_LocalCache_AvoidsRepeatRedisAndInnerCalls(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "fresh-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(mr, FailureModeOpen), testParams())

	for i := 0; i < 5; i++ {
		if _, err := src.Token(); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch across 5 calls (rest served from local cache), got %d", inner.calls)
	}
}

// TestRedisCachingTokenSource_DifferentConfigs_GetIsolatedCacheEntries is the
// regression test for the cross-provider cache collision bug: two policy
// instances backed by different oauth2 credentials (as a proxy's primary
// provider and an additionalProviders entry would be) must never read or
// write each other's Redis entry, even though both may be attached to the
// exact same API.
func TestRedisCachingTokenSource_DifferentConfigs_GetIsolatedCacheEntries(t *testing.T) {
	mr := miniredis.RunT(t)
	innerA := &stubTokenSource{token: &xoauth2.Token{AccessToken: "token-for-provider-a", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	innerB := &stubTokenSource{token: &xoauth2.Token{AccessToken: "token-for-provider-b", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	paramsA := testParams(func(p *oauth2Params) { p.clientID = "provider-a-client" })
	paramsB := testParams(func(p *oauth2Params) { p.clientID = "provider-b-client" })

	srcA := mustNewRedisCachingTokenSource(t, innerA, testRedisParams(mr, FailureModeOpen), paramsA)
	srcB := mustNewRedisCachingTokenSource(t, innerB, testRedisParams(mr, FailureModeOpen), paramsB)

	tokA, err := srcA.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tokB, err := srcB.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokA.AccessToken != "token-for-provider-a" {
		t.Errorf("provider A got the wrong token: %q", tokA.AccessToken)
	}
	if tokB.AccessToken != "token-for-provider-b" {
		t.Errorf("provider B got the wrong token: %q", tokB.AccessToken)
	}

	keyA := buildRedisKey("oauth2-generator:token:v1:", oauth2ConfigDiscriminator(paramsA))
	keyB := buildRedisKey("oauth2-generator:token:v1:", oauth2ConfigDiscriminator(paramsB))
	if keyA == keyB {
		t.Fatal("expected different oauth2 configs to produce different redis keys")
	}
}

func TestRedisCachingTokenSource_RedisKeyFixedAtConstruction(t *testing.T) {
	// The key is derived from oauth2Params at construction time, not from
	// anything request-time - it never needs to move over the instance's
	// lifetime.
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "fresh-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	params := testParams()

	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(mr, FailureModeOpen), params).(*redisCachingTokenSource)

	want := buildRedisKey("oauth2-generator:token:v1:", oauth2ConfigDiscriminator(params))
	if src.redisKey != want {
		t.Fatalf("expected redisKey to be set at construction to %q, got %q", want, src.redisKey)
	}

	if _, err := src.Token(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src.redisKey != want {
		t.Errorf("expected the redis key to stay fixed after use, got %q", src.redisKey)
	}
}

func TestRedisCachingTokenSource_RedisDown_FailOpen_FallsBackToInner(t *testing.T) {
	mr := miniredis.RunT(t)
	rp := testRedisParams(mr, FailureModeOpen)
	mr.Close() // simulate redis being unreachable

	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "fallback-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	src := mustNewRedisCachingTokenSource(t, inner, rp, testParams())

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("expected failureMode=open to fall back to the inner source, got error: %v", err)
	}
	if tok.AccessToken != "fallback-token" {
		t.Errorf("unexpected access token: %q", tok.AccessToken)
	}
	if inner.calls != 1 {
		t.Errorf("expected the inner source to be called once as a fallback, got %d", inner.calls)
	}
}

func TestRedisCachingTokenSource_RedisDown_FailClosed_ReturnsErrorWithoutFallback(t *testing.T) {
	mr := miniredis.RunT(t)
	rp := testRedisParams(mr, FailureModeClosed)
	mr.Close() // simulate redis being unreachable

	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "should-not-be-fetched", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	src := mustNewRedisCachingTokenSource(t, inner, rp, testParams())

	_, err := src.Token()
	if err == nil {
		t.Fatal("expected an error when redis is down and failureMode is closed")
	}
	if inner.calls != 0 {
		t.Errorf("expected failureMode=closed to never fall back to the inner source, got %d calls", inner.calls)
	}
}

func TestRedisCachingTokenSource_InnerError_IsPropagated(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{err: errors.New("token endpoint returned invalid_client")}

	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(mr, FailureModeOpen), testParams())

	_, err := src.Token()
	if err == nil {
		t.Fatal("expected the inner source's error to propagate")
	}
}

// ─── tokenFreshEnough / expiryBuffer ─────────────────────────────────────────

func TestTokenFreshEnough_Nil_IsNotFresh(t *testing.T) {
	if tokenFreshEnough(nil, time.Minute) {
		t.Error("expected a nil token to never be fresh enough")
	}
}

func TestTokenFreshEnough_EmptyAccessToken_IsNotFresh(t *testing.T) {
	tok := &xoauth2.Token{Expiry: time.Now().Add(time.Hour)}
	if tokenFreshEnough(tok, time.Minute) {
		t.Error("expected a token with no AccessToken to never be fresh enough")
	}
}

func TestTokenFreshEnough_ZeroExpiry_IsFresh(t *testing.T) {
	tok := &xoauth2.Token{AccessToken: "tok"} // Expiry left zero - "never expires", mirrors Token.Valid()
	if !tokenFreshEnough(tok, time.Minute) {
		t.Error("expected a zero-Expiry token to be treated as fresh, same as Token.Valid()")
	}
}

func TestTokenFreshEnough_WithinBuffer_IsNotFresh(t *testing.T) {
	// Expires in 15s; a 30s buffer means this is "not fresh enough" even
	// though the token itself, per Token.Valid()'s own hardcoded 10s margin,
	// would still be considered valid.
	tok := &xoauth2.Token{AccessToken: "tok", Expiry: time.Now().Add(15 * time.Second)}
	if tokenFreshEnough(tok, 30*time.Second) {
		t.Error("expected a token expiring within the buffer window to not be fresh enough")
	}
	if !tok.Valid() {
		t.Fatal("test setup invariant broken: expected the raw token to still satisfy Token.Valid() at this margin")
	}
}

func TestTokenFreshEnough_OutsideBuffer_IsFresh(t *testing.T) {
	tok := &xoauth2.Token{AccessToken: "tok", Expiry: time.Now().Add(time.Hour)}
	if !tokenFreshEnough(tok, 30*time.Second) {
		t.Error("expected a token expiring well outside the buffer window to be fresh enough")
	}
}

// TestRedisCachingTokenSource_LocalCache_WithinExpiryBuffer_TriggersRefetch
// locks in that the in-process tier re-fetches once a cached token enters
// its configured expiryBuffer window, rather than serving it until its
// literal expiry - the whole point of the feature (avoid handing the
// backend a credential that's about to expire mid-flight).
func TestRedisCachingTokenSource_LocalCache_WithinExpiryBuffer_TriggersRefetch(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "soon-to-expire", TokenType: "Bearer", Expiry: time.Now().Add(5 * time.Second)}}

	params := testParams(func(p *oauth2Params) { p.expiryBuffer = 30 * time.Second })
	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(mr, FailureModeOpen), params)

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "soon-to-expire" {
		t.Fatalf("unexpected access token on first call: %q", tok.AccessToken)
	}

	// The just-fetched token's 5s remaining TTL is inside the 30s
	// expiryBuffer, so the next call must not be served from the local
	// cache - it should fall through to a second inner fetch.
	inner.token = &xoauth2.Token{AccessToken: "freshly-refetched", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}
	tok, err = src.Token()
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if tok.AccessToken != "freshly-refetched" {
		t.Errorf("expected the near-expiry token to trigger a refetch, got access token %q", tok.AccessToken)
	}
	if inner.calls != 2 {
		t.Errorf("expected exactly 2 inner fetches (initial + buffer-triggered refetch), got %d", inner.calls)
	}
}

// TestRedisCachingTokenSource_RedisRead_WithinExpiryBuffer_TriggersRefetch is
// the Redis-tier equivalent: an entry written by another replica that's now
// within this replica's expiryBuffer window must not be served as-is.
func TestRedisCachingTokenSource_RedisRead_WithinExpiryBuffer_TriggersRefetch(t *testing.T) {
	mr := miniredis.RunT(t)
	params := testParams(func(p *oauth2Params) { p.expiryBuffer = 30 * time.Second })

	key := buildRedisKey("oauth2-generator:token:v1:", oauth2ConfigDiscriminator(params))
	cached, _ := json.Marshal(cachedToken{AccessToken: "soon-to-expire", TokenType: "Bearer", Expiry: time.Now().Add(5 * time.Second)})
	if err := mr.Set(key, string(cached)); err != nil {
		t.Fatalf("failed to seed miniredis: %v", err)
	}

	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "freshly-refetched", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(mr, FailureModeOpen), params)

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "freshly-refetched" {
		t.Errorf("expected the near-expiry redis entry to be rejected and trigger a refetch, got access token %q", tok.AccessToken)
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch after rejecting the stale redis entry, got %d", inner.calls)
	}
}

// TestBuildTokenSource_ClientCredentials_ExpiryBuffer_ForcesRealRefetch is
// the end-to-end regression test for the actual bug this feature fixes:
// without wrapping the token-endpoint source in
// xoauth2.ReuseTokenSourceWithExpiry(expiryBuffer), the library's own
// ReuseTokenSource (hardcoded to a 10s margin) would keep silently handing
// back the same soon-to-expire token whenever the outer cache's larger
// expiryBuffer decided to fall through and re-fetch - defeating the whole
// feature the moment expiryBuffer exceeds 10s. This uses the real
// buildTokenSource path (not stubTokenSource) against an httptest server so
// that library-internal caching is actually exercised.
func TestBuildTokenSource_ClientCredentials_ExpiryBuffer_ForcesRealRefetch(t *testing.T) {
	mr := miniredis.RunT(t)

	var idpCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idpCalls++
		accessToken, expiresIn := "token-1", 5 // expires in 5s - inside the 10s expiryBuffer below
		if idpCalls > 1 {
			accessToken, expiresIn = "token-2", 300
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   expiresIn,
		})
	}))
	defer server.Close()

	params := testParams(func(p *oauth2Params) {
		p.tokenEndpoint = server.URL
		p.expiryBuffer = 10 * time.Second
	})
	inner, err := buildTokenSource(params)
	if err != nil {
		t.Fatalf("unexpected error building token source: %v", err)
	}
	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(mr, FailureModeOpen), params)

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("unexpected error priming the cache: %v", err)
	}
	if tok.AccessToken != "token-1" {
		t.Fatalf("unexpected primed access token: %q", tok.AccessToken)
	}
	if idpCalls != 1 {
		t.Fatalf("expected exactly 1 token-endpoint call to prime the cache, got %d", idpCalls)
	}

	// token-1's 5s remaining TTL is inside the 10s expiryBuffer: the outer
	// cache falls through to inner.Token(), and inner itself - via
	// ReuseTokenSourceWithExpiry using that same 10s buffer - must perform a
	// genuine second token-endpoint call rather than replaying token-1.
	tok, err = src.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "token-2" {
		t.Errorf("expected expiryBuffer to force a fresh token-endpoint call instead of reusing the near-expiry token, got access token %q", tok.AccessToken)
	}
	if idpCalls != 2 {
		t.Errorf("expected exactly 2 token-endpoint calls total (primed + buffer-triggered refetch), got %d", idpCalls)
	}
}

// ─── redisclient.Resolve integration ─────────────────────────────────────────

func TestRedisCachingTokenSource_SharesClientForIdenticalOverrideConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	rp := testRedisParams(mr, FailureModeOpen)

	src1 := mustNewRedisCachingTokenSource(t, &stubTokenSource{}, rp, testParams()).(*redisCachingTokenSource)
	src2 := mustNewRedisCachingTokenSource(t, &stubTokenSource{}, rp, testParams()).(*redisCachingTokenSource)

	if src1.redisClient != src2.redisClient {
		t.Error("expected two policy instances with identical policy-level redis override settings to share one *redis.Client")
	}
}

func TestNewRedisCachingTokenSource_MemoryStrategy_NeverTouchesRedis(t *testing.T) {
	cp := cacheParams{
		strategy: CacheStrategyMemory,
		// Deliberately unreachable - if cacheStrategy: memory ever dialed
		// Redis despite the strategy, using this host would surface as an
		// error or a fallback rather than silently succeeding via the
		// in-process tier alone.
		redisOverride: &redis.Options{
			Addr:         "unreachable.invalid:1",
			DialTimeout:  50 * time.Millisecond,
			ReadTimeout:  50 * time.Millisecond,
			WriteTimeout: 50 * time.Millisecond,
		},
	}
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "tok", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	src := mustNewRedisCachingTokenSource(t, inner, cp, testParams()).(*redisCachingTokenSource)

	if src.redisClient != nil {
		t.Fatal("expected cacheStrategy: memory to never resolve a redis client, even with a redisOverride configured")
	}

	tok, err := src.Token()
	if err != nil {
		t.Fatalf("unexpected error with an unreachable redis host configured under memory strategy: %v", err)
	}
	if tok.AccessToken != "tok" {
		t.Errorf("unexpected access token: %q", tok.AccessToken)
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly one inner fetch, got %d", inner.calls)
	}

	// Second call should be served from the in-process tier without
	// refetching - the only tier active under memory strategy.
	if _, err := src.Token(); err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if inner.calls != 1 {
		t.Errorf("expected the in-process cache to avoid a second inner fetch, got %d calls", inner.calls)
	}
}

// TestNewRedisCachingTokenSource_NoOverrideFallsBackToGatewayShared proves the
// precedence decision itself: with no policy-level redis.host configured,
// cacheStrategy: redis must resolve to whatever redisclient.Shared() returns,
// not silently disable the Redis tier.
func TestNewRedisCachingTokenSource_NoOverrideFallsBackToGatewayShared(t *testing.T) {
	mr := miniredis.RunT(t)
	sharedClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	redisclient.SetSharedForTesting(t, sharedClient)

	cp := cacheParams{strategy: CacheStrategyRedis, keyPrefix: "p:", failureMode: FailureModeOpen}
	src := mustNewRedisCachingTokenSource(t, &stubTokenSource{}, cp, testParams()).(*redisCachingTokenSource)

	if src.redisClient != sharedClient {
		t.Error("expected cacheStrategy: redis with no policy-level override to use the gateway-level shared client")
	}
	// readTimeout/writeTimeout must be zero here, not some fallback constant -
	// see redisCachingTokenSource's own field comment for why: falling back
	// to the gateway default means inheriting ITS timeout tuning via
	// go-redis's own Options-level deadline, not layering this policy's
	// preference on top of a connection it doesn't own.
	if src.readTimeout != 0 || src.writeTimeout != 0 {
		t.Errorf("expected readTimeout/writeTimeout to be zero when falling back to the gateway default, got %v/%v", src.readTimeout, src.writeTimeout)
	}
}

// TestNewRedisCachingTokenSource_NeitherOverrideNorSharedConfigured_Errors is
// the fail-fast contract: cacheStrategy: redis with genuinely nothing to
// connect to (no policy-level override, no gateway-level shared redis) is a
// real configuration gap and must error at construction, not silently
// degrade to memory-only caching.
func TestNewRedisCachingTokenSource_NeitherOverrideNorSharedConfigured_Errors(t *testing.T) {
	redisclient.SetSharedForTesting(t, nil) // simulates InitFromConfig having found no "redis" section

	cp := cacheParams{strategy: CacheStrategyRedis}
	if _, err := newRedisCachingTokenSource(&stubTokenSource{}, cp, testParams()); err == nil {
		t.Error("expected an error when cacheStrategy is redis but neither a policy-level override nor a gateway-level shared redis is configured")
	}
}

// ─── extractCacheParams ──────────────────────────────────────────────────────

func TestExtractCacheParams_DefaultsWhenAbsent(t *testing.T) {
	cp := extractCacheParams(map[string]interface{}{})
	if cp.strategy != CacheStrategyMemory {
		t.Errorf("expected cacheStrategy to default to %q, got %q", CacheStrategyMemory, cp.strategy)
	}
	if cp.redisOverride != nil {
		t.Errorf("expected no policy-level redis override when redis.host is absent, got %+v", cp.redisOverride)
	}
	if cp.keyPrefix != defaultRedisKeyPrefix || cp.failureMode != FailureModeOpen {
		t.Errorf("unexpected redis defaults: keyPrefix=%q failureMode=%q", cp.keyPrefix, cp.failureMode)
	}
}

func TestExtractCacheParams_StrategyRedis(t *testing.T) {
	params := map[string]interface{}{
		"cacheStrategy": "redis",
	}
	cp := extractCacheParams(params)
	if cp.strategy != CacheStrategyRedis {
		t.Errorf("expected cacheStrategy %q, got %q", CacheStrategyRedis, cp.strategy)
	}
}

func TestExtractCacheParams_NestedMapShape(t *testing.T) {
	params := map[string]interface{}{
		"cacheStrategy": "redis",
		"redis": map[string]interface{}{
			"host":        "redis.internal",
			"port":        float64(6380), // JSON numbers decode as float64
			"keyPrefix":   "custom:",
			"failureMode": "closed",
		},
	}
	cp := extractCacheParams(params)
	if cp.redisOverride == nil || cp.redisOverride.Addr != "redis.internal:6380" {
		t.Errorf("unexpected redisOverride from nested map shape: %+v", cp.redisOverride)
	}
	if cp.keyPrefix != "custom:" || cp.failureMode != "closed" {
		t.Errorf("unexpected params from nested map shape: keyPrefix=%q failureMode=%q", cp.keyPrefix, cp.failureMode)
	}
}

func TestExtractCacheParams_FlattenedDottedKeyShape(t *testing.T) {
	params := map[string]interface{}{
		"cacheStrategy": "redis",
		"redis.host":    "redis.internal",
		"redis.port":    6380,
	}
	cp := extractCacheParams(params)
	if cp.strategy != CacheStrategyRedis {
		t.Errorf("expected cacheStrategy %q, got %q", CacheStrategyRedis, cp.strategy)
	}
	if cp.redisOverride == nil || cp.redisOverride.Addr != "redis.internal:6380" {
		t.Errorf("unexpected redisOverride from flattened dotted-key shape: %+v", cp.redisOverride)
	}
}

// TestExtractCacheParams_DurationParsing_NoHostIgnored proves
// connectionTimeout/readTimeout/writeTimeout are gated on host exactly like
// port/username/password/db/poolSize: with no host configured, they're not
// read into anything at all - there's no top-level cacheParams field left to
// check them against, only redisOverride, which must be nil.
func TestExtractCacheParams_DurationParsing_NoHostIgnored(t *testing.T) {
	params := map[string]interface{}{
		"redis": map[string]interface{}{
			"connectionTimeout": "250ms",
		},
	}
	cp := extractCacheParams(params)
	if cp.redisOverride != nil {
		t.Errorf("expected no override since redis.host was never set, got %+v", cp.redisOverride)
	}
}

// TestExtractCacheParams_DurationParsing_WithHostAppliesToOverride is the
// positive case: once host is set, connectionTimeout/readTimeout/writeTimeout
// apply to that override's own *redis.Options, same as any other override field.
func TestExtractCacheParams_DurationParsing_WithHostAppliesToOverride(t *testing.T) {
	params := map[string]interface{}{
		"redis": map[string]interface{}{
			"host":              "redis.internal",
			"connectionTimeout": "250ms",
			"readTimeout":       "111ms",
			"writeTimeout":      "222ms",
		},
	}
	cp := extractCacheParams(params)
	if cp.redisOverride == nil {
		t.Fatal("expected a redisOverride since host was set")
	}
	if cp.redisOverride.DialTimeout != 250*time.Millisecond || cp.redisOverride.ReadTimeout != 111*time.Millisecond || cp.redisOverride.WriteTimeout != 222*time.Millisecond {
		t.Errorf("unexpected override timeouts: %+v", cp.redisOverride)
	}
}
