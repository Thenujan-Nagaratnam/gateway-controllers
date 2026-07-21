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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
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

func testRedisParams(mr *miniredis.Miniredis, failureMode string) redisParams {
	return redisParams{
		host:              mr.Host(),
		port:              mustAtoi(mr.Port()),
		keyPrefix:         "upstream-oauth2:token:v1:",
		failureMode:       failureMode,
		connectionTimeout: time.Second,
		readTimeout:       time.Second,
		writeTimeout:      time.Second,
	}
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
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
// in that a config with no "params" set at all (customParams == nil, the
// client_credentials/no-scope common case) and one with an explicitly empty
// "params": {} are indistinguishable - both mean "no extra token-request
// fields" and must land on the same cache entry, not two different ones for
// what is operationally the same configuration.
func TestOauth2ConfigDiscriminator_NilVsEmptyCustomParams_ProducesSameKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.customParams = nil }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.customParams = map[string]string{} }))
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
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.customParams = map[string]string{"scope": "read"} }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.customParams = map[string]string{"scope": "write"} }))
	if a == b {
		t.Error("expected different scope (via customParams) to produce a different discriminator")
	}
}

func TestOauth2ConfigDiscriminator_ParamsKeyOrder_ProducesSameKey(t *testing.T) {
	// encoding/json sorts map keys when marshaling - locks in that the
	// discriminator doesn't depend on incidental map iteration order.
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) {
		p.customParams = map[string]string{"scope": "read", "audience": "api-a"}
	}))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) {
		p.customParams = map[string]string{"audience": "api-a", "scope": "read"}
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
	key := buildRedisKey("upstream-oauth2:token:v1:", "abc123")
	want := "upstream-oauth2:token:v1:abc123"
	if key != want {
		t.Errorf("got %q, want %q", key, want)
	}
}

func TestBuildRedisKey_OmitsEmptyDiscriminator(t *testing.T) {
	key := buildRedisKey("upstream-oauth2:token:v1:", "")
	want := "upstream-oauth2:token:v1"
	if key != want {
		t.Errorf("got %q, want %q", key, want)
	}
}

// ─── redisCachingTokenSource ─────────────────────────────────────────────────

func TestRedisCachingTokenSource_CacheMiss_FetchesFromInnerAndStores(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "fresh-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testParams())

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

	key := buildRedisKey("upstream-oauth2:token:v1:", oauth2ConfigDiscriminator(testParams()))
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
	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), params)

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
	key := buildRedisKey("upstream-oauth2:token:v1:", oauth2ConfigDiscriminator(params))
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
	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), params)

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

	key := buildRedisKey("upstream-oauth2:token:v1:", oauth2ConfigDiscriminator(params))
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

	key := buildRedisKey("upstream-oauth2:token:v1:", oauth2ConfigDiscriminator(testParams()))
	cached, _ := json.Marshal(cachedToken{AccessToken: "cached-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)})
	if err := mr.Set(key, string(cached)); err != nil {
		t.Fatalf("failed to seed miniredis: %v", err)
	}

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testParams())

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

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testParams())

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

	srcA := newRedisCachingTokenSource(innerA, testRedisParams(mr, FailureModeOpen), paramsA)
	srcB := newRedisCachingTokenSource(innerB, testRedisParams(mr, FailureModeOpen), paramsB)

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

	keyA := buildRedisKey("upstream-oauth2:token:v1:", oauth2ConfigDiscriminator(paramsA))
	keyB := buildRedisKey("upstream-oauth2:token:v1:", oauth2ConfigDiscriminator(paramsB))
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

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), params).(*redisCachingTokenSource)

	want := buildRedisKey("upstream-oauth2:token:v1:", oauth2ConfigDiscriminator(params))
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
	src := newRedisCachingTokenSource(inner, rp, testParams())

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
	src := newRedisCachingTokenSource(inner, rp, testParams())

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

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testParams())

	_, err := src.Token()
	if err == nil {
		t.Fatal("expected the inner source's error to propagate")
	}
}

// ─── getOrCreateRedisClient ──────────────────────────────────────────────────

func TestGetOrCreateRedisClient_SharesClientForIdenticalConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	rp := testRedisParams(mr, FailureModeOpen)

	src1 := newRedisCachingTokenSource(&stubTokenSource{}, rp, testParams()).(*redisCachingTokenSource)
	src2 := newRedisCachingTokenSource(&stubTokenSource{}, rp, testParams()).(*redisCachingTokenSource)

	if src1.redisClient != src2.redisClient {
		t.Error("expected two policy instances with identical redis connection settings to share one *redis.Client")
	}
}

// ─── extractRedisParams ──────────────────────────────────────────────────────

func TestExtractRedisParams_DefaultsWhenAbsent(t *testing.T) {
	rp := extractRedisParams(map[string]interface{}{})
	if rp.host != defaultRedisHost || rp.port != defaultRedisPort || rp.keyPrefix != defaultRedisKeyPrefix || rp.failureMode != FailureModeOpen {
		t.Errorf("unexpected defaults: %+v", rp)
	}
}

func TestExtractRedisParams_NestedMapShape(t *testing.T) {
	params := map[string]interface{}{
		"redis": map[string]interface{}{
			"host":        "redis.internal",
			"port":        float64(6380), // JSON numbers decode as float64
			"keyPrefix":   "custom:",
			"failureMode": "closed",
		},
	}
	rp := extractRedisParams(params)
	if rp.host != "redis.internal" || rp.port != 6380 || rp.keyPrefix != "custom:" || rp.failureMode != "closed" {
		t.Errorf("unexpected params from nested map shape: %+v", rp)
	}
}

func TestExtractRedisParams_FlattenedDottedKeyShape(t *testing.T) {
	params := map[string]interface{}{
		"redis.host": "redis.internal",
		"redis.port": 6380,
	}
	rp := extractRedisParams(params)
	if rp.host != "redis.internal" || rp.port != 6380 {
		t.Errorf("unexpected params from flattened dotted-key shape: %+v", rp)
	}
}

func TestExtractRedisParams_DurationParsing(t *testing.T) {
	params := map[string]interface{}{
		"redis": map[string]interface{}{
			"connectionTimeout": "250ms",
		},
	}
	rp := extractRedisParams(params)
	if rp.connectionTimeout != 250*time.Millisecond {
		t.Errorf("expected 250ms connectionTimeout, got %v", rp.connectionTimeout)
	}
}
