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
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	xoauth2 "golang.org/x/oauth2"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
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
		keyPrefix:         "oauth2:token:v1:",
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

// testMetadata supplies only a RouteName - the last-resort fallback used
// when a request-time API identity isn't available (see resolveAPIIdentity).
func testMetadata() policy.PolicyMetadata {
	return policy.PolicyMetadata{RouteName: "test-route"}
}

// testReqCtx builds a *policy.RequestHeaderContext carrying the given
// SharedContext.APIId - the request-time source the Redis cache key is
// actually resolved from.
func testReqCtx(apiID string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{SharedContext: &policy.SharedContext{APIId: apiID}}
}

const testAPIID = "test-api-id"

// ─── resolveAPIIdentity ──────────────────────────────────────────────────────

func TestResolveAPIIdentity_PrefersAPIId(t *testing.T) {
	reqCtx := &policy.RequestHeaderContext{SharedContext: &policy.SharedContext{
		APIId: "api-1", APIName: "ignored", APIVersion: "ignored",
	}}
	if got := resolveAPIIdentity(reqCtx, "route-fallback"); got != "api-1" {
		t.Errorf("got %q, want %q", got, "api-1")
	}
}

func TestResolveAPIIdentity_FallsBackToAPINameVersion(t *testing.T) {
	reqCtx := &policy.RequestHeaderContext{SharedContext: &policy.SharedContext{
		APIName: "PetStore", APIVersion: "v1.0.0",
	}}
	want := "PetStore:v1.0.0"
	if got := resolveAPIIdentity(reqCtx, "route-fallback"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveAPIIdentity_FallsBackToRouteNameWhenSharedContextEmpty(t *testing.T) {
	reqCtx := &policy.RequestHeaderContext{SharedContext: &policy.SharedContext{}}
	if got := resolveAPIIdentity(reqCtx, "route-fallback"); got != "route-fallback" {
		t.Errorf("got %q, want %q", got, "route-fallback")
	}
}

func TestResolveAPIIdentity_FallsBackToRouteNameWhenReqCtxNil(t *testing.T) {
	if got := resolveAPIIdentity(nil, "route-fallback"); got != "route-fallback" {
		t.Errorf("got %q, want %q", got, "route-fallback")
	}
}

// ─── buildRedisKey ───────────────────────────────────────────────────────────

func TestBuildRedisKey(t *testing.T) {
	key := buildRedisKey("oauth2:token:v1:", "api-1")
	want := "oauth2:token:v1:api-1"
	if key != want {
		t.Errorf("got %q, want %q", key, want)
	}
}

func TestBuildRedisKey_OmitsEmptyIdentity(t *testing.T) {
	key := buildRedisKey("oauth2:token:v1:", "")
	want := "oauth2:token:v1"
	if key != want {
		t.Errorf("got %q, want %q", key, want)
	}
}

// ─── redisCachingTokenSource ─────────────────────────────────────────────────

func TestRedisCachingTokenSource_CacheMiss_FetchesFromInnerAndStores(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "fresh-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testMetadata())

	tok, err := src.Token(testReqCtx(testAPIID))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "fresh-token" {
		t.Errorf("unexpected access token: %q", tok.AccessToken)
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch on cache miss, got %d", inner.calls)
	}

	key := buildRedisKey("oauth2:token:v1:", testAPIID)
	if !mr.Exists(key) {
		t.Errorf("expected token to be written to redis under key %q", key)
	}
}

func TestRedisCachingTokenSource_RedisCacheHit_SkipsInnerFetch(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "should-not-be-used", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	key := buildRedisKey("oauth2:token:v1:", testAPIID)
	cached, _ := json.Marshal(cachedToken{AccessToken: "cached-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)})
	if err := mr.Set(key, string(cached)); err != nil {
		t.Fatalf("failed to seed miniredis: %v", err)
	}

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testMetadata())

	tok, err := src.Token(testReqCtx(testAPIID))
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

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testMetadata())

	for i := 0; i < 5; i++ {
		if _, err := src.Token(testReqCtx(testAPIID)); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch across 5 calls (rest served from local cache), got %d", inner.calls)
	}
}

func TestRedisCachingTokenSource_DifferentAPIs_GetIsolatedCacheEntries(t *testing.T) {
	// Same policy instance (e.g. same clientId/tokenEndpoint reused across
	// two LlmProviders would still be two separate GetPolicy calls in
	// practice, but this proves the key itself is what isolates them, not
	// incidental separation of instances).
	mr := miniredis.RunT(t)
	innerA := &stubTokenSource{token: &xoauth2.Token{AccessToken: "token-for-api-a", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	innerB := &stubTokenSource{token: &xoauth2.Token{AccessToken: "token-for-api-b", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	srcA := newRedisCachingTokenSource(innerA, testRedisParams(mr, FailureModeOpen), testMetadata())
	srcB := newRedisCachingTokenSource(innerB, testRedisParams(mr, FailureModeOpen), testMetadata())

	tokA, err := srcA.Token(testReqCtx("api-a"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tokB, err := srcB.Token(testReqCtx("api-b"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokA.AccessToken == tokB.AccessToken {
		t.Fatal("expected different APIs to get isolated tokens")
	}

	keyA := buildRedisKey("oauth2:token:v1:", "api-a")
	keyB := buildRedisKey("oauth2:token:v1:", "api-b")
	if keyA == keyB {
		t.Fatal("expected different APIs to produce different redis keys")
	}
}

func TestRedisCachingTokenSource_RedisKeyIsFixedAfterFirstResolution(t *testing.T) {
	// The key is resolved from the FIRST request's context and then never
	// re-resolved - a route (and the API it belongs to) doesn't change over
	// a policy instance's lifetime, so this is correct, not a bug: passing
	// a different apiId on a later call must not move the cache entry.
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "fresh-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testMetadata()).(*redisCachingTokenSource)

	if _, err := src.Token(testReqCtx("api-a")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := src.Token(testReqCtx("api-b")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inner.calls != 1 {
		t.Errorf("expected the second call to reuse the local cache (key fixed from the first call), got %d inner fetches", inner.calls)
	}
	if src.redisKey != buildRedisKey("oauth2:token:v1:", "api-a") {
		t.Errorf("expected the redis key to stay fixed to the first-resolved identity, got %q", src.redisKey)
	}
}

func TestRedisCachingTokenSource_RedisDown_FailOpen_FallsBackToInner(t *testing.T) {
	mr := miniredis.RunT(t)
	rp := testRedisParams(mr, FailureModeOpen)
	mr.Close() // simulate redis being unreachable

	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "fallback-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	src := newRedisCachingTokenSource(inner, rp, testMetadata())

	tok, err := src.Token(testReqCtx(testAPIID))
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
	src := newRedisCachingTokenSource(inner, rp, testMetadata())

	_, err := src.Token(testReqCtx(testAPIID))
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

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testMetadata())

	_, err := src.Token(testReqCtx(testAPIID))
	if err == nil {
		t.Fatal("expected the inner source's error to propagate")
	}
}

// ─── getOrCreateRedisClient ──────────────────────────────────────────────────

func TestGetOrCreateRedisClient_SharesClientForIdenticalConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	rp := testRedisParams(mr, FailureModeOpen)

	src1 := newRedisCachingTokenSource(&stubTokenSource{}, rp, testMetadata()).(*redisCachingTokenSource)
	src2 := newRedisCachingTokenSource(&stubTokenSource{}, rp, testMetadata()).(*redisCachingTokenSource)

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
