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
		keyPrefix:         "azure-managed-identity:token:v1:",
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

func testMetadata() policy.PolicyMetadata {
	return policy.PolicyMetadata{APIId: "test-api", RouteName: "test-route"}
}

const (
	testClientID = "11111111-1111-1111-1111-111111111111"
	testResource = "https://cognitiveservices.azure.com/"
)

// ─── buildRedisKey ───────────────────────────────────────────────────────────

func TestBuildRedisKey(t *testing.T) {
	key := buildRedisKey("azure-managed-identity:token:v1:", policy.PolicyMetadata{APIId: "api-1", RouteName: "route-1"}, testClientID, testResource)
	want := "azure-managed-identity:token:v1:api-1:route-1:" + testClientID + ":" + testResource
	if key != want {
		t.Errorf("got %q, want %q", key, want)
	}
}

func TestBuildRedisKey_DiffersByResource(t *testing.T) {
	metadata := policy.PolicyMetadata{APIId: "api-1", RouteName: "route-1"}
	keyA := buildRedisKey("prefix:", metadata, testClientID, "https://cognitiveservices.azure.com/")
	keyB := buildRedisKey("prefix:", metadata, testClientID, "https://management.azure.com/")
	if keyA == keyB {
		t.Error("expected different resources on the same route to produce different cache keys")
	}
}

func TestBuildRedisKey_DiffersByClientID(t *testing.T) {
	metadata := policy.PolicyMetadata{APIId: "api-1", RouteName: "route-1"}
	keyA := buildRedisKey("prefix:", metadata, "client-a", testResource)
	keyB := buildRedisKey("prefix:", metadata, "client-b", testResource)
	if keyA == keyB {
		t.Error("expected different clientIds on the same route to produce different cache keys")
	}
}

// ─── redisCachingTokenSource ─────────────────────────────────────────────────

func TestRedisCachingTokenSource_CacheMiss_FetchesFromInnerAndStores(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "fresh-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testMetadata(), testClientID, testResource)

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

	key := buildRedisKey("azure-managed-identity:token:v1:", testMetadata(), testClientID, testResource)
	if !mr.Exists(key) {
		t.Errorf("expected token to be written to redis under key %q", key)
	}
}

func TestRedisCachingTokenSource_RedisCacheHit_SkipsInnerFetch(t *testing.T) {
	mr := miniredis.RunT(t)
	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "should-not-be-used", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	key := buildRedisKey("azure-managed-identity:token:v1:", testMetadata(), testClientID, testResource)
	cached, _ := json.Marshal(cachedToken{AccessToken: "cached-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)})
	if err := mr.Set(key, string(cached)); err != nil {
		t.Fatalf("failed to seed miniredis: %v", err)
	}

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testMetadata(), testClientID, testResource)

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

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testMetadata(), testClientID, testResource)

	for i := 0; i < 5; i++ {
		if _, err := src.Token(); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch across 5 calls (rest served from local cache), got %d", inner.calls)
	}
}

func TestRedisCachingTokenSource_RedisDown_FailOpen_FallsBackToInner(t *testing.T) {
	mr := miniredis.RunT(t)
	rp := testRedisParams(mr, FailureModeOpen)
	mr.Close() // simulate redis being unreachable

	inner := &stubTokenSource{token: &xoauth2.Token{AccessToken: "fallback-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	src := newRedisCachingTokenSource(inner, rp, testMetadata(), testClientID, testResource)

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
	src := newRedisCachingTokenSource(inner, rp, testMetadata(), testClientID, testResource)

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
	inner := &stubTokenSource{err: errors.New("IMDS returned status 400")}

	src := newRedisCachingTokenSource(inner, testRedisParams(mr, FailureModeOpen), testMetadata(), testClientID, testResource)

	_, err := src.Token()
	if err == nil {
		t.Fatal("expected the inner source's error to propagate")
	}
}

// ─── getOrCreateRedisClient ──────────────────────────────────────────────────

func TestGetOrCreateRedisClient_SharesClientForIdenticalConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	rp := testRedisParams(mr, FailureModeOpen)

	src1 := newRedisCachingTokenSource(&stubTokenSource{}, rp, testMetadata(), testClientID, testResource).(*redisCachingTokenSource)
	src2 := newRedisCachingTokenSource(&stubTokenSource{}, rp, testMetadata(), "other-client", "other-resource").(*redisCachingTokenSource)

	if src1.redisClient != src2.redisClient {
		t.Error("expected two policy instances with identical redis connection settings to share one *redis.Client")
	}
}

// ─── extractSystemParams / extractRedisParams ───────────────────────────────

func TestExtractSystemParams_DefaultsWhenAbsent(t *testing.T) {
	sp := extractSystemParams(map[string]interface{}{})
	if sp.imdsEndpoint != defaultIMDSEndpoint {
		t.Errorf("expected default imdsEndpoint, got %q", sp.imdsEndpoint)
	}
	if sp.requestTimeout != defaultRequestTimeout {
		t.Errorf("expected default requestTimeout, got %v", sp.requestTimeout)
	}
	if sp.redis.host != defaultRedisHost || sp.redis.port != defaultRedisPort {
		t.Errorf("unexpected redis defaults: %+v", sp.redis)
	}
}

func TestExtractSystemParams_ImdsEndpointOverride(t *testing.T) {
	params := map[string]interface{}{
		"imdsEndpoint": "http://localhost:9701/metadata/identity/oauth2/token",
	}
	sp := extractSystemParams(params)
	if sp.imdsEndpoint != "http://localhost:9701/metadata/identity/oauth2/token" {
		t.Errorf("unexpected imdsEndpoint: %q", sp.imdsEndpoint)
	}
}

func TestExtractRedisParams_NestedMapShape(t *testing.T) {
	params := map[string]interface{}{
		"redis": map[string]interface{}{
			"host":        "redis.internal",
			"port":        float64(6380),
			"keyPrefix":   "custom:",
			"failureMode": "closed",
		},
	}
	rp := extractRedisParams(params)
	if rp.host != "redis.internal" || rp.port != 6380 || rp.keyPrefix != "custom:" || rp.failureMode != "closed" {
		t.Errorf("unexpected params from nested map shape: %+v", rp)
	}
}
