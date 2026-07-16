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
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	xoauth2 "golang.org/x/oauth2"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// FailureModeOpen degrades to fetching directly from IMDS when Redis is
	// unavailable - a Redis outage costs caching, not auth.
	FailureModeOpen = "open"
	// FailureModeClosed treats a Redis error as a token-acquisition failure.
	FailureModeClosed = "closed"

	defaultRedisHost              = "localhost"
	defaultRedisPort              = 6379
	defaultRedisKeyPrefix         = "azure-managed-identity:token:v1:"
	defaultRedisConnectionTimeout = 5 * time.Second
	defaultRedisReadTimeout       = 3 * time.Second
	defaultRedisWriteTimeout      = 3 * time.Second
)

// redisParams bundles the extracted, validated systemParameters.redis
// values. All fields have sane defaults (see policy-definition.yaml), so
// omitting the whole "redis" block is always valid.
type redisParams struct {
	host              string
	port              int
	username          string
	password          string
	db                int
	keyPrefix         string
	failureMode       string
	connectionTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	poolSize          int
}

// systemParams bundles every systemParameters value this policy reads:
// Redis connection settings plus the IMDS endpoint/timeout overrides.
type systemParams struct {
	imdsEndpoint   string
	requestTimeout time.Duration
	redis          redisParams
}

func extractSystemParams(params map[string]interface{}) systemParams {
	return systemParams{
		imdsEndpoint:   getNestedStringParam(params, "imdsEndpoint", defaultIMDSEndpoint),
		requestTimeout: getNestedDurationParam(params, "requestTimeout", defaultRequestTimeout),
		redis:          extractRedisParams(params),
	}
}

func extractRedisParams(params map[string]interface{}) redisParams {
	return redisParams{
		host:              getNestedStringParam(params, "redis.host", defaultRedisHost),
		port:              getNestedIntParam(params, "redis.port", defaultRedisPort),
		username:          getNestedStringParam(params, "redis.username", ""),
		password:          getNestedStringParam(params, "redis.password", ""),
		db:                getNestedIntParam(params, "redis.db", 0),
		keyPrefix:         getNestedStringParam(params, "redis.keyPrefix", defaultRedisKeyPrefix),
		failureMode:       getNestedStringParam(params, "redis.failureMode", FailureModeOpen),
		connectionTimeout: getNestedDurationParam(params, "redis.connectionTimeout", defaultRedisConnectionTimeout),
		readTimeout:       getNestedDurationParam(params, "redis.readTimeout", defaultRedisReadTimeout),
		writeTimeout:      getNestedDurationParam(params, "redis.writeTimeout", defaultRedisWriteTimeout),
		poolSize:          getNestedIntParam(params, "redis.poolSize", 0),
	}
}

// getNestedParam resolves a dotted key ("redis.host") against a params map
// that may store it either as nested maps (params["redis"]["host"]) or as a
// single flattened key (params["redis.host"]), and returns (value, true) on
// a hit. Nested-object systemParameters can arrive either way depending on
// how the policy engine flattens config, so this is deliberately tolerant
// of both.
func getNestedParam(params map[string]interface{}, dottedKey string) (interface{}, bool) {
	if v, ok := params[dottedKey]; ok {
		return v, true
	}
	var cur interface{} = params
	for _, part := range strings.Split(dottedKey, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		v, ok := m[part]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func getNestedStringParam(params map[string]interface{}, dottedKey, def string) string {
	if v, ok := getNestedParam(params, dottedKey); ok {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return def
}

func getNestedIntParam(params map[string]interface{}, dottedKey string, def int) int {
	if v, ok := getNestedParam(params, dottedKey); ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
				return parsed
			}
		}
	}
	return def
}

func getNestedDurationParam(params map[string]interface{}, dottedKey string, def time.Duration) time.Duration {
	if v, ok := getNestedParam(params, dottedKey); ok {
		if s, ok := v.(string); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil {
				return d
			}
		}
	}
	return def
}

// buildRedisKey scopes the cached token to the specific API/route this
// policy instance is attached to (so distinct LlmProviders never collide),
// AND to the clientId/resource pair actually used to obtain it. Unlike the
// oauth2 policy (which keys only by route), this also includes clientId and
// resource - neither is a secret, and including them means a config change
// that swaps to a different identity or a different target resource can
// never accidentally keep serving a stale token minted for the old
// identity/audience out of a route-scoped cache entry that config change
// didn't touch.
func buildRedisKey(prefix string, metadata policy.PolicyMetadata, clientID, resource string) string {
	candidates := []string{strings.TrimSuffix(prefix, ":"), metadata.APIId, metadata.RouteName, clientID, resource}
	var parts []string
	for _, s := range candidates {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ":")
}

// cachedToken is the JSON shape stored in Redis - just the fields needed to
// reconstruct an xoauth2.Token.
type cachedToken struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	Expiry      time.Time `json:"expiry"`
}

// redisCachingTokenSource wraps a real, IMDS-fetching xoauth2.TokenSource
// with a two-tier cache:
//  1. A per-process in-memory token - near-zero latency on the hot path.
//  2. A shared Redis entry - lets every gateway-runtime replica reuse the
//     same token instead of each independently calling IMDS, and survives
//     an individual replica restart.
//
// Redis is treated as an optimization layered on top of IMDS, not a hard
// dependency: a Redis error either falls back to fetching directly from
// IMDS (failOpen=true, the default) or is surfaced as a token-acquisition
// failure (failOpen=false), per the redis.failureMode param. Identical
// design to the oauth2 policy's own token cache.
type redisCachingTokenSource struct {
	inner        xoauth2.TokenSource
	redisClient  *redis.Client // nil disables the Redis tier entirely
	redisKey     string
	failOpen     bool
	readTimeout  time.Duration
	writeTimeout time.Duration

	mu    sync.Mutex
	local *xoauth2.Token
}

// newRedisCachingTokenSource builds the cache wrapper around inner. metadata,
// clientID, and resource are used only to derive the Redis key
// (buildRedisKey) - the wrapper otherwise knows nothing about how inner
// fetches tokens.
func newRedisCachingTokenSource(inner xoauth2.TokenSource, rp redisParams, metadata policy.PolicyMetadata, clientID, resource string) xoauth2.TokenSource {
	client := getOrCreateRedisClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", rp.host, rp.port),
		Username:     rp.username,
		Password:     rp.password,
		DB:           rp.db,
		DialTimeout:  rp.connectionTimeout,
		ReadTimeout:  rp.readTimeout,
		WriteTimeout: rp.writeTimeout,
		PoolSize:     rp.poolSize,
		// MaxRetries: -1 disables go-redis's own command-level retries. This
		// cache already has a fallback (fetch directly from IMDS) for
		// exactly the case a Redis command fails, so paying for automatic
		// retries here is pure added latency on the fail-open path with no
		// corresponding benefit.
		MaxRetries: -1,
	})

	return &redisCachingTokenSource{
		inner:        inner,
		redisClient:  client,
		redisKey:     buildRedisKey(rp.keyPrefix, metadata, clientID, resource),
		failOpen:     rp.failureMode != FailureModeClosed,
		readTimeout:  rp.readTimeout,
		writeTimeout: rp.writeTimeout,
	}
}

func (s *redisCachingTokenSource) Token() (*xoauth2.Token, error) {
	if tok := s.localToken(); tok != nil {
		return tok, nil
	}

	if s.redisClient != nil {
		tok, err := s.getFromRedis()
		switch {
		case err != nil && !s.failOpen:
			return nil, fmt.Errorf("redis token cache unavailable: %w", err)
		case err != nil:
			slog.Warn("AzureManagedIdentity: redis token cache unavailable, fetching directly from IMDS", "error", err)
		case tok != nil:
			s.setLocal(tok)
			return tok, nil
		}
	}

	tok, err := s.inner.Token()
	if err != nil {
		return nil, err
	}
	s.setLocal(tok)

	if s.redisClient != nil {
		if err := s.saveToRedis(tok); err != nil {
			// Failing to populate the shared cache doesn't invalidate the
			// token we just successfully obtained - log and continue. This
			// replica just won't share it with others until a future write
			// succeeds.
			slog.Warn("AzureManagedIdentity: failed to write token to redis cache", "error", err)
		}
	}
	return tok, nil
}

func (s *redisCachingTokenSource) localToken() *xoauth2.Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.local != nil && s.local.Valid() {
		return s.local
	}
	return nil
}

func (s *redisCachingTokenSource) setLocal(tok *xoauth2.Token) {
	s.mu.Lock()
	s.local = tok
	s.mu.Unlock()
}

func (s *redisCachingTokenSource) getFromRedis() (*xoauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.readTimeout)
	defer cancel()

	val, err := s.redisClient.Get(ctx, s.redisKey).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var ct cachedToken
	if err := json.Unmarshal([]byte(val), &ct); err != nil {
		return nil, fmt.Errorf("failed to decode cached token: %w", err)
	}

	tok := &xoauth2.Token{
		AccessToken: ct.AccessToken,
		TokenType:   ct.TokenType,
		Expiry:      ct.Expiry,
	}
	if !tok.Valid() {
		// Defensive only - the Redis TTL should already have expired this
		// entry by the time it would fail Valid().
		return nil, nil
	}
	return tok, nil
}

func (s *redisCachingTokenSource) saveToRedis(tok *xoauth2.Token) error {
	ttl := time.Until(tok.Expiry)
	if ttl <= 0 {
		// No usable expiry to derive a TTL from - nothing safe to cache.
		return nil
	}

	data, err := json.Marshal(cachedToken{
		AccessToken: tok.AccessToken,
		TokenType:   tok.TokenType,
		Expiry:      tok.Expiry,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()
	return s.redisClient.Set(ctx, s.redisKey, data, ttl).Err()
}
