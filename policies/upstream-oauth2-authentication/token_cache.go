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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	xoauth2 "golang.org/x/oauth2"
)

const (
	// FailureModeOpen degrades to fetching directly from the token endpoint
	// when Redis is unavailable, so authentication keeps working through a
	// Redis outage.
	FailureModeOpen = "open"
	// FailureModeClosed treats a Redis error as a token-acquisition failure.
	FailureModeClosed = "closed"

	defaultRedisHost              = "localhost"
	defaultRedisPort              = 6379
	defaultRedisKeyPrefix         = "upstream-oauth2:token:v1:"
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

// extractRedisParams reads systemParameters.redis.* from the raw params map,
// falling back to the defaults declared in policy-definition.yaml for any
// field that is absent or the wrong type. Unlike the business params
// (tokenEndpoint, clientId, ...), nothing here is required.
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

// buildRedisKey scopes the cached token to a config discriminator - see
// oauth2ConfigDiscriminator.
func buildRedisKey(prefix, discriminator string) string {
	candidates := []string{strings.TrimSuffix(prefix, ":"), discriminator}
	var parts []string
	for _, s := range candidates {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ":")
}

// oauth2CacheKeyFields is the subset of oauth2Params that determines what
// access token the token endpoint would issue, and which caller is entitled
// to receive it. Serialized as a struct (fixed field order, JSON-escaped
// strings) rather than delimiter-joined concatenation so that no combination
// of field values can produce the same serialized bytes as a different
// combination.
type oauth2CacheKeyFields struct {
	GrantType        string `json:"grantType"`
	TokenEndpoint    string `json:"tokenEndpoint"`
	ClientID         string `json:"clientId"`
	ClientAuthMethod string `json:"clientAuthMethod"`
	Username         string `json:"username,omitempty"`

	// Params (scope, audience, resource, tenant, ...) must be part of the
	// discriminator: a different scope earns a different key, so a config
	// only ever gets a token minted for its own scope. encoding/json sorts
	// map[string]string keys alphabetically when marshaling, so this is
	// stable regardless of the map's iteration order.
	Params map[string]string `json:"params,omitempty"`

	// ClientSecretHash and PasswordHash bind the cache entry to the specific
	// credential presented - see oauth2ConfigDiscriminator.
	ClientSecretHash string `json:"clientSecretHash"`
	PasswordHash     string `json:"passwordHash,omitempty"`
}

// oauth2ConfigDiscriminator derives a stable cache-key component from the
// oauth2 configuration itself, computed once from the already-validated
// oauth2Params at construction time. Every field that determines what token
// the endpoint would issue, and who is entitled to receive it, feeds into
// the hash: two oauth2 configs with any differing field (including a
// rotated clientSecret/password) land on different keys, while two
// byte-identical configs land on the same one regardless of which API or
// provider each is attached to.
//
// clientSecret and password are hashed with SHA-256 rather than stored raw
// (Redis key names appear in Redis MONITOR/slowlog output; hashSensitiveValue
// in redis_clients.go applies the same principle to the Redis connection
// password). Including them closes a real cross-credential reuse gap: two
// configs sharing only clientId/tokenEndpoint but presenting different
// credentials now always land on different keys. The cost is one extra
// token fetch the first time a rotated credential is used - the old entry's
// key is simply never looked up again.
func oauth2ConfigDiscriminator(p oauth2Params) string {
	fields := oauth2CacheKeyFields{
		GrantType:        p.grantType,
		TokenEndpoint:    p.tokenEndpoint,
		ClientID:         p.clientID,
		ClientAuthMethod: p.clientAuthMethod,
		Username:         p.username,
		Params:           p.customParams,
		ClientSecretHash: hashSensitiveValue(p.clientSecret),
		PasswordHash:     hashSensitiveValue(p.password),
	}
	// Marshaling a struct of plain strings and a map[string]string cannot
	// fail; the error is only checked to satisfy static analysis.
	data, err := json.Marshal(fields)
	if err != nil {
		data = []byte(fmt.Sprintf("%+v", fields))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// cachedToken is the JSON shape stored in Redis - just the fields needed to
// reconstruct an xoauth2.Token.
type cachedToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry"`
}

// tokenProvider is satisfied by redisCachingTokenSource. Token() has the
// same shape as xoauth2.TokenSource - no request-time context is needed to
// look up the cache entry, since the Redis key is derived entirely from the
// oauth2 config at construction time (see oauth2ConfigDiscriminator). Purge
// clears both cache tiers, for the response-phase purge-on-upstream-status
// case (see OnResponseHeaders).
type tokenProvider interface {
	Token() (*xoauth2.Token, error)
	Purge()
}

// redisCachingTokenSource wraps a real, IDP-fetching xoauth2.TokenSource
// with a two-tier cache:
//  1. A per-process in-memory token - near-zero latency on the hot path.
//  2. A shared Redis entry - lets every gateway-runtime replica reuse the
//     same token, and survives an individual replica restart.
//
// Redis is an optimization layered on top of the token endpoint: a Redis
// error either falls back to fetching directly from the token endpoint
// (failOpen=true, the default) or is surfaced as a token-acquisition
// failure (failOpen=false), per the redis.failureMode param.
type redisCachingTokenSource struct {
	// inner is read/written under mu, not just at construction - Purge()
	// replaces it with a freshly-built one (see Purge() for why).
	inner xoauth2.TokenSource

	// params is the same validated oauth2Params inner was built from,
	// retained so Purge() can rebuild inner via buildTokenSource(params).
	params oauth2Params

	redisClient  *redis.Client // nil disables the Redis tier entirely
	failOpen     bool
	readTimeout  time.Duration
	writeTimeout time.Duration

	// defaultTTL is applied to a freshly-fetched token whose Expiry is the
	// zero value - see the comment at its use site in Token() for why.
	defaultTTL time.Duration

	mu    sync.Mutex
	local *xoauth2.Token

	// redisKey is fixed once at construction from oauth2ConfigDiscriminator -
	// it depends only on the (already-validated) oauth2 config, never on
	// anything request-time, so there is nothing to resolve lazily.
	redisKey string
}

// newRedisCachingTokenSource builds the cache wrapper around inner. p is the
// same validated oauth2Params inner was built from - newRedisCachingTokenSource
// reads it to derive the Redis key (see oauth2ConfigDiscriminator) and the
// cache TTL fallback, and retains it so Purge() can rebuild inner later.
func newRedisCachingTokenSource(inner xoauth2.TokenSource, rp redisParams, p oauth2Params) tokenProvider {
	client := getOrCreateRedisClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", rp.host, rp.port),
		Username:     rp.username,
		Password:     rp.password,
		DB:           rp.db,
		DialTimeout:  rp.connectionTimeout,
		ReadTimeout:  rp.readTimeout,
		WriteTimeout: rp.writeTimeout,
		PoolSize:     rp.poolSize,
		// MaxRetries: -1 disables go-redis's own command retries - a failed
		// command already falls back to the token endpoint, so retrying
		// first is just added latency on that path.
		MaxRetries: -1,
	})

	return &redisCachingTokenSource{
		inner:        inner,
		params:       p,
		redisClient:  client,
		redisKey:     buildRedisKey(rp.keyPrefix, oauth2ConfigDiscriminator(p)),
		failOpen:     rp.failureMode != FailureModeClosed,
		readTimeout:  rp.readTimeout,
		writeTimeout: rp.writeTimeout,
		defaultTTL:   p.tokenTTLFallback,
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
			slog.Warn("OAuth2: redis token cache unavailable, fetching directly from token endpoint", "error", err)
		case tok != nil:
			s.setLocal(tok)
			return tok, nil
		}
	}

	tok, err := s.getInner().Token()
	if err != nil {
		return nil, err
	}
	if tok.Expiry.IsZero() {
		// Some IdPs omit expires_in; golang.org/x/oauth2 leaves Expiry as
		// the zero value then, and Token.Valid() treats that as
		// already-expired, so this fallback is what makes the token
		// cacheable at all. tok is the same *Token pointer s.inner's own
		// ReuseTokenSource retains and may hand to a concurrent caller with
		// no lock held over it, so mutate a copy.
		fixed := *tok
		fixed.Expiry = time.Now().Add(s.defaultTTL)
		tok = &fixed
	}
	s.setLocal(tok)

	if s.redisClient != nil {
		if err := s.saveToRedis(tok); err != nil {
			// Failing to populate the shared cache doesn't invalidate the
			// token we just successfully obtained - log and continue. This
			// replica just won't share it with others until a future write
			// succeeds.
			slog.Warn("OAuth2: failed to write token to redis cache", "error", err)
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

func (s *redisCachingTokenSource) getInner() xoauth2.TokenSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner
}

// Purge clears both cache tiers, so the next Token() call fetches a fresh
// token instead of reusing whatever is currently cached. Used when the
// upstream backend rejects the token this policy just injected (see
// OnResponseHeaders) - clearing only Redis would leave this same replica
// still serving the same rejected token from its own local tier.
//
// Clearing local and Redis alone is not enough: inner itself is typically an
// xoauth2.ReuseTokenSource (see buildTokenSource) that keeps reusing its own
// cached token until that token's own Expiry, regardless of what this cache
// does - a Purge() that only cleared local/Redis would still see the same
// stale token on the very next call, right up until it happened to expire
// naturally. Replacing inner with a freshly-built one (which starts with no
// cached token of its own) is what actually forces a real fetch. Rebuilding
// via buildTokenSource(s.params) can only fail on an unsupported grantType,
// which validateAndExtractParams already rejected before this token source
// was ever constructed - so if it does fail here, something more
// fundamental broke; keep the existing inner rather than leave it nil.
func (s *redisCachingTokenSource) Purge() {
	s.mu.Lock()
	s.local = nil
	if fresh, err := buildTokenSource(s.params); err == nil {
		s.inner = fresh
	} else {
		slog.Error("OAuth2: failed to rebuild token source while purging, keeping the existing one", "error", err)
	}
	s.mu.Unlock()

	if s.redisClient == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()
	if err := s.redisClient.Del(ctx, s.redisKey).Err(); err != nil {
		slog.Warn("OAuth2: failed to purge redis token cache entry", "error", err)
	}
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
		AccessToken:  ct.AccessToken,
		TokenType:    ct.TokenType,
		RefreshToken: ct.RefreshToken,
		Expiry:       ct.Expiry,
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
		AccessToken:  tok.AccessToken,
		TokenType:    tok.TokenType,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()
	return s.redisClient.Set(ctx, s.redisKey, data, ttl).Err()
}
