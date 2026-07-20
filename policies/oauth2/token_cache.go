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
	// FailureModeOpen degrades to fetching directly from the token endpoint
	// when Redis is unavailable - a Redis outage costs caching, not auth.
	FailureModeOpen = "open"
	// FailureModeClosed treats a Redis error as a token-acquisition failure.
	FailureModeClosed = "closed"

	defaultRedisHost              = "localhost"
	defaultRedisPort              = 6379
	defaultRedisKeyPrefix         = "oauth2:token:v1:"
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

// buildRedisKey scopes the cached token to the API this policy instance is
// attached to - deliberately the API, not the individual route/resource.
// oauth2 config lives on upstream.auth, one value for the whole API, so
// every resource an LlmProvider/LlmProxy exposes (/chat/completions,
// /embeddings, ...) shares the exact same credentials and should share the
// exact same cached token. Keying by route as well would mint one
// redundant token (and one redundant token-endpoint call) per resource
// instead of one per API. grantType is deliberately NOT part of the key
// either: there is exactly one grantType per API's oauth2 config, so it can
// never disambiguate two entries for the same API - and even in the edge
// case of a live redeploy changing grantType, reusing a still-valid cached
// token from the old grant is harmless (the token itself doesn't carry or
// care which grant produced it).
func buildRedisKey(prefix, apiIdentity string) string {
	candidates := []string{strings.TrimSuffix(prefix, ":"), apiIdentity}
	var parts []string
	for _, s := range candidates {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ":")
}

// resolveAPIIdentity derives a stable per-API cache-key component,
// mirroring the semantic-cache policy's own convention
// ("<APIName>:<APIVersion>", sourced from SharedContext at request time).
//
// PolicyMetadata.APIId (passed into GetPolicy at construction time) is not
// usable for this: gateway-controller's PolicyChainConfig xDS resource
// never populates an api_id in its wire metadata (a pre-existing gap
// affecting every policy attached this way, not something specific to
// oauth2), so it is always empty by the time it reaches GetPolicy.
// SharedContext.APIId/APIName/APIVersion, by contrast, ARE reliably
// populated per-request - they come from a different xDS resource
// (RouteConfig) that does carry the real API UUID - so they're read here,
// lazily, on the first real request, rather than at construction time.
//
// metadata.RouteName is used only as a last-resort fallback if even those
// are empty - correct-but-overly-narrow (see buildRedisKey), never
// incorrect.
func resolveAPIIdentity(reqCtx *policy.RequestHeaderContext, routeNameFallback string) string {
	if reqCtx != nil && reqCtx.SharedContext != nil {
		if reqCtx.APIId != "" {
			return reqCtx.APIId
		}
		if reqCtx.APIName != "" || reqCtx.APIVersion != "" {
			return reqCtx.APIName + ":" + reqCtx.APIVersion
		}
	}
	return routeNameFallback
}

// cachedToken is the JSON shape stored in Redis - just the fields needed to
// reconstruct an xoauth2.Token.
type cachedToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry"`
}

// tokenProvider is satisfied by redisCachingTokenSource. Unlike
// xoauth2.TokenSource, Token() takes the request-header context: the Redis
// cache key can only be resolved correctly from data (SharedContext.APIId
// et al.) that's only available at request time, not from anything passed
// into GetPolicy at construction time - see resolveAPIIdentity.
type tokenProvider interface {
	Token(reqCtx *policy.RequestHeaderContext) (*xoauth2.Token, error)
}

// redisCachingTokenSource wraps a real, IDP-fetching xoauth2.TokenSource
// with a two-tier cache:
//  1. A per-process in-memory token - near-zero latency on the hot path,
//     the same guarantee the plain xoauth2.ReuseTokenSource gave before.
//  2. A shared Redis entry - lets every gateway-runtime replica reuse the
//     same token instead of each independently hitting the token endpoint,
//     and survives an individual replica restart.
//
// Redis is treated as an optimization layered on top of the token endpoint,
// not a hard dependency: a Redis error either falls back to fetching
// directly from the token endpoint (failOpen=true, the default) or is
// surfaced as a token-acquisition failure (failOpen=false), per the
// redis.failureMode param.
type redisCachingTokenSource struct {
	inner             xoauth2.TokenSource
	redisClient       *redis.Client // nil disables the Redis tier entirely
	keyPrefix         string
	routeNameFallback string
	failOpen          bool
	readTimeout       time.Duration
	writeTimeout      time.Duration

	// defaultTTL is applied to a freshly-fetched token whose Expiry is the
	// zero value - see the comment at its use site in Token() for why.
	defaultTTL time.Duration

	mu       sync.Mutex
	local    *xoauth2.Token
	redisKey string // resolved lazily from the first request - see resolveAPIIdentity
}

// newRedisCachingTokenSource builds the cache wrapper around inner. metadata
// is kept only for its RouteName, used as a last-resort fallback when
// deriving the Redis key (see resolveAPIIdentity) - the wrapper otherwise
// knows nothing about how inner fetches tokens.
func newRedisCachingTokenSource(inner xoauth2.TokenSource, rp redisParams, metadata policy.PolicyMetadata, defaultTTL time.Duration) tokenProvider {
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
		// cache already has a fallback (fetch directly from the token
		// endpoint) for exactly the case a Redis command fails, so paying
		// for automatic retries here is pure added latency on the fail-open
		// path with no corresponding benefit - fail fast into the fallback
		// instead of retrying a command whose result we'll discard anyway.
		MaxRetries: -1,
	})

	return &redisCachingTokenSource{
		inner:             inner,
		redisClient:       client,
		keyPrefix:         rp.keyPrefix,
		routeNameFallback: metadata.RouteName,
		failOpen:          rp.failureMode != FailureModeClosed,
		readTimeout:       rp.readTimeout,
		writeTimeout:      rp.writeTimeout,
		defaultTTL:        defaultTTL,
	}
}

func (s *redisCachingTokenSource) Token(reqCtx *policy.RequestHeaderContext) (*xoauth2.Token, error) {
	s.ensureRedisKey(reqCtx)

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

	tok, err := s.inner.Token()
	if err != nil {
		return nil, err
	}
	if tok.Expiry.IsZero() {
		// Some IdPs omit expires_in entirely; golang.org/x/oauth2 leaves
		// Expiry as the zero value in that case, and Token.Valid() always
		// treats a zero-value Expiry as already-expired. Left unfixed, that
		// would mean this cache tier AND the inner xoauth2.ReuseTokenSource's
		// own reuse-until-expiry behavior would both silently never cache
		// the token, refetching on every single request. Mutate tok in
		// place (not a copy): s.inner's own cached copy is the same
		// underlying pointer, so this fixes the expiry for both.
		tok.Expiry = time.Now().Add(s.defaultTTL)
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

// ensureRedisKey resolves and fixes the Redis key on the first call only.
// Safe to call unconditionally on every Token() invocation - a route (and
// thus the API it belongs to) never changes over a policy instance's
// lifetime, so resolving once and reusing thereafter is correct, not just
// an optimization.
func (s *redisCachingTokenSource) ensureRedisKey(reqCtx *policy.RequestHeaderContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.redisKey != "" {
		return
	}
	s.redisKey = buildRedisKey(s.keyPrefix, resolveAPIIdentity(reqCtx, s.routeNameFallback))
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
