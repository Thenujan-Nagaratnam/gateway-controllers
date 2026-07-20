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

// buildRedisKey scopes the cached token to a discriminator, not to the
// API/route this policy instance happens to be attached to. See
// oauth2ConfigDiscriminator for what the discriminator is derived from and
// why: two different oauth2 configs attached to the very same API (e.g. a
// primary provider and an additionalProviders entry on one LlmProxy, each
// with independent credentials) must land on different keys, while two
// different APIs configured with byte-identical oauth2 config legitimately
// share one.
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

	// Params (scope, audience, resource, tenant, ...) MUST be part of the
	// discriminator: two configs sharing clientId/tokenEndpoint but
	// requesting different scopes are not interchangeable - serving one's
	// cached token to the other would hand out the wrong scope. encoding/
	// json sorts map[string]string keys alphabetically when marshaling, so
	// this is stable regardless of the map's iteration order.
	Params map[string]string `json:"params,omitempty"`

	// ClientSecretHash and PasswordHash bind the cache entry to the specific
	// credential that was actually presented - see oauth2ConfigDiscriminator
	// for why these must be included despite an earlier version of this
	// function deliberately leaving them out.
	ClientSecretHash string `json:"clientSecretHash"`
	PasswordHash     string `json:"passwordHash,omitempty"`
}

// oauth2ConfigDiscriminator derives a stable cache-key component from the
// oauth2 configuration itself, mirroring Kong's Upstream OAuth plugin (the
// closest comparable product, cross-checked in oauth2-upstream-auth.md),
// which caches "using a hash of all values configured under config.oauth" -
// two plugin instances with identical oauth2 config share a cached token
// regardless of which route/service they're attached to, and two instances
// with different config never collide.
//
// This is keyed on the parsed, already-validated oauth2Params - available
// synchronously at GetPolicy/construction time - rather than on any
// request-time API identity, which is what buildRedisKey used before this
// and the reason it previously had to lazily resolve the key from the first
// request's SharedContext (see git history). Fixing the key to construction
// time also fixes the underlying bug that made the lazy resolution
// necessary in the first place: a proxy's primary provider and an
// additionalProviders entry can carry entirely different oauth2 credentials
// while being attached to the very same API, so keying by API identity
// alone let one provider's cached token be served to another provider's
// backend.
//
// clientSecret and password ARE included, as a SHA-256 hash rather than the
// raw value (never put raw secret material into a Redis key - key names
// appear in Redis MONITOR/slowlog output; redis_clients.go's
// hashRedisPassword follows the same principle for the Redis connection
// password). An earlier version of this function left both out entirely, on
// the reasoning that a cached token represents "this client, with this
// scope" rather than "whichever secret proved it this time", so rotating a
// secret for the same clientId/tokenEndpoint shouldn't invalidate a
// still-valid cached token. That reasoning has a real hole: clientId and
// tokenEndpoint alone do not prove two configs are the same authorized
// caller - a live end-to-end run of this exact scenario (a second LlmProvider
// registered with the same clientId/tokenEndpoint as an existing one but a
// deliberately wrong clientSecret, to test that bad credentials are
// rejected) demonstrated the gap directly: the wrong-secret config's request
// was served the OTHER config's legitimately-cached token from Redis and
// spuriously succeeded, instead of failing as its own (wrong) credential
// should have caused it to. The same failure mode applies to password (the
// password grant's equivalent proof-of-identity). Hashing them into the key
// means a secret rotation costs one extra token fetch after the redeploy
// (the old entry is simply never looked up again) - a negligible, one-time
// price for closing a real cross-credential token reuse hole.
func oauth2ConfigDiscriminator(p oauth2Params) string {
	fields := oauth2CacheKeyFields{
		GrantType:        p.grantType,
		TokenEndpoint:    p.tokenEndpoint,
		ClientID:         p.clientID,
		ClientAuthMethod: p.clientAuthMethod,
		Username:         p.username,
		Params:           p.customParams,
		ClientSecretHash: hashSecret(p.clientSecret),
		PasswordHash:     hashSecret(p.password),
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

// hashSecret returns a SHA-256 hex digest of a secret value for inclusion in
// the cache-key discriminator - never the raw value, per
// oauth2ConfigDiscriminator's doc comment. Empty stays empty (rather than
// hashing the empty string) purely to keep the JSON field omitted via
// omitempty - password is unset entirely for client_credentials, and this
// keeps that case's serialized bytes identical to before password support
// existed rather than embedding sha256("")'s digest for every such config.
func hashSecret(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
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

// tokenProvider is satisfied by redisCachingTokenSource. Same shape as
// xoauth2.TokenSource - no request-time context is needed to look up the
// cache entry, since the Redis key is derived entirely from the oauth2
// config at construction time (see oauth2ConfigDiscriminator).
type tokenProvider interface {
	Token() (*xoauth2.Token, error)
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
	inner        xoauth2.TokenSource
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
// only reads it to derive the Redis key (see oauth2ConfigDiscriminator) and
// the cache TTL fallback; it otherwise knows nothing about how inner
// actually fetches tokens.
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
		// MaxRetries: -1 disables go-redis's own command-level retries. This
		// cache already has a fallback (fetch directly from the token
		// endpoint) for exactly the case a Redis command fails, so paying
		// for automatic retries here is pure added latency on the fail-open
		// path with no corresponding benefit - fail fast into the fallback
		// instead of retrying a command whose result we'll discard anyway.
		MaxRetries: -1,
	})

	return &redisCachingTokenSource{
		inner:        inner,
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
