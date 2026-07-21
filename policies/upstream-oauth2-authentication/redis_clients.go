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
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisConnKey identifies a distinct Redis connection configuration. Two
// policy instances with identical connection settings share one
// *redis.Client (one pool) - mirrors the advanced-ratelimit policy's own
// redis_clients.go, the only other place in this codebase that talks to
// Redis directly.
type redisConnKey struct {
	addr         string
	username     string
	passwordHash string // sha256 hex; keeps the secret out of the in-process map key
	db           int
	dialTimeout  time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
	poolSize     int
}

// redisClients is the process-wide registry of shared Redis clients. Without
// it, GetPolicy would create a new *redis.Client (a whole connection pool)
// per policy instance and per config reload, leaking pools and exploding
// Redis connections at scale.
var redisClients = struct {
	mu sync.Mutex
	m  map[redisConnKey]*redis.Client
}{m: make(map[redisConnKey]*redis.Client)}

// hashSensitiveValue returns a SHA-256 hex digest of a secret value, for
// contexts where the value needs to be part of a lookup key (an in-process
// map key here; the Redis cache-key discriminator in
// oauth2ConfigDiscriminator, token_cache.go) without the raw secret ever
// appearing in that key. Empty stays empty rather than hashing the empty
// string, so an absent value doesn't collide with some future config that
// has an empty-but-present one, and so omitempty-tagged JSON fields that use
// this stay omitted.
func hashSensitiveValue(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// getOrCreateRedisClient returns the process-wide shared client for these
// connection settings, creating it on first use. Construction always
// succeeds regardless of whether Redis is actually reachable: Redis is a
// caching optimization layered over the real source of truth (the token
// endpoint), so a transient blip at gateway startup or config reload should
// leave OAuth2 authentication to the upstream backend working. go-redis
// connects lazily on the first actual command, and any error there is
// handled by the caller according to the configured failureMode.
func getOrCreateRedisClient(opts *redis.Options) *redis.Client {
	key := redisConnKey{
		addr:         opts.Addr,
		username:     opts.Username,
		passwordHash: hashSensitiveValue(opts.Password),
		db:           opts.DB,
		dialTimeout:  opts.DialTimeout,
		readTimeout:  opts.ReadTimeout,
		writeTimeout: opts.WriteTimeout,
		poolSize:     opts.PoolSize,
	}

	redisClients.mu.Lock()
	defer redisClients.mu.Unlock()

	if c, ok := redisClients.m[key]; ok {
		return c
	}

	c := redis.NewClient(opts)
	redisClients.m[key] = c
	return c
}
