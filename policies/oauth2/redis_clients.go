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

func hashRedisPassword(p string) string {
	if p == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// getOrCreateRedisClient returns the process-wide shared client for these
// connection settings, creating it on first use.
//
// Unlike advanced-ratelimit's equivalent, this deliberately does NOT ping on
// creation and does NOT fail if the ping fails: for rate-limiting, Redis
// being reachable is core to the feature's correctness, so a synchronous
// health check at construction time is worth it. For this policy, Redis is
// purely a caching optimization layered over the real source of truth (the
// token endpoint) - construction must never block on or fail over Redis's
// availability, since a transient Redis blip at gateway startup or config
// reload must not take down OAuth2 authentication to the upstream backend.
// go-redis connects lazily on the first actual command, and any error there
// is handled by the caller according to the configured failureMode.
func getOrCreateRedisClient(opts *redis.Options) *redis.Client {
	key := redisConnKey{
		addr:         opts.Addr,
		username:     opts.Username,
		passwordHash: hashRedisPassword(opts.Password),
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
