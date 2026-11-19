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

package ratelimit

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisClientRegistry(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	addr := mr.Addr() // capture before any mr.Close() below
	opts := func(db int) *redis.Options { return &redis.Options{Addr: addr, DB: db} }

	// First call creates and pings.
	c1, created1, err1 := getOrCreateRedisClient(opts(0), "", time.Second)
	if !created1 || err1 != nil {
		t.Fatalf("first call: created=%v err=%v (want true,nil)", created1, err1)
	}

	// Identical config reuses the same client (no second create).
	c2, created2, err2 := getOrCreateRedisClient(opts(0), "", time.Second)
	if created2 || err2 != nil {
		t.Fatalf("second call: created=%v err=%v (want false,nil)", created2, err2)
	}
	if c1 != c2 {
		t.Fatal("expected the same *redis.Client for identical config")
	}

	// Reuse must NOT re-ping: close Redis, re-get -> still reused, no error.
	mr.Close()
	c3, created3, err3 := getOrCreateRedisClient(opts(0), "", time.Second)
	if created3 || err3 != nil || c3 != c1 {
		t.Fatalf("reuse after Redis down should skip ping: created=%v err=%v same=%v", created3, err3, c3 == c1)
	}

	// Different connection config (db) -> distinct client.
	c4, created4, _ := getOrCreateRedisClient(opts(1), "", time.Second)
	if !created4 || c4 == c1 {
		t.Fatalf("different db should create a distinct client (created=%v same=%v)", created4, c4 == c1)
	}
}
