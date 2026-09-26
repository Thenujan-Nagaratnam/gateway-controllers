/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package modelfailover

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_800_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestPlanAdvanceWalksEachTargetOnce(t *testing.T) {
	r := newPlanRegistry(newFakeClock().now)
	nonce, err := r.create("c1", []int{0, 2}, nil, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 32 {
		t.Fatalf("nonce must be 128-bit hex, got %q", nonce)
	}
	a, plan, err := r.advance(nonce, "c1")
	if err != nil || a.targetIdx != 0 || a.position != 0 || a.timedOutTarget != -1 {
		t.Fatalf("first advance: %+v %v", a, err)
	}
	plan.record(a.position, Outcome{Class: OutcomeEligibleFailure, Reason: "status_429"})
	a, _, err = r.advance(nonce, "c1")
	if err != nil || a.targetIdx != 2 || a.position != 1 || a.timedOutTarget != -1 {
		t.Fatalf("second advance must skip index 1: %+v %v", a, err)
	}
	if _, _, err := r.advance(nonce, "c1"); !errors.Is(err, errPlanExhausted) {
		t.Fatalf("third advance must report exhaustion, got %v", err)
	}
}

func TestPlanAdvanceInfersTimeout(t *testing.T) {
	r := newPlanRegistry(newFakeClock().now)
	nonce, _ := r.create("c1", []int{0, 1}, nil, time.Minute, nil)
	if _, _, err := r.advance(nonce, "c1"); err != nil {
		t.Fatal(err)
	}
	// No outcome recorded for attempt 0: Envoy abandoned it on per-try timeout.
	a, plan, err := r.advance(nonce, "c1")
	if err != nil || a.timedOutTarget != 0 {
		t.Fatalf("expected timeout inference for target 0: %+v %v", a, err)
	}
	if plan.record(0, Outcome{Class: OutcomeSuccess}) {
		t.Fatal("a late outcome must not overwrite the inferred timeout")
	}
}

func TestPlanRejectsUnknownMismatchedAndExpired(t *testing.T) {
	clock := newFakeClock()
	r := newPlanRegistry(clock.now)
	if _, _, err := r.advance("deadbeef", "c1"); !errors.Is(err, errUnknownPlan) {
		t.Fatalf("unknown nonce: %v", err)
	}
	nonce, _ := r.create("c1", []int{0}, nil, time.Second, nil)
	if _, _, err := r.advance(nonce, "other"); !errors.Is(err, errChainMismatch) {
		t.Fatalf("chain mismatch: %v", err)
	}
	clock.advance(2 * time.Second)
	if _, _, err := r.advance(nonce, "c1"); !errors.Is(err, errUnknownPlan) {
		t.Fatalf("expired plan: %v", err)
	}
}

func TestPlanSweepHandsExpiredPlansToHook(t *testing.T) {
	clock := newFakeClock()
	r := newPlanRegistry(clock.now)
	var expired []string
	hook := func(p *attemptPlan) { expired = append(expired, p.chainID) }
	_, _ = r.create("short", []int{0}, nil, time.Second, hook)
	_, _ = r.create("long", []int{0}, nil, time.Hour, hook)
	clock.advance(2 * time.Second)
	r.sweep()
	if len(expired) != 1 || expired[0] != "short" || r.size() != 1 {
		t.Fatalf("sweep: expired=%v size=%d", expired, r.size())
	}
}

func TestPlanConcurrentAdvanceHandsOutDistinctPositions(t *testing.T) {
	r := newPlanRegistry(newFakeClock().now)
	targets := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	nonce, _ := r.create("c1", targets, nil, time.Minute, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[int]bool{}
	for range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, plan, err := r.advance(nonce, "c1")
			if err != nil {
				t.Error(err)
				return
			}
			plan.record(a.position, Outcome{Class: OutcomeEligibleFailure})
			mu.Lock()
			seen[a.position] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != len(targets) {
		t.Fatalf("expected %d distinct positions, got %d", len(targets), len(seen))
	}
}

func TestPlanCloseRemoves(t *testing.T) {
	r := newPlanRegistry(newFakeClock().now)
	nonce, _ := r.create("c1", []int{0}, nil, time.Minute, nil)
	if r.close(nonce) == nil || r.close(nonce) != nil || r.size() != 0 {
		t.Fatal("close must remove the plan exactly once")
	}
}

func TestPlanCompletionHookRunsOnceAndReportsUnusedProbes(t *testing.T) {
	r := newPlanRegistry(newFakeClock().now)
	var runs int
	var unused []int
	nonce, _ := r.create("c1", []int{0, 1, 2}, map[int]bool{1: true, 2: true}, time.Minute, func(p *attemptPlan) {
		runs++
		unused = p.unrecordedProbes()
	})
	a, plan, _ := r.advance(nonce, "c1")
	plan.record(a.position, Outcome{Class: OutcomeEligibleFailure})
	a, plan, _ = r.advance(nonce, "c1") // probe target 1
	plan.record(a.position, Outcome{Class: OutcomeSuccess, Probe: true})
	r.close(nonce)
	r.close(nonce)
	if runs != 1 {
		t.Fatalf("hook ran %d times", runs)
	}
	if len(unused) != 1 || unused[0] != 2 {
		t.Fatalf("only probe target 2 went unused, got %v", unused)
	}
}
