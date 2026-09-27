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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// OutcomeClass classifies a single attempt's result.
type OutcomeClass string

const (
	OutcomeSuccess         OutcomeClass = "success"
	OutcomeNonEligible     OutcomeClass = "non_eligible"
	OutcomeEligibleFailure OutcomeClass = "eligible_failure"
)

// Outcome is the recorded result of one attempt.
type Outcome struct {
	Class    OutcomeClass
	Reason   string
	Probe    bool
	recorded bool
}

var (
	errUnknownPlan   = errors.New("unknown or expired attempt plan")
	errChainMismatch = errors.New("attempt plan belongs to a different chain")
	errPlanExhausted = errors.New("attempt plan has no targets left")
)

// attemptPlan is the per-request list of targets, in order, that the Envoy
// retry loop walks. Built by the front hop, advanced once per dispatch-hop
// arrival. Suspended targets are already excluded, so walking it tries each
// available target at most once.
type attemptPlan struct {
	chainID string
	// targets holds indices into Config.Targets.
	targets []int
	// probes marks target indices admitted as recovery probes; their slots
	// must be released exactly once.
	probes map[int]bool
	// passThrough is true while the request's model has no chain: its single
	// attempt forwards the request unchanged and is never retried.
	passThrough bool

	mu        sync.Mutex
	cursor    int
	outcomes  []Outcome
	expiresAt time.Time

	// onDone runs exactly once, when the front hop closes the plan or the
	// sweeper expires it, to give back probe slots nobody used.
	onDone   func(*attemptPlan)
	doneOnce sync.Once
}

// finish runs the plan's completion hook once.
func (p *attemptPlan) finish() {
	p.doneOnce.Do(func() {
		if p.onDone != nil {
			p.onDone(p)
		}
	})
}

// unrecordedProbes lists the probe targets that never produced an outcome:
// the chain stopped before reaching them, or their attempt was cut off.
func (p *attemptPlan) unrecordedProbes() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []int
	for pos, idx := range p.targets {
		if p.probes[idx] && !p.outcomes[pos].recorded {
			out = append(out, idx)
		}
	}
	return out
}

// attempt describes the target a dispatch-hop arrival must use.
type attempt struct {
	position  int
	targetIdx int
	probe     bool
	// timedOutTarget is the target index of the previous attempt when it
	// never recorded an outcome, meaning Envoy abandoned it on its
	// per-try timeout; -1 otherwise.
	timedOutTarget int
}

// planRegistry holds live attempt plans. It is shared by the front and
// dispatch instances of every chain in the process: both hops call the same
// policy-engine process, so a nonce minted by the front hop resolves here.
type planRegistry struct {
	mu        sync.Mutex
	plans     map[string]*attemptPlan
	now       func() time.Time
	sweepOnce sync.Once
}

func newPlanRegistry(now func() time.Time) *planRegistry {
	return &planRegistry{plans: make(map[string]*attemptPlan), now: now}
}

var globalPlans = newPlanRegistry(time.Now)

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// createPassThrough stores a one-attempt pass-through plan and returns its
// nonce. The front hop retargets it once it knows the request's chain.
func (r *planRegistry) createPassThrough(chainID string, target int, ttl time.Duration) (string, error) {
	nonce, err := r.create(chainID, []int{target}, nil, ttl, nil)
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	r.plans[nonce].passThrough = true
	r.mu.Unlock()
	return nonce, nil
}

// retarget replaces a plan's targets with a chain's before any attempt has
// been dispatched, and ends pass-through. It reports false if the plan is gone
// or already advanced.
func (r *planRegistry) retarget(nonce string, targets []int, probes map[int]bool, onDone func(*attemptPlan)) bool {
	p := r.get(nonce)
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cursor != 0 {
		return false
	}
	p.targets = targets
	p.probes = probes
	p.outcomes = make([]Outcome, len(targets))
	p.passThrough = false
	p.onDone = onDone
	return true
}

// isPassThrough reports whether the plan forwards the request unchanged.
func (p *attemptPlan) isPassThrough() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.passThrough
}

// create stores a new plan and returns its nonce. onDone may be nil.
func (r *planRegistry) create(chainID string, targets []int, probes map[int]bool, ttl time.Duration, onDone func(*attemptPlan)) (string, error) {
	nonce, err := newNonce()
	if err != nil {
		return "", err
	}
	p := &attemptPlan{
		chainID:   chainID,
		targets:   targets,
		probes:    probes,
		outcomes:  make([]Outcome, len(targets)),
		expiresAt: r.now().Add(ttl),
		onDone:    onDone,
	}
	r.mu.Lock()
	r.plans[nonce] = p
	r.mu.Unlock()
	return nonce, nil
}

func (r *planRegistry) get(nonce string) *attemptPlan {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.plans[nonce]
	if p == nil || !r.now().Before(p.expiresAt) {
		return nil
	}
	return p
}

// advance hands the next target of the plan to a dispatch-hop arrival.
func (r *planRegistry) advance(nonce, chainID string) (attempt, *attemptPlan, error) {
	p := r.get(nonce)
	if p == nil {
		return attempt{}, nil, errUnknownPlan
	}
	if p.chainID != chainID {
		return attempt{}, nil, errChainMismatch
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	a := attempt{position: p.cursor, timedOutTarget: -1}
	if p.cursor > 0 && !p.outcomes[p.cursor-1].recorded {
		a.timedOutTarget = p.targets[p.cursor-1]
		p.outcomes[p.cursor-1] = Outcome{Class: OutcomeEligibleFailure, Reason: reasonTimeout, Probe: p.probes[p.targets[p.cursor-1]], recorded: true}
	}
	if p.cursor >= len(p.targets) {
		return a, p, errPlanExhausted
	}
	a.targetIdx = p.targets[p.cursor]
	a.probe = p.probes[a.targetIdx]
	p.cursor++
	return a, p, nil
}

// record stores an attempt's outcome. It reports false when an outcome was
// already recorded for that position (e.g. inferred as a timeout).
func (p *attemptPlan) record(position int, o Outcome) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if position < 0 || position >= len(p.outcomes) || p.outcomes[position].recorded {
		return false
	}
	o.recorded = true
	p.outcomes[position] = o
	return true
}

// lastAttempted returns the position and target index of the most recent
// attempt, or ok=false if no attempt was dispatched.
func (p *attemptPlan) lastAttempted() (position, targetIdx int, recorded, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cursor == 0 {
		return 0, 0, false, false
	}
	pos := p.cursor - 1
	return pos, p.targets[pos], p.outcomes[pos].recorded, true
}

// attempts returns how many attempts were dispatched.
func (p *attemptPlan) attempts() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cursor
}

// close removes the plan and runs its completion hook. It returns the plan,
// or nil if it was already gone.
func (r *planRegistry) close(nonce string) *attemptPlan {
	r.mu.Lock()
	p := r.plans[nonce]
	delete(r.plans, nonce)
	r.mu.Unlock()
	if p != nil {
		p.finish()
	}
	return p
}

// peek returns a plan even if it has expired but not yet been swept, so the
// front hop can still attribute the final attempt.
func (r *planRegistry) peek(nonce string) *attemptPlan {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.plans[nonce]
}

// sweep removes expired plans and runs their completion hooks.
func (r *planRegistry) sweep() {
	now := r.now()
	var expired []*attemptPlan
	r.mu.Lock()
	for nonce, p := range r.plans {
		if !now.Before(p.expiresAt) {
			expired = append(expired, p)
			delete(r.plans, nonce)
		}
	}
	r.mu.Unlock()
	for _, p := range expired {
		p.finish()
	}
}

// startSweeper runs sweep every interval for the life of the process.
func (r *planRegistry) startSweeper(interval time.Duration) {
	r.sweepOnce.Do(func() {
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for range t.C {
				r.sweep()
			}
		}()
	})
}

func (r *planRegistry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.plans)
}
