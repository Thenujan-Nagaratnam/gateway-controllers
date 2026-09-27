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
	"sync"
	"time"
)

// TargetState is where a target is in its health lifecycle:
//
//	healthy   --N consecutive eligible failures--> suspended
//	suspended --suspendDuration elapsed----------> probing
//	probing   --M consecutive probe successes----> healthy
//	probing   --any probe failure----------------> suspended
type TargetState int

const (
	StateHealthy TargetState = iota
	StateSuspended
	StateProbing
)

func (s TargetState) String() string {
	switch s {
	case StateSuspended:
		return "suspended"
	case StateProbing:
		return "probing"
	}
	return "healthy"
}

// targetHealth is the runtime state of one target.
type targetHealth struct {
	mu                  sync.Mutex
	state               TargetState
	consecutiveFailures int
	suspendedUntil      time.Time
	probeSuccesses      int
	probesInFlight      int
}

// Transition reports a state change, for logs.
type Transition struct {
	ChainID  string
	Target   Target
	From, To TargetState
	// Failures is the consecutive-failure count that caused a suspension.
	Failures int
	// Until is when a suspension ends.
	Until time.Time
	// ProbeSuccesses is the count that ended a recovery.
	ProbeSuccesses int
}

// healthRegistry tracks every target of every chain in this process. Targets
// are keyed by chain plus provider and model, so a config update that keeps a
// target keeps its state even if its position in the chain moves, and a
// changed (provider, model) pair starts healthy.
type healthRegistry struct {
	mu      sync.Mutex
	entries map[string]*targetHealth
	now     func() time.Time
}

func newHealthRegistry(now func() time.Time) *healthRegistry {
	return &healthRegistry{entries: make(map[string]*targetHealth), now: now}
}

var globalHealth = newHealthRegistry(time.Now)

func healthKey(chainID string, t Target) string {
	return chainID + "\x00" + t.Provider + "\x00" + t.Model
}

func (r *healthRegistry) get(chainID string, t Target) *targetHealth {
	key := healthKey(chainID, t)
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.entries[key]
	if h == nil {
		h = &targetHealth{}
		r.entries[key] = h
	}
	return h
}

// admit decides which targets a new request may try, in chain order. Healthy
// targets are always included. A suspended target whose suspension has ended
// moves to probing. A probing target is included only if it can take one of
// the limited probe slots; the claimed slot is reported in probes and must be
// given back through record or release.
func (r *healthRegistry) admit(cfg *Config) (targets []int, probes map[int]bool, transitions []Transition) {
	now := r.now()
	for i, t := range cfg.Targets {
		h := r.get(cfg.ChainID, t)
		h.mu.Lock()
		if h.state == StateSuspended && !now.Before(h.suspendedUntil) {
			transitions = append(transitions, Transition{ChainID: cfg.ChainID, Target: t, From: StateSuspended, To: StateProbing})
			h.state = StateProbing
			h.probeSuccesses = 0
			h.probesInFlight = 0
		}
		switch h.state {
		case StateHealthy:
			targets = append(targets, i)
		case StateProbing:
			if h.probesInFlight < cfg.ProbeConcurrency {
				h.probesInFlight++
				targets = append(targets, i)
				if probes == nil {
					probes = map[int]bool{}
				}
				probes[i] = true
			}
		}
		h.mu.Unlock()
	}
	return targets, probes, transitions
}

// record applies one attempt's outcome to its target.
func (r *healthRegistry) record(cfg *Config, targetIdx int, o Outcome) *Transition {
	t := cfg.Targets[targetIdx]
	h := r.get(cfg.ChainID, t)
	h.mu.Lock()
	defer h.mu.Unlock()
	if o.Probe && h.probesInFlight > 0 {
		h.probesInFlight--
	}

	switch h.state {
	case StateHealthy:
		if o.Class != OutcomeEligibleFailure {
			h.consecutiveFailures = 0
			return nil
		}
		h.consecutiveFailures++
		if h.consecutiveFailures < cfg.SuspendAfterConsecutiveFailures {
			return nil
		}
		return h.suspend(cfg, t, StateHealthy, r.now())

	case StateProbing:
		if !o.Probe {
			// A request admitted before the target was suspended finished
			// late; it says nothing about recovery.
			return nil
		}
		if o.Class == OutcomeEligibleFailure {
			return h.suspend(cfg, t, StateProbing, r.now())
		}
		h.probeSuccesses++
		if h.probeSuccesses < cfg.RecoverAfterSuccessfulProbes {
			return nil
		}
		tr := &Transition{ChainID: cfg.ChainID, Target: t, From: StateProbing, To: StateHealthy, ProbeSuccesses: h.probeSuccesses}
		h.state = StateHealthy
		h.consecutiveFailures = 0
		h.probeSuccesses = 0
		return tr
	}
	// Suspended: outcomes of requests admitted before the suspension are
	// ignored.
	return nil
}

func (h *targetHealth) suspend(cfg *Config, t Target, from TargetState, now time.Time) *Transition {
	failures := h.consecutiveFailures
	h.state = StateSuspended
	h.suspendedUntil = now.Add(cfg.SuspendDuration)
	h.consecutiveFailures = 0
	h.probeSuccesses = 0
	h.probesInFlight = 0
	return &Transition{ChainID: cfg.ChainID, Target: t, From: from, To: StateSuspended, Failures: failures, Until: h.suspendedUntil}
}

// release gives back a probe slot whose attempt produced no outcome: the
// chain succeeded before reaching the target, or the client went away.
func (r *healthRegistry) release(cfg *Config, targetIdx int) {
	h := r.get(cfg.ChainID, cfg.Targets[targetIdx])
	h.mu.Lock()
	if h.state == StateProbing && h.probesInFlight > 0 {
		h.probesInFlight--
	}
	h.mu.Unlock()
}

// state reports a target's current state, for tests and logs.
func (r *healthRegistry) state(cfg *Config, targetIdx int) TargetState {
	h := r.get(cfg.ChainID, cfg.Targets[targetIdx])
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}
