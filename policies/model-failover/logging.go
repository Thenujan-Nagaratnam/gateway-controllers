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
	"context"
	"log/slog"
	"time"
)

// The events below are the contract in contracts/observability.md. They carry
// target identity and outcome only: never header values, bodies, credentials
// or the hop secret.

func logAttemptFailed(ctx context.Context, requestID, chainID string, t Target, position int, reason string, latency time.Duration) {
	slog.WarnContext(ctx, "model_failover.attempt_failed",
		"request_id", requestID, "chain", chainID, "target", t.ID,
		"provider", t.Provider, "model", t.Model, "position", position,
		"reason", reason, "latency_ms", latency.Milliseconds())
}

func logServed(ctx context.Context, requestID, chainID string, t Target, position, attempts int) {
	level := slog.LevelInfo
	if position == 0 {
		level = slog.LevelDebug
	}
	slog.Log(ctx, level, "model_failover.served",
		"request_id", requestID, "chain", chainID, "target", t.ID,
		"position", position, "attempts", attempts)
}

func logExhausted(ctx context.Context, requestID, chainID, cause string, attempted int) {
	slog.WarnContext(ctx, "model_failover.exhausted",
		"request_id", requestID, "chain", chainID, "cause", cause, "attempted_targets", attempted)
}

func logTransitions(ctx context.Context, transitions ...*Transition) {
	for _, tr := range transitions {
		if tr == nil {
			continue
		}
		switch tr.To {
		case StateSuspended:
			slog.WarnContext(ctx, "model_failover.target_suspended",
				"chain", tr.ChainID, "target", tr.Target.ID, "provider", tr.Target.Provider,
				"model", tr.Target.Model, "consecutive_failures", tr.Failures,
				"suspended_until", tr.Until.UTC().Format(time.RFC3339))
		case StateProbing:
			slog.InfoContext(ctx, "model_failover.target_probing",
				"chain", tr.ChainID, "target", tr.Target.ID, "provider", tr.Target.Provider, "model", tr.Target.Model)
		case StateHealthy:
			slog.InfoContext(ctx, "model_failover.target_recovered",
				"chain", tr.ChainID, "target", tr.Target.ID, "provider", tr.Target.Provider,
				"model", tr.Target.Model, "probe_successes", tr.ProbeSuccesses)
		}
	}
}

func transitionPtrs(ts []Transition) []*Transition {
	out := make([]*Transition, len(ts))
	for i := range ts {
		out[i] = &ts[i]
	}
	return out
}
