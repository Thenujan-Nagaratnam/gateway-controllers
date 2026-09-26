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
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Role is the part a model-failover instance plays in the two-hop pipeline.
// The front role sits on the client-facing LlmProxy route whose Envoy retry
// policy drives the chain; the dispatch role sits on the internal-listener
// route that every retry attempt passes through.
type Role string

const (
	RoleFront    Role = "front"
	RoleDispatch Role = "dispatch"
)

const (
	maxTargets     = 10
	maxModelLength = 256

	defaultPerAttemptTimeout    = 30 * time.Second
	minPerAttemptTimeout        = time.Second
	maxPerAttemptTimeout        = 300 * time.Second
	defaultSuspendAfterFailures = 3
	maxSuspendAfterFailures     = 100
	defaultSuspendDuration      = 30 * time.Second
	minSuspendDuration          = time.Second
	maxSuspendDuration          = 3600 * time.Second
	defaultProbeConcurrency     = 1
	maxProbeConcurrency         = 10
	defaultRecoverAfterProbes   = 2
	maxRecoverAfterProbes       = 20
	internalParamPrefix         = "_"
	paramInternalRole           = "_role"
	paramInternalChainID        = "_chainId"
	paramInternalTargetIDs      = "_targetIds"
	paramInternalTargetNative   = "_targetNative"
	paramInternalHopSecret      = "_hopSecret"
)

var (
	defaultFailoverStatusCodes = []int{429, 500, 502, 503, 504}
	durationPattern            = regexp.MustCompile(`^[0-9]+(ms|s|m)$`)
)

// Target is one entry of the ordered failover chain.
type Target struct {
	Provider string
	Model    string
	// ID is the controller-assigned stable identifier (t0, t1, ...). The
	// per-target upstream definition is named "failover-" + ID.
	ID string
	// Native is true when the target speaks the client's (OpenAI) format and
	// no transformer runs for it, so the dispatch hop rewrites "model" itself.
	Native bool
}

// UpstreamName is the per-target loopback upstream definition the controller
// generates for the dispatch route.
func (t Target) UpstreamName() string {
	return "failover-" + t.ID
}

// FailoverOn selects which attempt outcomes move the request to the next target.
type FailoverOn struct {
	StatusCodes    map[int]bool
	ConnectFailure bool
	Reset          bool
	Timeout        bool
}

// Config is the parsed policy configuration, combining the publisher-authored
// parameters with the controller-injected internal keys.
type Config struct {
	Targets                         []Target
	FailoverOn                      FailoverOn
	PerAttemptTimeout               time.Duration
	SuspendAfterConsecutiveFailures int
	SuspendDuration                 time.Duration
	ProbeConcurrency                int
	RecoverAfterSuccessfulProbes    int

	Role      Role
	ChainID   string
	HopSecret string
}

// parseConfig parses and validates params. Authored keys are validated against
// the bounds in the policy definition; omitted keys fall back to the schema
// default, distinguished from an explicit value by key presence.
func parseConfig(params map[string]interface{}) (*Config, error) {
	cfg := &Config{
		FailoverOn: FailoverOn{
			StatusCodes:    toSet(defaultFailoverStatusCodes),
			ConnectFailure: true,
			Reset:          true,
			Timeout:        true,
		},
		PerAttemptTimeout:               defaultPerAttemptTimeout,
		SuspendAfterConsecutiveFailures: defaultSuspendAfterFailures,
		SuspendDuration:                 defaultSuspendDuration,
		ProbeConcurrency:                defaultProbeConcurrency,
		RecoverAfterSuccessfulProbes:    defaultRecoverAfterProbes,
	}

	targets, err := parseTargets(params["targets"])
	if err != nil {
		return nil, err
	}
	cfg.Targets = targets

	if raw, ok := params["failoverOn"]; ok {
		if err := parseFailoverOn(raw, &cfg.FailoverOn); err != nil {
			return nil, err
		}
	}
	if raw, ok := params["perAttemptTimeout"]; ok {
		if cfg.PerAttemptTimeout, err = parseBoundedDuration("perAttemptTimeout", raw, minPerAttemptTimeout, maxPerAttemptTimeout); err != nil {
			return nil, err
		}
	}
	if raw, ok := params["suspendAfterConsecutiveFailures"]; ok {
		if cfg.SuspendAfterConsecutiveFailures, err = parseBoundedInt("suspendAfterConsecutiveFailures", raw, 1, maxSuspendAfterFailures); err != nil {
			return nil, err
		}
	}
	if raw, ok := params["suspendDuration"]; ok {
		if cfg.SuspendDuration, err = parseBoundedDuration("suspendDuration", raw, minSuspendDuration, maxSuspendDuration); err != nil {
			return nil, err
		}
	}
	if raw, ok := params["probeConcurrency"]; ok {
		if cfg.ProbeConcurrency, err = parseBoundedInt("probeConcurrency", raw, 1, maxProbeConcurrency); err != nil {
			return nil, err
		}
	}
	if raw, ok := params["recoverAfterSuccessfulProbes"]; ok {
		if cfg.RecoverAfterSuccessfulProbes, err = parseBoundedInt("recoverAfterSuccessfulProbes", raw, 1, maxRecoverAfterProbes); err != nil {
			return nil, err
		}
	}

	if err := parseInternal(params, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ValidateAuthoredParams rejects publisher-authored params that try to set a
// controller-internal key. The controller calls the equivalent check at
// registration; this is the runtime backstop for params that never passed
// through the controller.
func ValidateAuthoredParams(params map[string]interface{}) error {
	for k := range params {
		if strings.HasPrefix(k, internalParamPrefix) {
			return fmt.Errorf("parameter %q is reserved for gateway-internal use", k)
		}
	}
	_, err := parseAuthored(params)
	return err
}

func parseAuthored(params map[string]interface{}) (*Config, error) {
	withoutInternal := make(map[string]interface{}, len(params)+2)
	for k, v := range params {
		withoutInternal[k] = v
	}
	withoutInternal[paramInternalRole] = string(RoleFront)
	withoutInternal[paramInternalChainID] = "validation"
	return parseConfig(withoutInternal)
}

func parseTargets(raw interface{}) ([]Target, error) {
	if raw == nil {
		return nil, fmt.Errorf("'targets' is required")
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'targets' must be an array")
	}
	if len(list) == 0 || len(list) > maxTargets {
		return nil, fmt.Errorf("'targets' must contain between 1 and %d entries", maxTargets)
	}
	seen := make(map[string]int, len(list))
	targets := make([]Target, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("targets[%d] must be an object", i)
		}
		provider, err := requiredString(m, "provider", fmt.Sprintf("targets[%d]", i))
		if err != nil {
			return nil, err
		}
		model, err := requiredString(m, "model", fmt.Sprintf("targets[%d]", i))
		if err != nil {
			return nil, err
		}
		if len(model) > maxModelLength {
			return nil, fmt.Errorf("targets[%d].model must be at most %d characters", i, maxModelLength)
		}
		key := provider + "\x00" + model
		if prev, dup := seen[key]; dup {
			return nil, fmt.Errorf("targets[%d] duplicates targets[%d] (provider %q, model %q)", i, prev, provider, model)
		}
		seen[key] = i
		targets = append(targets, Target{Provider: provider, Model: model, ID: "t" + strconv.Itoa(i), Native: true})
	}
	return targets, nil
}

func parseFailoverOn(raw interface{}, out *FailoverOn) error {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("'failoverOn' must be an object")
	}
	if codesRaw, present := m["statusCodes"]; present {
		codes, ok := codesRaw.([]interface{})
		if !ok {
			return fmt.Errorf("'failoverOn.statusCodes' must be an array")
		}
		set := make(map[int]bool, len(codes))
		for i, c := range codes {
			code, err := toInt(c)
			if err != nil {
				return fmt.Errorf("failoverOn.statusCodes[%d]: %w", i, err)
			}
			if code != 429 && (code < 500 || code > 599) {
				return fmt.Errorf("failoverOn.statusCodes[%d]: %d is not allowed (must be 429 or 500-599)", i, code)
			}
			if set[code] {
				return fmt.Errorf("failoverOn.statusCodes[%d]: duplicate status code %d", i, code)
			}
			set[code] = true
		}
		out.StatusCodes = set
	}
	for _, f := range []struct {
		key string
		dst *bool
	}{
		{"connectFailure", &out.ConnectFailure},
		{"reset", &out.Reset},
		{"timeout", &out.Timeout},
	} {
		if v, present := m[f.key]; present {
			b, ok := v.(bool)
			if !ok {
				return fmt.Errorf("'failoverOn.%s' must be a boolean", f.key)
			}
			*f.dst = b
		}
	}
	return nil
}

func parseInternal(params map[string]interface{}, cfg *Config) error {
	role, _ := params[paramInternalRole].(string)
	switch Role(role) {
	case RoleFront, RoleDispatch:
		cfg.Role = Role(role)
	default:
		return fmt.Errorf("internal parameter %s must be %q or %q (is the gateway-controller up to date?)", paramInternalRole, RoleFront, RoleDispatch)
	}
	chainID, _ := params[paramInternalChainID].(string)
	if chainID == "" {
		return fmt.Errorf("internal parameter %s is required", paramInternalChainID)
	}
	cfg.ChainID = chainID

	if raw, ok := params[paramInternalTargetIDs]; ok {
		ids, ok := raw.([]interface{})
		if !ok || len(ids) != len(cfg.Targets) {
			return fmt.Errorf("internal parameter %s must list one id per target", paramInternalTargetIDs)
		}
		for i, v := range ids {
			id, ok := v.(string)
			if !ok || id == "" {
				return fmt.Errorf("internal parameter %s[%d] must be a non-empty string", paramInternalTargetIDs, i)
			}
			cfg.Targets[i].ID = id
		}
	}
	if raw, ok := params[paramInternalTargetNative]; ok {
		flags, ok := raw.([]interface{})
		if !ok || len(flags) != len(cfg.Targets) {
			return fmt.Errorf("internal parameter %s must list one flag per target", paramInternalTargetNative)
		}
		for i, v := range flags {
			b, ok := v.(bool)
			if !ok {
				return fmt.Errorf("internal parameter %s[%d] must be a boolean", paramInternalTargetNative, i)
			}
			cfg.Targets[i].Native = b
		}
	}
	if cfg.Role == RoleDispatch {
		secret, _ := params[paramInternalHopSecret].(string)
		if secret == "" {
			return fmt.Errorf("internal parameter %s is required for the dispatch role", paramInternalHopSecret)
		}
		cfg.HopSecret = secret
	}
	return nil
}

// planTTL bounds how long an attempt plan may live: every attempt at its
// per-attempt limit plus the Envoy retry back-off and a safety margin.
func (c *Config) planTTL() time.Duration {
	return time.Duration(len(c.Targets))*c.PerAttemptTimeout + 7*time.Second
}

func requiredString(m map[string]interface{}, key, path string) (string, error) {
	v, ok := m[key].(string)
	if !ok || strings.TrimSpace(v) == "" {
		return "", fmt.Errorf("%s.%s is required and must be a non-empty string", path, key)
	}
	return v, nil
}

func parseBoundedDuration(name string, raw interface{}, lo, hi time.Duration) (time.Duration, error) {
	s, ok := raw.(string)
	if !ok || !durationPattern.MatchString(s) {
		return 0, fmt.Errorf("'%s' must be a duration like 30s, 500ms or 2m", name)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("'%s': %w", name, err)
	}
	if d < lo || d > hi {
		return 0, fmt.Errorf("'%s' must be between %s and %s", name, lo, hi)
	}
	return d, nil
}

func parseBoundedInt(name string, raw interface{}, lo, hi int) (int, error) {
	n, err := toInt(raw)
	if err != nil {
		return 0, fmt.Errorf("'%s': %w", name, err)
	}
	if n < lo || n > hi {
		return 0, fmt.Errorf("'%s' must be between %d and %d", name, lo, hi)
	}
	return n, nil
}

func toInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if n != float64(int(n)) {
			return 0, fmt.Errorf("%v is not an integer", n)
		}
		return int(n), nil
	default:
		return 0, fmt.Errorf("expected an integer, got %T", v)
	}
}

func toSet(codes []int) map[int]bool {
	s := make(map[int]bool, len(codes))
	for _, c := range codes {
		s[c] = true
	}
	return s
}
