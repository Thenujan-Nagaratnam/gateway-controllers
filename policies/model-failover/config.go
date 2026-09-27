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
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
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
	maxChains         = 20
	maxFallbacks      = 9
	maxTargets        = 50
	maxModelLength    = 256
	passThroughTarget = "tp"

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
	paramInternalRouteToTarget  = "_routeToTarget"
)

var (
	defaultFailoverStatusCodes = []int{429, 500, 502, 503, 504}
	durationPattern            = regexp.MustCompile(`^[0-9]+(ms|s|m)$`)
)

// Target is one provider and model a chain can try; the unit of health.
// Config.Targets holds every distinct target of every chain, followed by the
// pass-through target (empty Model), which forwards a request whose model
// has no chain without changing it.
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
	Targets []Target
	// Chains maps each primary model to its chain: indices into Targets,
	// primary first, then fallbacks in order.
	Chains map[string][]int
	// PassThrough is the index of the pass-through target (always last).
	PassThrough int

	FailoverOn                      FailoverOn
	PerAttemptTimeout               time.Duration
	SuspendAfterConsecutiveFailures int
	SuspendDuration                 time.Duration
	ProbeConcurrency                int
	RecoverAfterSuccessfulProbes    int

	Role      Role
	ChainID   string
	HopSecret string
	// RouteToTarget is false when every target shares the route's own
	// upstream (model-failover on an LlmProvider): the dispatch role then
	// selects no upstream and only rewrites the model.
	RouteToTarget bool
	// RequestModel says where a native target's model goes in the request.
	// The controller copies it from the LLM provider template. It applies on
	// an LlmProvider only; on an LlmProxy native targets speak the client's
	// OpenAI format, so it is always the top-level "model" of the JSON body.
	RequestModel RequestModel
}

// Model locations a provider template's requestModel can name.
const (
	LocationPayload    = "payload"
	LocationHeader     = "header"
	LocationQueryParam = "queryParam"
	LocationPathParam  = "pathParam"
)

// RequestModel is a template's requestModel: a JSONPath into the body, a
// header name, a query parameter name, or a path regex whose first capture
// group is the model.
type RequestModel struct {
	Location   string
	Identifier string
	pathRe     *regexp.Regexp
}

var defaultRequestModel = RequestModel{Location: LocationPayload, Identifier: "$.model"}

// inBody reports whether the model is rewritten in the request body phase.
func (r RequestModel) inBody() bool {
	return r.Location == LocationPayload
}

// readOutsideBody reads a header, query or path model from the request.
func (r RequestModel) readOutsideBody(h *policy.Headers, path string) (string, bool) {
	var v string
	switch r.Location {
	case LocationHeader:
		v = firstHeader(h, r.Identifier)
	case LocationQueryParam:
		_, rawQuery, _ := strings.Cut(path, "?")
		q, err := url.ParseQuery(rawQuery)
		if err != nil {
			return "", false
		}
		v = q.Get(r.Identifier)
	case LocationPathParam:
		base, _, _ := strings.Cut(path, "?")
		m := r.pathRe.FindStringSubmatch(base)
		if len(m) < 2 {
			return "", false
		}
		u, err := url.PathUnescape(m[1])
		if err != nil {
			return "", false
		}
		v = u
	}
	return v, v != ""
}

func parseRequestModel(raw interface{}) (RequestModel, error) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return RequestModel{}, fmt.Errorf("requestModel must be an object")
	}
	location, _ := m["location"].(string)
	identifier, _ := m["identifier"].(string)
	if identifier == "" {
		return RequestModel{}, fmt.Errorf("requestModel.identifier is required")
	}
	rm := RequestModel{Location: location, Identifier: identifier}
	switch location {
	case LocationPayload, LocationHeader, LocationQueryParam:
	case LocationPathParam:
		re, err := regexp.Compile(identifier)
		if err != nil {
			return RequestModel{}, fmt.Errorf("requestModel.identifier is not a valid regular expression: %w", err)
		}
		if re.NumSubexp() < 1 {
			return RequestModel{}, fmt.Errorf("requestModel.identifier must have a capture group around the model")
		}
		rm.pathRe = re
	default:
		return RequestModel{}, fmt.Errorf("requestModel.location must be one of %s, %s, %s, %s", LocationPayload, LocationHeader, LocationQueryParam, LocationPathParam)
	}
	return rm, nil
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
		RequestModel:                    defaultRequestModel,
	}

	if _, old := params["targets"]; old {
		return nil, fmt.Errorf("'targets' was replaced by 'chains': list a primary model and its fallbacks")
	}
	targets, chains, err := parseChains(params["chains"])
	if err != nil {
		return nil, err
	}
	cfg.Targets, cfg.Chains, cfg.PassThrough = targets, chains, len(targets)-1

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

	if raw, ok := params["requestModel"]; ok {
		if cfg.RequestModel, err = parseRequestModel(raw); err != nil {
			return nil, err
		}
	}

	if err := parseInternal(params, cfg); err != nil {
		return nil, err
	}
	if cfg.RouteToTarget {
		cfg.RequestModel = defaultRequestModel
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
	if chains, ok := params["chains"].([]interface{}); ok {
		for i, c := range chains {
			m, _ := c.(map[string]interface{})
			pm, _ := m["primary"].(map[string]interface{})
			if _, set := pm["provider"]; set {
				return fmt.Errorf("chains[%d].primary.provider: the primary is the requested model on the provider the request is routed to; name providers on fallbacks", i)
			}
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

// parseChains flattens chains into distinct targets, in chain order (primary,
// then fallbacks) with repeats skipped, and appends the pass-through target.
// The gateway-controller flattens the same way, so its per-target ids and
// upstreams line up with these indices.
func parseChains(raw interface{}) ([]Target, map[string][]int, error) {
	if raw == nil {
		return nil, nil, fmt.Errorf("'chains' is required")
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("'chains' must be an array")
	}
	if len(list) == 0 || len(list) > maxChains {
		return nil, nil, fmt.Errorf("'chains' must contain between 1 and %d entries", maxChains)
	}
	var targets []Target
	index := map[string]int{}
	chains := make(map[string][]int, len(list))
	primaryAt := make(map[string]int, len(list))
	for i, item := range list {
		path := fmt.Sprintf("chains[%d]", i)
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("%s must be an object", path)
		}
		pm, ok := m["primary"].(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("%s.primary is required", path)
		}
		primary, err := parseTarget(pm, path+".primary")
		if err != nil {
			return nil, nil, err
		}
		if prev, dup := primaryAt[primary.Model]; dup {
			return nil, nil, fmt.Errorf("%s.primary.model: %q already has a chain (chains[%d])", path, primary.Model, prev)
		}
		primaryAt[primary.Model] = i

		fl, ok := m["fallbacks"].([]interface{})
		if !ok || len(fl) == 0 || len(fl) > maxFallbacks {
			return nil, nil, fmt.Errorf("%s.fallbacks must contain between 1 and %d entries", path, maxFallbacks)
		}
		members := []Target{primary}
		for j, f := range fl {
			fm, ok := f.(map[string]interface{})
			if !ok {
				return nil, nil, fmt.Errorf("%s.fallbacks[%d] must be an object", path, j)
			}
			t, err := parseTarget(fm, fmt.Sprintf("%s.fallbacks[%d]", path, j))
			if err != nil {
				return nil, nil, err
			}
			members = append(members, t)
		}

		inChain := map[string]bool{}
		for k, t := range members {
			key := t.Provider + "\x00" + t.Model
			if inChain[key] {
				return nil, nil, fmt.Errorf("%s lists provider %q, model %q more than once (entry %d)", path, t.Provider, t.Model, k)
			}
			inChain[key] = true
			idx, seen := index[key]
			if !seen {
				idx = len(targets)
				t.ID = "t" + strconv.Itoa(idx)
				t.Native = true
				targets = append(targets, t)
				index[key] = idx
			}
			chains[primary.Model] = append(chains[primary.Model], idx)
		}
	}
	if len(targets) > maxTargets {
		return nil, nil, fmt.Errorf("'chains' name %d distinct provider and model pairs; at most %d are allowed", len(targets), maxTargets)
	}
	// The pass-through target goes wherever the route would send the request
	// without failover: the first chain's primary provider.
	targets = append(targets, Target{Provider: targets[0].Provider, ID: passThroughTarget, Native: true})
	return targets, chains, nil
}

// parseTarget reads {provider?, model}. provider may be empty in authored
// params; the controller fills it in before the policy runs.
func parseTarget(m map[string]interface{}, path string) (Target, error) {
	model, err := requiredString(m, "model", path)
	if err != nil {
		return Target{}, err
	}
	if len(model) > maxModelLength {
		return Target{}, fmt.Errorf("%s.model must be at most %d characters", path, maxModelLength)
	}
	var provider string
	if raw, ok := m["provider"]; ok {
		if provider, ok = raw.(string); !ok || provider == "" {
			return Target{}, fmt.Errorf("%s.provider must be a non-empty string", path)
		}
	}
	return Target{Provider: provider, Model: model}, nil
}

// isPassThrough reports whether i is the pass-through target.
func (c *Config) isPassThrough(i int) bool {
	return i == c.PassThrough
}

// longestChain is the most attempts any request can make.
func (c *Config) longestChain() int {
	n := 1
	for _, idx := range c.Chains {
		if len(idx) > n {
			n = len(idx)
		}
	}
	return n
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
	cfg.RouteToTarget = true
	if raw, ok := params[paramInternalRouteToTarget]; ok {
		b, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("internal parameter %s must be a boolean", paramInternalRouteToTarget)
		}
		cfg.RouteToTarget = b
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
	return time.Duration(c.longestChain())*c.PerAttemptTimeout + 7*time.Second
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
