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

package llmheaderrouter

import (
	"context"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func validParams() map[string]interface{} {
	return map[string]interface{}{
		"defaultProvider": "openai-provider",
		"mappings": []interface{}{
			map[string]interface{}{"headerValue": "anthropic", "provider": "anthropic-provider"},
			map[string]interface{}{"headerValue": "gemini", "provider": "gemini-provider"},
		},
	}
}

func TestGetPolicy_ValidAndInvalid(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, validParams()); err != nil {
		t.Fatalf("unexpected error for valid params: %v", err)
	}
	// defaultProvider is optional.
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"mappings": []interface{}{map[string]interface{}{"headerValue": "a", "provider": "p"}},
	}); err != nil {
		t.Errorf("unexpected error when defaultProvider is missing: %v", err)
	}
	// mappings is required.
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"defaultProvider": "openai-provider",
	}); err == nil {
		t.Error("expected error when mappings is missing")
	}
}

func TestParseParams_DefaultHeaderName(t *testing.T) {
	p, err := parseParams(validParams())
	if err != nil {
		t.Fatalf("parseParams failed: %v", err)
	}
	if p.HeaderName != DefaultHeaderName {
		t.Errorf("expected default header name %q, got %q", DefaultHeaderName, p.HeaderName)
	}
}

func TestParseParams_RejectsDuplicateHeaderValues(t *testing.T) {
	params := map[string]interface{}{
		"defaultProvider": "openai-provider",
		"mappings": []interface{}{
			map[string]interface{}{"headerValue": "anthropic", "provider": "p1"},
			// Duplicate (case-insensitive) — must be rejected.
			map[string]interface{}{"headerValue": "Anthropic", "provider": "p2"},
		},
	}
	if _, err := parseParams(params); err == nil {
		t.Error("expected error for duplicate (case-insensitive) headerValue")
	}
}

func TestSelectProvider(t *testing.T) {
	p := &RouterPolicy{params: mustParse(t)}

	// Exact match.
	if got, src := p.selectProvider("anthropic"); got != "anthropic-provider" || src != "header" {
		t.Errorf("expected anthropic-provider/header, got %s/%s", got, src)
	}
	// Case-insensitive match.
	if got, src := p.selectProvider("GEMINI"); got != "gemini-provider" || src != "header" {
		t.Errorf("expected gemini-provider/header, got %s/%s", got, src)
	}
	// Unknown value falls back to default.
	if got, src := p.selectProvider("unknown"); got != "openai-provider" || src != "default" {
		t.Errorf("expected openai-provider/default, got %s/%s", got, src)
	}
	// Empty header falls back to default.
	if got, src := p.selectProvider(""); got != "openai-provider" || src != "default" {
		t.Errorf("expected openai-provider/default, got %s/%s", got, src)
	}
}

func TestSelectProvider_WithoutDefault(t *testing.T) {
	params := validParams()
	delete(params, "defaultProvider")
	parsed, err := parseParams(params)
	if err != nil {
		t.Fatalf("parseParams failed: %v", err)
	}
	p := &RouterPolicy{params: parsed}

	for _, headerValue := range []string{"", "unknown"} {
		if got, src := p.selectProvider(headerValue); got != "" || src != "primary" {
			t.Errorf("header %q: expected empty provider/primary, got %q/%s", headerValue, got, src)
		}
	}
}

func TestPublishSelection_WithoutDefaultLeavesProviderUnset(t *testing.T) {
	params := validParams()
	delete(params, "defaultProvider")
	parsed, err := parseParams(params)
	if err != nil {
		t.Fatalf("parseParams failed: %v", err)
	}
	p := &RouterPolicy{params: parsed}

	metadata := map[string]interface{}{MetadataKeySelectedProvider: ""}
	p.publishSelection(metadata, nil)

	if _, ok := metadata[MetadataKeySelectedProvider]; ok {
		t.Errorf("%s must be unset so the LlmProxy uses its primary provider", MetadataKeySelectedProvider)
	}
}

func mustParse(t *testing.T) PolicyParams {
	t.Helper()
	p, err := parseParams(validParams())
	if err != nil {
		t.Fatalf("parseParams failed: %v", err)
	}
	return p
}

// upstreamFrom reports the upstream a header-phase action selected, and whether
// one was selected at all.
func upstreamFrom(t *testing.T, action policy.RequestHeaderAction) (string, bool) {
	t.Helper()
	mods, isHeaderMods := action.(policy.UpstreamRequestHeaderModifications)
	if !isHeaderMods {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.UpstreamName == nil {
		return "", false
	}
	return *mods.UpstreamName, true
}

// TestOnRequestHeaders_RoutesAndAnnounces covers all three selection states.
// The router must do both halves of the contract every other routing policy
// honours: set the upstream so the request actually moves, and publish the
// selection so conditional credential and transformer policies know which
// provider was chosen.
//
// The `primary` fall-through is the exception and must stay as it is: nothing
// published, nothing routed, so the default cluster and the primary's own
// credential condition keep working.
func TestOnRequestHeaders_RoutesAndAnnounces(t *testing.T) {
	cases := []struct {
		name            string
		withDefault     bool
		header          string
		wantPublished   string
		wantUpstream    string
		wantUpstreamSet bool
	}{
		{
			name: "header maps to a provider", withDefault: true, header: "anthropic",
			wantPublished: "anthropic-provider", wantUpstream: "anthropic-provider", wantUpstreamSet: true,
		},
		{
			name: "no mapping falls back to defaultProvider", withDefault: true, header: "unknown",
			wantPublished: "openai-provider", wantUpstream: "openai-provider", wantUpstreamSet: true,
		},
		{
			name: "no header falls back to defaultProvider", withDefault: true, header: "",
			wantPublished: "openai-provider", wantUpstream: "openai-provider", wantUpstreamSet: true,
		},
		{
			name: "no mapping and no default falls through to the primary", withDefault: false, header: "unknown",
			wantPublished: "", wantUpstream: "", wantUpstreamSet: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := validParams()
			if !tc.withDefault {
				delete(params, "defaultProvider")
			}
			parsed, err := parseParams(params)
			if err != nil {
				t.Fatalf("parseParams failed: %v", err)
			}
			p := &RouterPolicy{params: parsed}

			reqCtx := &policy.RequestHeaderContext{
				SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
				Headers:       policy.NewHeaders(map[string][]string{"x-provider": {tc.header}}),
			}
			action := p.OnRequestHeaders(context.Background(), reqCtx, nil)

			published, _ := reqCtx.Metadata[MetadataKeySelectedProvider].(string)
			if published != tc.wantPublished {
				t.Errorf("published selection = %q, want %q", published, tc.wantPublished)
			}

			upstream, wasSet := upstreamFrom(t, action)
			if wasSet != tc.wantUpstreamSet {
				t.Fatalf("upstream set = %v (%q), want set = %v", wasSet, upstream, tc.wantUpstreamSet)
			}
			if upstream != tc.wantUpstream {
				t.Errorf("upstream = %q, want %q", upstream, tc.wantUpstream)
			}
		})
	}
}

// TestOnRequestHeaders_DoesNotOverrideAnEarlierSelection: when an earlier policy
// has already chosen a provider, the router leaves both halves of that decision
// alone — it neither republishes nor re-routes.
func TestOnRequestHeaders_DoesNotOverrideAnEarlierSelection(t *testing.T) {
	p := &RouterPolicy{params: mustParse(t)}
	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{
			MetadataKeySelectedProvider: "chosen-earlier",
		}},
		Headers: policy.NewHeaders(map[string][]string{"x-provider": {"anthropic"}}),
	}

	action := p.OnRequestHeaders(context.Background(), reqCtx, nil)

	if got := reqCtx.Metadata[MetadataKeySelectedProvider]; got != "chosen-earlier" {
		t.Errorf("published selection = %v, want the earlier selection left untouched", got)
	}
	if upstream, wasSet := upstreamFrom(t, action); wasSet {
		t.Errorf("upstream = %q, want unset so an upstream already chosen is not overridden", upstream)
	}
}

// TestOnRequestBody_StillPublishesAndDoesNotRoute: the body phase keeps its
// idempotent republish and must not route — the upstream belongs to the header
// phase, so the cluster is known before the request is forwarded.
func TestOnRequestBody_StillPublishesAndDoesNotRoute(t *testing.T) {
	p := &RouterPolicy{params: mustParse(t)}
	reqCtx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
		Headers:       policy.NewHeaders(map[string][]string{"x-provider": {"anthropic"}}),
	}

	action := p.OnRequestBody(context.Background(), reqCtx, nil)

	if got, _ := reqCtx.Metadata[MetadataKeySelectedProvider].(string); got != "anthropic-provider" {
		t.Errorf("body phase published %q, want the selection republished unchanged", got)
	}
	mods, isBodyMods := action.(policy.UpstreamRequestModifications)
	if !isBodyMods {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if mods.UpstreamName != nil {
		t.Errorf("body phase set upstream %q, want routing to stay in the header phase", *mods.UpstreamName)
	}
}

// TestOnRequestHeaders_RoutingIsIndependentOfTransformers: the router's entire
// input surface is headerName, mappings and defaultProvider —
// it cannot observe whether the selected provider carries a wire-format
// transformer, so routing cannot depend on one. Before this fix it effectively
// did: the router published a selection and a transformer routed on its behalf,
// so a provider needing no translation was never reached.
//
// The assertion is that identical selections produce identical routing across
// providers that differ only in whether a transformer would be attached to them
// downstream — anthropic-provider normally carries one, gemini-provider here
// stands for a provider whose format matches the inbound interface.
func TestOnRequestHeaders_RoutingIsIndependentOfTransformers(t *testing.T) {
	p := &RouterPolicy{params: mustParse(t)}

	for header, wantProvider := range map[string]string{
		"anthropic": "anthropic-provider",
		"gemini":    "gemini-provider",
	} {
		t.Run(header, func(t *testing.T) {
			reqCtx := &policy.RequestHeaderContext{
				SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{}},
				Headers:       policy.NewHeaders(map[string][]string{"x-provider": {header}}),
			}
			action := p.OnRequestHeaders(context.Background(), reqCtx, nil)

			upstream, wasSet := upstreamFrom(t, action)
			if !wasSet || upstream != wantProvider {
				t.Errorf("upstream = %q (set=%v), want %q — routing must follow the selection alone",
					upstream, wasSet, wantProvider)
			}
		})
	}
}
