/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package mcpauthn

import (
	"context"
	"encoding/json"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

// exemptPolicy exempts one method group entry so a test can tell "auth skipped" from
// "auth required" without standing up a JWKS server: an exempt request returns nil, and
// anything else returns an action.
func exemptPolicy(exceptions ...string) *McpAuthPolicy {
	p := &McpAuthPolicy{
		OnFailureStatusCode: 401,
		ErrorMessageFormat:  "json",
		AuthConfig:          GetMcpAuthConfig(map[string]any{}),
	}
	p.AuthConfig.Methods = SecurityConfig{Enabled: true, Exceptions: exceptions}
	p.AuthConfig.Tools = SecurityConfig{Enabled: true, Exceptions: exceptions}
	p.AuthConfig.Resources = SecurityConfig{Enabled: true, Exceptions: exceptions}
	return p
}

// resolvedHeaderPost builds a POST /mcp header-phase context on a route whose resolver ran.
//
// mcp.body.present is set for every caller: the resolver publishes it for any body it
// received, so a fixture that omits it models a state the engine cannot produce. Use
// resolvedHeaderPostNoBody for the one case that legitimately has no attributes at all.
func resolvedHeaderPost(headers map[string][]string, attrs map[string]string) *policy.RequestHeaderContext {
	withBody := map[string]string{attrBodyPresent: "true"}
	for k, v := range attrs {
		withBody[k] = v
	}
	return resolvedHeaderPostRaw(headers, withBody)
}

// resolvedHeaderPostNoBody models a request that reached the resolver carrying no body, which
// is the only way a resolver-bearing route publishes nothing at all.
func resolvedHeaderPostNoBody(headers map[string][]string) *policy.RequestHeaderContext {
	return resolvedHeaderPostRaw(headers, nil)
}

func resolvedHeaderPostRaw(headers map[string][]string, attrs map[string]string) *policy.RequestHeaderContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:            "test-request-id",
			Metadata:             map[string]any{metadataBodyResolved: true},
			OperationPath:        "/mcp",
			APIKind:              policy.APIKindMCP,
			ResolvedOperation:    "mcp",
			ResolutionAttributes: policy.NewResolutionAttributes(attrs),
		},
		Headers: policy.NewHeaders(headers),
		Path:    "/mcp",
		Method:  "POST",
	}
}

// unresolvedBodyPost builds a POST /mcp body-phase context on a gateway with no resolver:
// no ResolvedOperation, no attributes, and a real body to parse.
func unresolvedBodyPost(headers map[string][]string, body string) *policy.RequestContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID:     "test-request-id",
			Metadata:      map[string]any{},
			OperationPath: "/mcp",
		},
		Headers: policy.NewHeaders(headers),
		Body:    &policy.Body{Present: true, Content: []byte(body)},
		Path:    "/mcp",
		Method:  "POST",
	}
}

func assertExempt(t *testing.T, action any) {
	t.Helper()
	if action != nil {
		t.Fatalf("expected the request to be exempt from authentication, got %#v", action)
	}
}

func assertNotExempt(t *testing.T, action any) {
	t.Helper()
	if action == nil {
		t.Fatal("expected authentication to be attempted, but the request was exempted")
	}
}

// assertMissingHeaderRejected checks the 400 for a missing required mirrored header.
func assertMissingHeaderRejected(t *testing.T, action any) {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected an immediate rejection, got %#v", action)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var env jsonRPCErrorResponse
	if err := json.Unmarshal(resp.Body, &env); err != nil {
		t.Fatalf("body is not a JSON-RPC error: %v (%s)", err, resp.Body)
	}
	if env.Error.Code != JSONRPCHeaderMismatch {
		t.Fatalf("error code = %d, want %d", env.Error.Code, JSONRPCHeaderMismatch)
	}
}

// ─── Mode: the whole point of the parameter ──────────────────────────────────

// Both request phases are asked for unconditionally; which one decides is settled per request.
func TestMode_AsksForBothRequestPhases(t *testing.T) {
	m := (&McpAuthPolicy{}).Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess || m.RequestBodyMode != policy.BodyModeBuffer {
		t.Errorf("request modes = %v/%v, want Process/Buffer", m.RequestHeaderMode, m.RequestBodyMode)
	}
	if m.ResponseHeaderMode != policy.HeaderModeSkip || m.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("unexpected response modes %+v", m)
	}
}

// The route's resolver is read off the request, not a parameter, so an unknown parameter cannot
// silently leave the policy parsing a body the resolver already read.
func TestShouldParseBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shared *policy.SharedContext
		want   bool
	}{
		{"nil shared context", nil, false},
		{"no resolver on the route", &policy.SharedContext{APIKind: policy.APIKindMCP}, false},
		{"an engine that never sets the marker",
			&policy.SharedContext{APIKind: policy.APIKindMCP, Metadata: map[string]any{}}, false},
		{"a marker that is not true",
			&policy.SharedContext{APIKind: policy.APIKindMCP, Metadata: map[string]any{metadataBodyResolved: false}}, false},
		{"a marker of the wrong type",
			&policy.SharedContext{APIKind: policy.APIKindMCP, Metadata: map[string]any{metadataBodyResolved: "true"}}, false},
		{"a resolver, but not on an MCP route",
			&policy.SharedContext{Metadata: map[string]any{metadataBodyResolved: true}}, false},
		{"a resolver on an MCP route",
			&policy.SharedContext{APIKind: policy.APIKindMCP,
				Metadata: map[string]any{metadataBodyResolved: true}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := !shouldParseBody(tc.shared); got != tc.want {
				t.Errorf("shouldParseBody = %v, want %v", got, tc.want)
			}
		})
	}
}

// ─── The three fact sources ──────────────────────────────────────────────────

// A modern request carries its facts in headers, which every gateway can read. This is the
// one path that needs neither a resolver nor a buffered body.
func TestFacts_ModernRequestNeedsNoResolver(t *testing.T) {
	headers := map[string][]string{
		headerProtocolVersion: {"2026-07-28"},
		headerMcpMethod:       {"tools/call"},
		headerMcpName:         {"get_forecast"},
	}
	facts := mcpFacts(policy.NewHeaders(headers), &policy.SharedContext{})
	if facts.Method == "" || facts.Method != "tools/call" || facts.Name != "get_forecast" {
		t.Fatalf("mcpFacts = %+v, want tools/call/get_forecast, usable", facts)
	}
}

// A sentinel-encoded name is decoded before it is matched against an exception list, or a
// name that cannot be written in ASCII would never match one.
func TestFacts_SentinelNameIsDecoded(t *testing.T) {
	headers := map[string][]string{
		headerProtocolVersion: {"2026-07-28"},
		headerMcpMethod:       {"tools/call"},
		headerMcpName:         {"=?base64?dG9vbF/DvG1sYXV0?="},
	}
	facts := mcpFacts(policy.NewHeaders(headers), &policy.SharedContext{})
	if facts.Method == "" || facts.Name != "tool_ümlaut" {
		t.Fatalf("facts = %+v, want the decoded value marked usable", facts)
	}
}

// A legacy request mirrors nothing, so its facts come from the resolver.
func TestFacts_LegacyRequestComesFromTheResolver(t *testing.T) {
	shared := &policy.SharedContext{
		ResolvedOperation: "mcp",
		ResolutionAttributes: policy.NewResolutionAttributes(map[string]string{
			attrBodyMethod:         "tools/call",
			attrBodyCapabilityName: "get_forecast",
		}),
	}
	facts := mcpFacts(policy.NewHeaders(nil), shared)
	if facts.Method == "" || facts.Method != "tools/call" || facts.Name != "get_forecast" {
		t.Fatalf("mcpFacts = %+v", facts)
	}
}

// ─── End to end, across all three pairings ───────────────────────────────────

// The same request, the same configured exemption, the same outcome — whichever gateway it
// lands on. This is the backward-compatibility claim stated as a test.
func TestExemptionsHonouredOnEveryPath(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	t.Run("new gateway, legacy request — facts from the resolver", func(t *testing.T) {
		p := exemptPolicy("ping")
		ctx := resolvedHeaderPost(nil, map[string]string{attrBodyMethod: "ping"})
		assertExempt(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	t.Run("new gateway, modern request — facts from the headers", func(t *testing.T) {
		p := exemptPolicy("ping")
		ctx := resolvedHeaderPost(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"ping"},
		}, nil)
		assertExempt(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	t.Run("old gateway, legacy request — the policy parses the body itself", func(t *testing.T) {
		p := exemptPolicy("ping")
		ctx := unresolvedBodyPost(nil, body)
		assertExempt(t, p.OnRequestBody(context.Background(), ctx, map[string]any{}))
	})

	// On a gateway with no resolver the body is buffered anyway, so it decides — even for
	// a modern client that also sent the mirrored headers. The header here claims an exempt
	// ping while the body invokes tools/call; the body is what the server would run, so the
	// request authenticates.
	//
	// This differs from a resolver-bearing route, where the body is not available to this
	// policy and the headers are taken at face value. Both are documented; the rule is that
	// mcp-auth uses the most authoritative source it actually has.
	t.Run("old gateway, modern request — the buffered body outranks the headers", func(t *testing.T) {
		p := exemptPolicy("ping")
		ctx := unresolvedBodyPost(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"ping"},
		}, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)
		assertNotExempt(t, p.OnRequestBody(context.Background(), ctx, map[string]any{}))
	})

	t.Run("old gateway, modern request whose headers and body agree", func(t *testing.T) {
		p := exemptPolicy("ping")
		ctx := unresolvedBodyPost(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"ping"},
		}, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
		assertExempt(t, p.OnRequestBody(context.Background(), ctx, map[string]any{}))
	})
}

// The regression this version exists to prevent. Reading facts only from the resolver
// would make every configured exemption vanish on a gateway that has none.
func TestOldGatewayDoesNotLoseItsExemptions(t *testing.T) {
	p := exemptPolicy("initialize", "ping", "tools/list")
	for _, method := range []string{"initialize", "ping", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			ctx := unresolvedBodyPost(nil, `{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`)
			assertExempt(t, p.OnRequestBody(context.Background(), ctx, map[string]any{}))
		})
	}
}

// A method that is not exempt still authenticates, on every path — the exemption test must
// not be passing simply because nothing ever authenticates.
func TestNonExemptMethodAuthenticatesOnEveryPath(t *testing.T) {
	t.Run("resolved route", func(t *testing.T) {
		p := exemptPolicy("ping")
		ctx := resolvedHeaderPost(nil, map[string]string{attrBodyMethod: "tools/call"})
		assertNotExempt(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})
	t.Run("unresolved route", func(t *testing.T) {
		p := exemptPolicy("ping")
		ctx := unresolvedBodyPost(nil, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)
		assertNotExempt(t, p.OnRequestBody(context.Background(), ctx, map[string]any{}))
	})
}

// server/discover is the modern entry point where legacy used initialize. There are no
// built-in exemptions, so a dual-era proxy lists both — and both must work identically.
func TestDualEraEntryPointsAreOrdinaryMethodExceptions(t *testing.T) {
	p := exemptPolicy("initialize", "server/discover")

	t.Run("legacy initialize via the resolver", func(t *testing.T) {
		ctx := resolvedHeaderPost(nil, map[string]string{attrBodyMethod: "initialize"})
		assertExempt(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})
	t.Run("modern server/discover via the headers", func(t *testing.T) {
		ctx := resolvedHeaderPost(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"server/discover"},
		}, nil)
		assertExempt(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})
}

// Transport auth is untouched by the POST branch, on either kind of gateway.
//
// GET and DELETE never enter that branch, and its early return could not skip them even if
// they did: requiresTransportAuth declines POST itself. The existing transport tests all run
// on a resolver-less route, so this pins the other half.
func TestTransportAuthIsUnaffectedByTheResolver(t *testing.T) {
	for _, resolved := range []bool{false, true} {
		for _, method := range []string{"GET", "DELETE"} {
			t.Run(method, func(t *testing.T) {
				p := exemptPolicy("ping")
				ctx := resolvedHeaderPost(nil, nil)
				ctx.Method = method
				if !resolved {
					ctx.ResolvedOperation = ""
			delete(ctx.Metadata, metadataBodyResolved)
					delete(ctx.Metadata, metadataBodyResolved)
				}

				// No token presented, so authentication must be attempted and fail — the
				// point is that it was attempted at all.
				if _, ok := p.OnRequestHeaders(context.Background(), ctx, map[string]any{}).(policy.ImmediateResponse); !ok {
					t.Fatalf("resolver=%v: %s /mcp was forwarded without authentication", resolved, method)
				}
			})
		}
	}
}

// OPTIONS is a preflight and stays exempt on both, so the test above is not simply
// asserting that everything authenticates.
func TestOptionsIsNeverAuthenticated(t *testing.T) {
	for _, resolved := range []bool{false, true} {
		p := exemptPolicy("ping")
		ctx := resolvedHeaderPost(nil, nil)
		ctx.Method = "OPTIONS"
		if !resolved {
			ctx.ResolvedOperation = ""
			delete(ctx.Metadata, metadataBodyResolved)
		}
		if _, ok := p.OnRequestHeaders(context.Background(), ctx, map[string]any{}).(policy.UpstreamRequestHeaderModifications); !ok {
			t.Errorf("resolver=%v: OPTIONS must be forwarded untouched", resolved)
		}
	}
}

// ─── Facts unavailable must never mean "no exception matched" ────────────────

// An operation this policy cannot be sure of authenticates rather than being matched against an
// exception list, where an empty key matches nothing and a non-match under `enabled: false` is
// an exemption. Two ways to be unsure:
//
//   - a legacy request with no body; and
//   - a modern request with no Mcp-Method, which mirroring makes mandatory.
//
// The second is a DELIBERATE divergence: the same body reaches the rule on a legacy gateway and
// may be exempt. Challenging it costs a conformant client nothing.
func TestUnsureOperationAuthenticatesRatherThanExempting(t *testing.T) {
	// methods.enabled:false is the shape that makes this dangerous, and the shape
	// exemptPolicy does NOT produce. Under enabled:true an empty method authenticates all by
	// itself, so a test built on that would pass with the guard removed.
	p := exemptPolicy("ping")
	p.AuthConfig.Methods = SecurityConfig{Enabled: false, Exceptions: []string{"ping"}}

	// The precondition: with methods open by default, an unidentified operation matches no
	// exception, and a non-match here is an exemption.
	if p.isAuthRequired(mcpRequestFacts{Method: ""}) {
		t.Fatal("precondition changed: an empty method no longer exempts under enabled:false")
	}

	t.Run("no body at all", func(t *testing.T) {
		assertNotExempt(t, p.OnRequestHeaders(context.Background(),
			resolvedHeaderPostNoBody(nil), map[string]any{}))
	})

	t.Run("modern request that named no operation anywhere is rejected", func(t *testing.T) {
		ctx := resolvedHeaderPost(map[string][]string{headerProtocolVersion: {"2026-07-28"}}, nil)
		assertMissingHeaderRejected(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	// A legacy body that named no operation is authoritative and reaches the rule — this is
	// the case the divergence above is measured against, and the one A2 was about.
	t.Run("legacy body that named no operation — the rule decides", func(t *testing.T) {
		assertExempt(t, p.OnRequestHeaders(context.Background(),
			resolvedHeaderPost(nil, nil), map[string]any{}))
	})

	// Mcp-Method names the operation, so the rule decides even with no body. Such a request
	// executes nothing anyway: the server answers a bodyless POST with -32700.
	t.Run("modern, no body, but the headers name the operation — the rule decides", func(t *testing.T) {
		q := exemptPolicy()
		q.AuthConfig.Tools = SecurityConfig{Enabled: false, Exceptions: []string{"dangerous_tool"}}
		ctx := resolvedHeaderPostNoBody(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/call"},
			headerMcpName:         {"harmless_tool"},
		})
		assertExempt(t, q.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	// The same request without Mcp-Name left out a header tools/call must mirror, so it is refused.
	t.Run("modern, no body, and a capability method with no name", func(t *testing.T) {
		q := exemptPolicy()
		q.AuthConfig.Tools = SecurityConfig{Enabled: false, Exceptions: []string{"dangerous_tool"}}
		ctx := resolvedHeaderPostNoBody(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/call"},
		})
		assertMissingHeaderRejected(t, q.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	// A legacy request has only the body, so a bodyless one still authenticates, whatever a
	// header claims — as OnRequestBody does on a gateway with no resolver.
	t.Run("legacy, no body, and a mirrored header does not excuse it", func(t *testing.T) {
		q := exemptPolicy()
		q.AuthConfig.Tools = SecurityConfig{Enabled: false, Exceptions: []string{"dangerous_tool"}}
		if q.isAuthRequired(mcpRequestFacts{Method: "tools/call", Name: ""}) {
			t.Fatal("precondition changed: tools/call with no name no longer exempts")
		}
		ctx := resolvedHeaderPostNoBody(map[string][]string{headerMcpMethod: {"tools/call"}})
		assertNotExempt(t, q.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})
}

// On a modern request the name comes from Mcp-Name alone: a withheld or undecodable one leaves
// it empty, and the body is not consulted.
//
// Under a group configured `enabled: false` with exceptions a non-match is an exemption, so an
// empty name would skip authentication on the very tool the operator listed. 2026-07-28 requires
// Mcp-Name on a capability method, so such a request is rejected instead.
//
// The converse matters just as much: a method that never consults the name must keep the
// exemption its operator configured, whatever arrived in a header it does not use.
func TestModernNameComesFromTheHeaderOnly(t *testing.T) {
	const brokenName = "=?base64?!!!not-base64!!!?="

	newPolicy := func(group string, cfg SecurityConfig) *McpAuthPolicy {
		p := &McpAuthPolicy{
			OnFailureStatusCode: 401,
			ErrorMessageFormat:  "json",
			AuthConfig:          GetMcpAuthConfig(map[string]any{}),
		}
		switch group {
		case "tools":
			p.AuthConfig.Tools = cfg
		case "methods":
			p.AuthConfig.Methods = cfg
		}
		return p
	}

	// The precondition that makes the tools case dangerous: under enabled:false an empty
	// name is exempt, while the listed capability is protected.
	guard := newPolicy("tools", SecurityConfig{Enabled: false, Exceptions: []string{"dangerous_tool"}})
	if guard.isAuthRequired(mcpRequestFacts{Method: "tools/call", Name: ""}) {
		t.Fatal("precondition changed: an empty name no longer exempts under enabled:false")
	}
	if !guard.isAuthRequired(mcpRequestFacts{Method: "tools/call", Name: "dangerous_tool"}) {
		t.Fatal("precondition changed: the listed tool is no longer protected")
	}

	// What the resolver published: the body invoked the protected tool.
	dangerousBody := map[string]string{
		attrBodyPresent:        "true",
		attrBodyMethod:         "tools/call",
		attrBodyCapabilityName: "dangerous_tool",
	}

	// Modern takes the name from Mcp-Name alone, so an unreadable header leaves it empty.
	t.Run("an unreadable Mcp-Name leaves the name empty", func(t *testing.T) {
		facts := mcpFacts(policy.NewHeaders(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/call"},
			headerMcpName:         {brokenName},
		}), &policy.SharedContext{ResolutionAttributes: policy.NewResolutionAttributes(dangerousBody)})
		if facts.Method != "tools/call" || facts.Name != "" {
			t.Fatalf("mcpFacts = %+v, want the method from the header and no name", facts)
		}
	})

	// An unreadable name is refused rather than left to match no exception.
	t.Run("an unreadable Mcp-Name is rejected rather than exempted", func(t *testing.T) {
		p := newPolicy("tools", SecurityConfig{Enabled: false, Exceptions: []string{"dangerous_tool"}})
		ctx := resolvedHeaderPost(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/call"},
			headerMcpName:         {brokenName},
		}, dangerousBody)
		assertMissingHeaderRejected(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	t.Run("an absent Mcp-Name behaves identically", func(t *testing.T) {
		p := newPolicy("tools", SecurityConfig{Enabled: false, Exceptions: []string{"dangerous_tool"}})
		ctx := resolvedHeaderPost(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/call"},
		}, dangerousBody)
		assertMissingHeaderRejected(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	// The rule turns on the missing name, not on what the body happens to invoke.
	t.Run("a withheld header is rejected even where the body names an open tool", func(t *testing.T) {
		p := newPolicy("tools", SecurityConfig{Enabled: false, Exceptions: []string{"dangerous_tool"}})
		ctx := resolvedHeaderPost(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/call"},
		}, map[string]string{
			attrBodyPresent:        "true",
			attrBodyMethod:         "tools/call",
			attrBodyCapabilityName: "harmless_tool",
		})
		assertMissingHeaderRejected(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	t.Run("subscriptions/listen — the name is not consulted, so the exemption holds", func(t *testing.T) {
		p := newPolicy("methods", SecurityConfig{Enabled: true, Exceptions: []string{"subscriptions/listen"}})
		ctx := resolvedHeaderPost(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"subscriptions/listen"},
			headerMcpName:         {brokenName},
		}, map[string]string{attrBodyPresent: "true", attrBodyMethod: "subscriptions/listen"})
		assertExempt(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	t.Run("tools/list — likewise, and it shares the tools group", func(t *testing.T) {
		p := newPolicy("methods", SecurityConfig{Enabled: true, Exceptions: []string{"tools/list"}})
		ctx := resolvedHeaderPost(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/list"},
			headerMcpName:         {brokenName},
		}, map[string]string{attrBodyPresent: "true", attrBodyMethod: "tools/list"})
		assertExempt(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	// The legacy path is unchanged. There the name comes from the same body the server
	// executes, so an absent one means the request named none.
	t.Run("legacy — an absent capability name keeps its pre-resolver meaning", func(t *testing.T) {
		p := newPolicy("tools", SecurityConfig{Enabled: false, Exceptions: []string{"dangerous_tool"}})
		ctx := resolvedHeaderPost(nil, map[string]string{attrBodyPresent: "true", attrBodyMethod: "tools/call"})
		assertExempt(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})

	// The header wins whenever it is present and decodable, disagreement included — that is
	// mcp-spec-validation's to catch, not this policy's.
	t.Run("a decodable header still wins over the body", func(t *testing.T) {
		headers := policy.NewHeaders(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/call"},
			headerMcpName:         {"harmless_tool"},
		})
		facts := mcpFacts(headers, &policy.SharedContext{
			ResolutionAttributes: policy.NewResolutionAttributes(dangerousBody),
		})
		if facts.Name != "harmless_tool" {
			t.Fatalf("Name = %q, want the header value", facts.Name)
		}
	})

	// The method survives a name that will not decode; only the name is lost.
}

// ─── An unreadable body is rejected on the era that reads the body ───────────

// The resolver reports a reason only when the gateway and the backend may read the bytes
// differently. A legacy request is decided from those bytes, so parsing them here would just
// be choosing one of the two readings and the request is refused instead.
func TestUnusableBodyIsRejectedWithTheMappedCode(t *testing.T) {
	for reason, wantCode := range map[string]int{
		"syntax-error":        JSONRPCParseError,
		"invalid-member-type": JSONRPCInvalidRequest,
		"not-an-object":       JSONRPCInvalidRequest,
		"ambiguous":           JSONRPCInvalidRequest,
		"something-newer":     JSONRPCInvalidRequest,
	} {
		t.Run(reason, func(t *testing.T) {
			p := exemptPolicy("ping")
			ctx := resolvedHeaderPost(nil, map[string]string{attrBodyUnusable: reason})

			resp, ok := p.OnRequestHeaders(context.Background(), ctx, map[string]any{}).(policy.ImmediateResponse)
			if !ok {
				t.Fatal("an unreadable body must be rejected, not forwarded")
			}
			if resp.StatusCode != 400 {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			var envelope struct {
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(resp.Body, &envelope); err != nil {
				t.Fatalf("body is not a JSON-RPC envelope: %v", err)
			}
			if envelope.Error.Code != wantCode {
				t.Errorf("code = %d, want %d", envelope.Error.Code, wantCode)
			}
		})
	}
}

// ─── Sessions are legacy-only ────────────────────────────────────────────────

// 2026-07-28 removes sessions, so a modern client sends no mcp-session-id and must not be
// handed one back. The policy does not branch on the era for this — it echoes what arrived
// and nothing more, which is correct for both and also stops the older habit of returning
// an empty header to legacy clients that sent none.
func TestSessionIDIsEchoedOnlyWhenOneArrived(t *testing.T) {
	p := &McpAuthPolicy{
		OnFailureStatusCode: 401,
		ErrorMessageFormat:  "json",
		AuthConfig:          GetMcpAuthConfig(map[string]any{}),
	}

	modern := map[string][]string{
		headerProtocolVersion: {"2026-07-28"},
		headerMcpMethod:       {"tools/call"},
		headerMcpName:         {"get_forecast"},
	}
	withSession := map[string][]string{
		headerMcpMethod:  {"tools/call"},
		McpSessionHeader: {"session-123"},
	}

	// The 401 built inside authenticate.
	t.Run("modern 401 carries no session header at all", func(t *testing.T) {
		resp := rejection401(t, p, resolvedHeaderPost(modern, nil))
		if v, present := resp.Headers[McpSessionHeader]; present {
			t.Errorf("mcp-session-id present with %q; a modern client sent none", v)
		}
	})

	t.Run("legacy 401 echoes the session it was given", func(t *testing.T) {
		ctx := resolvedHeaderPost(withSession, map[string]string{attrBodyMethod: "tools/call"})
		if got := rejection401(t, p, ctx).Headers[McpSessionHeader]; got != "session-123" {
			t.Errorf("mcp-session-id = %q, want session-123", got)
		}
	})

	// And the protected-resource-metadata 200, which is the other site that echoes it.
	t.Run("well-known metadata echoes only a session that arrived", func(t *testing.T) {
		params := map[string]any{"keyManagers": []any{
			map[string]any{"name": "km1", "issuer": "https://issuer1.com"},
		}}
		for _, tc := range []struct {
			name    string
			headers map[string][]string
			want    string
		}{
			{"modern, no session", nil, ""},
			{"legacy, session present", map[string][]string{McpSessionHeader: {"session-123"}}, "session-123"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctx := resolvedHeaderPost(tc.headers, nil)
				ctx.Method = "GET"
				ctx.OperationPath = "/.well-known/oauth-protected-resource"

				resp, ok := p.OnRequestHeaders(context.Background(), ctx, params).(policy.ImmediateResponse)
				if !ok || resp.StatusCode != 200 {
					t.Fatalf("expected the metadata document, got %#v", resp)
				}
				got, present := resp.Headers[McpSessionHeader]
				if tc.want == "" && present {
					t.Errorf("mcp-session-id present with %q; none was sent", got)
				}
				if tc.want != "" && got != tc.want {
					t.Errorf("mcp-session-id = %q, want %q", got, tc.want)
				}
			})
		}
	})
}

func rejection401(t *testing.T, p *McpAuthPolicy, ctx *policy.RequestHeaderContext) policy.ImmediateResponse {
	t.Helper()
	resp, ok := p.OnRequestHeaders(context.Background(), ctx, map[string]any{}).(policy.ImmediateResponse)
	if !ok {
		t.Fatal("expected authentication to be attempted and fail")
	}
	return resp
}

// ─── A resource is identified by its uri, on both paths ─────────────────────

// A resources/read carrying both params.name and params.uri must resolve to the uri: the local
// parse reads params.uri, and the resolver keys capability.name on the family, so the decoy name
// cannot displace the resource actually read.
func TestResourcesReadIsIdentifiedByItsUri(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":1,"method":"resources/read",` +
		`"params":{"name":"shadow","uri":"file:///a.txt"}}`
	resolved := func() *policy.RequestHeaderContext {
		return resolvedHeaderPost(nil, map[string]string{
			attrBodyMethod:         "resources/read",
			attrBodyCapabilityName: "file:///a.txt",
		})
	}

	t.Run("the uri exempts on both paths", func(t *testing.T) {
		p := exemptPolicy("file:///a.txt")
		assertExempt(t, p.OnRequestBody(context.Background(),
			unresolvedBodyPost(nil, body), map[string]any{}))
		assertExempt(t, p.OnRequestHeaders(context.Background(), resolved(), map[string]any{}))
	})

	t.Run("the decoy name exempts on neither", func(t *testing.T) {
		p := exemptPolicy("shadow")
		assertNotExempt(t, p.OnRequestBody(context.Background(),
			unresolvedBodyPost(nil, body), map[string]any{}))
		assertNotExempt(t, p.OnRequestHeaders(context.Background(), resolved(), map[string]any{}))
	})
}

// ─── "named no operation" vs "we never learned it" ───────────────────────────

// A2. Under `methods: {enabled: false}` an unmatched key is an exemption, so an empty method
// must not reach the exception list unless the era's own source really named none.
func TestMcpFacts_UnknowableOperationIsJudgedOnTheErasOwnSource(t *testing.T) {
	modern := map[string][]string{headerProtocolVersion: {"2026-07-28"}}

	tests := []struct {
		name           string
		headers        map[string][]string
		attrs          map[string]string
		wantUnknowable bool
	}{
		{
			// A client-posted JSON-RPC response: read fine, names no operation, authoritative.
			name:           "legacy, body read, named no operation",
			attrs:          map[string]string{attrBodyPresent: "true", attrBodyJSONRPCID: "7"},
			wantUnknowable: false,
		},
		{
			// mcp.body.present is the only thing separating this from no body at all.
			name:           "legacy, body read, carried nothing whatsoever",
			attrs:          map[string]string{attrBodyPresent: "true"},
			wantUnknowable: false,
		},
		{
			name:           "legacy, no body reached the resolver",
			attrs:          nil,
			wantUnknowable: true,
		},
		{
			// Presence is the signal, not the attribute count; counting would answer the
			// opposite here. The resolver cannot emit this, so it only pins which is read.
			name:           "legacy, attributes but no presence key is not a body",
			attrs:          map[string]string{attrBodyJSONRPCID: `"7"`},
			wantUnknowable: true,
		},
		{
			name:           "no shared context at all",
			headers:        modern,
			wantUnknowable: true,
		},
		{
			// The body is not consulted on a modern request, so it cannot rescue a withheld
			// header.
			name:           "modern, Mcp-Method withheld, even though the body names one",
			headers:        modern,
			attrs:          map[string]string{attrBodyPresent: "true", attrBodyMethod: "tools/call", attrBodyCapabilityName: "delete_everything"},
			wantUnknowable: true,
		},
		{
			name:           "modern, Mcp-Method withheld and the body named none either",
			headers:        modern,
			attrs:          map[string]string{attrBodyPresent: "true"},
			wantUnknowable: true,
		},
		{
			name:           "modern, Mcp-Method mirrored, no body at all",
			headers:        map[string][]string{headerProtocolVersion: {"2026-07-28"}, headerMcpMethod: {"tools/call"}},
			wantUnknowable: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var shared *policy.SharedContext
			if tc.attrs != nil || tc.name != "no shared context at all" {
				shared = &policy.SharedContext{ResolutionAttributes: policy.NewResolutionAttributes(tc.attrs)}
			}
			facts := mcpFacts(policy.NewHeaders(tc.headers), shared)
			// Combined the way authenticateResolvedRequest combines it, one source per era.
			unknowable := facts.IsModernRequest && !facts.HasMethod() ||
				!facts.IsModernRequest && !facts.IsRequestBodyPresent
			if unknowable != tc.wantUnknowable {
				t.Fatalf("unknowable = %v, want %v (Method=%q, modern=%v, bodyPresent=%v)",
					unknowable, tc.wantUnknowable, facts.Method, facts.IsModernRequest, facts.IsRequestBodyPresent)
			}
		})
	}
}

// A2 closed. Under `methods: {enabled: false}` a body that names no operation is exempt.
// Before this fix the resolver-bearing gateway challenged it while the resolver-less one
// exempted it — the same proxy, the same YAML, opposite answers — because the header path
// could not tell "the body named none" from "we never learned it".
//
// The request is a client-posted JSON-RPC response answering a server-initiated
// sampling/createMessage call: an id, a result, and no method.
func TestMethodlessBodyIsExemptOnBothGateways(t *testing.T) {
	const response = `{"jsonrpc":"2.0","id":7,"result":{"role":"assistant","content":{"type":"text","text":"warm"}}}`

	openMethods := func() *McpAuthPolicy {
		p := exemptPolicy()
		// enabled:false with no exceptions — nothing in this group needs a token.
		p.AuthConfig.Methods = SecurityConfig{Enabled: false}
		return p
	}

	t.Run("resolver-less gateway parses the body", func(t *testing.T) {
		action := openMethods().OnRequestBody(context.Background(),
			unresolvedBodyPost(nil, response), map[string]any{})
		assertExempt(t, action)
	})

	t.Run("resolver-bearing gateway reads the attributes", func(t *testing.T) {
		// What the resolver publishes for that body: it was there, it was read, it carried
		// an id, and it named no operation.
		attrs := map[string]string{attrBodyPresent: "true", attrBodyJSONRPCID: "7"}
		action := openMethods().OnRequestHeaders(context.Background(),
			resolvedHeaderPost(nil, attrs), map[string]any{})
		assertExempt(t, action)
	})

	// The distinction is load-bearing, not cosmetic: with nothing published there is no
	// body, so the operation was never learned and the request authenticates — which is
	// what the resolver-less path does for a bodyless POST.
	t.Run("no body still authenticates", func(t *testing.T) {
		action := openMethods().OnRequestHeaders(context.Background(),
			resolvedHeaderPostNoBody(nil), map[string]any{})
		assertNotExempt(t, action)
	})

	// And the bypass stays shut: withholding the required Mcp-Method is refused, not exempted.
	t.Run("modern request withholding Mcp-Method is rejected", func(t *testing.T) {
		headers := map[string][]string{headerProtocolVersion: {"2026-07-28"}}
		attrs := map[string]string{attrBodyPresent: "true", attrBodyMethod: "tools/call", attrBodyCapabilityName: "delete_everything"}
		action := openMethods().OnRequestHeaders(context.Background(),
			resolvedHeaderPost(headers, attrs), map[string]any{})
		assertMissingHeaderRejected(t, action)
	})
}

// The method comes from Mcp-Method alone, the same way the name comes from Mcp-Name. Withholding
// it leaves the operation unnamed, and mcp-auth then authenticates rather than exempting.
func TestModernMethodComesFromTheHeaderOnly(t *testing.T) {
	body := map[string]string{
		attrBodyPresent:        "true",
		attrBodyMethod:         "tools/call",
		attrBodyCapabilityName: "dangerous_tool",
	}
	modern := map[string][]string{headerProtocolVersion: {"2026-07-28"}}

	t.Run("mcpFacts takes neither from the body", func(t *testing.T) {
		facts := mcpFacts(policy.NewHeaders(modern), &policy.SharedContext{
			ResolutionAttributes: policy.NewResolutionAttributes(body),
		})
		if facts.Method != "" || facts.Name != "" {
			t.Fatalf("mcpFacts = %+v, want both empty: a modern request mirrors or it states nothing", facts)
		}
	})

	// Mcp-Method is required on every modern request, so withholding it is refused.
	t.Run("mcp-auth rejects, because a required header is missing", func(t *testing.T) {
		p := &McpAuthPolicy{
			OnFailureStatusCode: 401,
			ErrorMessageFormat:  "json",
			AuthConfig:          GetMcpAuthConfig(map[string]any{}),
		}
		p.AuthConfig.Tools = SecurityConfig{Enabled: false, Exceptions: []string{"dangerous_tool"}}
		ctx := resolvedHeaderPost(modern, body)
		assertMissingHeaderRejected(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})
}

// A modern request decides on its headers, so an unreadable body says nothing about it and the
// operator's rule applies as usual. Rejecting that body is mcp-spec-validation's job.
func TestUnusableBodyOnAModernRequestLeavesTheRuleToDecide(t *testing.T) {
	p := exemptPolicy("ping")
	p.AuthConfig.Tools = SecurityConfig{Enabled: false, Exceptions: []string{"dangerous_tool"}}

	for _, reason := range []string{"syntax-error", "invalid-member-type", "not-an-object", "ambiguous"} {
		t.Run(reason, func(t *testing.T) {
			ctx := resolvedHeaderPost(map[string][]string{
				headerProtocolVersion: {"2026-07-28"},
				headerMcpMethod:       {"tools/call"},
				headerMcpName:         {"get_weather"},
			}, map[string]string{attrBodyUnusable: reason})
			assertExempt(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
		})
	}

	t.Run("a protected capability is still challenged", func(t *testing.T) {
		ctx := resolvedHeaderPost(map[string][]string{
			headerProtocolVersion: {"2026-07-28"},
			headerMcpMethod:       {"tools/call"},
			headerMcpName:         {"dangerous_tool"},
		}, map[string]string{attrBodyUnusable: "ambiguous"})
		assertNotExempt(t, p.OnRequestHeaders(context.Background(), ctx, map[string]any{}))
	})
}

// MissingRequiredName covers only the three methods that must mirror a name.
func TestFacts_MissingRequiredName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		facts mcpRequestFacts
		want  bool
	}{
		{"tools/call, no name", mcpRequestFacts{Method: "tools/call"}, true},
		{"resources/read, no name", mcpRequestFacts{Method: "resources/read"}, true},
		{"prompts/get, no name", mcpRequestFacts{Method: "prompts/get"}, true},
		{"tools/call, named", mcpRequestFacts{Method: "tools/call", Name: "t"}, false},
		{"tools/list mirrors no name", mcpRequestFacts{Method: "tools/list"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.facts.MissingRequiredName(); got != tc.want {
				t.Fatalf("MissingRequiredName() = %v, want %v", got, tc.want)
			}
		})
	}
}
