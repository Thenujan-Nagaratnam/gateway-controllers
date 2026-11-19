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

package mcpspecvalidation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	legacyVersion = "2025-06-18"
	modernVersion = "2026-07-28"

	// mcpOperation is what the engine's MCP resolver reports for a resolved route. Its
	// presence is how the policy knows a resolver ran at all.
	mcpOperation = "mcp"
)

func newPolicy(t *testing.T) *McpSpecValidationPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*McpSpecValidationPolicy)
}

// newRequest builds a POST on a route the MCP resolver ran on, which is every request the
// policy is meant to see.
func newRequest(headers map[string]string, attrs map[string]string) *policy.RequestHeaderContext {
	reqCtx := newUnresolvedRequest(headers, attrs)
	reqCtx.APIKind = policy.APIKindMCP
	reqCtx.ResolvedOperation = mcpOperation
	reqCtx.Metadata = map[string]any{metadataBodyResolved: true}
	return reqCtx
}

// newUnresolvedRequest builds a POST on a route with no protocol resolver — the policy
// attached to a non-MCP API, or running on an engine with no MCP resolver at all.
func newUnresolvedRequest(headers map[string]string, attrs map[string]string) *policy.RequestHeaderContext {
	hdrs := make(map[string][]string, len(headers))
	for k, v := range headers {
		hdrs[k] = []string{v}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			ResolutionAttributes: policy.NewResolutionAttributes(attrs),
		},
		Headers: policy.NewHeaders(hdrs),
		Method:  "POST",
	}
}

// modernAttrs is what the resolver publishes for a well-formed modern tools/call.
func modernAttrs(extra map[string]string) map[string]string {
	attrs := map[string]string{attrBodyProtocolVersion: modernVersion}
	for k, v := range extra {
		attrs[k] = v
	}
	return attrs
}

// rejection unpacks an ImmediateResponse into its JSON-RPC error code and object. It fails
// the test if the action forwarded the request instead.
func rejection(t *testing.T, action policy.RequestHeaderAction) (int, map[string]any) {
	t.Helper()
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected the request to be rejected, got %T", action)
	}
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	body := resp.Body
	if strings.HasPrefix(string(body), "event:") {
		_, after, _ := strings.Cut(string(body), "data: ")
		body = []byte(strings.TrimSpace(after))
	}
	var envelope struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, body)
	}
	code, _ := envelope.Error["code"].(float64)
	return int(code), envelope.Error
}

func assertForwarded(t *testing.T, action policy.RequestHeaderAction) {
	t.Helper()
	if action != nil {
		t.Fatalf("expected the request to be forwarded, got %#v", action)
	}
}

func run(t *testing.T, p *McpSpecValidationPolicy, reqCtx *policy.RequestHeaderContext) policy.RequestHeaderAction {
	t.Helper()
	return p.OnRequestHeaders(context.Background(), reqCtx, nil)
}

// newBodyRequest builds a POST on a route without the MCP resolver.
func newBodyRequest(body string) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{},
		Headers:       policy.NewHeaders(nil),
		Body:          &policy.Body{Content: []byte(body), EndOfStream: true, Present: true},
		Method:        "POST",
	}
}

func runBody(t *testing.T, p *McpSpecValidationPolicy, reqCtx *policy.RequestContext) policy.RequestAction {
	t.Helper()
	return p.OnRequestBody(context.Background(), reqCtx, nil)
}

// ─── Which hook validates ────────────────────────────────────────────────────

func TestHeaderHookStandsAsideWithoutTheResolver(t *testing.T) {
	p := newPolicy(t)
	assertForwarded(t, run(t, p, newUnresolvedRequest(
		map[string]string{headerProtocolVersion: modernVersion, headerMcpMethod: "tools/list"},
		map[string]string{attrBodyUnusable: reasonAmbiguous},
	)))
}

func TestAnotherProtocolsResolverIsNotTheMCPOne(t *testing.T) {
	p := newPolicy(t)
	reqCtx := newRequest(nil, map[string]string{attrBodyUnusable: reasonAmbiguous})
	reqCtx.APIKind = policy.APIKindAgent
	assertForwarded(t, run(t, p, reqCtx))

	body := newBodyRequest(`{"method":"a","Method":"b"}`)
	body.APIKind = policy.APIKindAgent
	body.ResolvedOperation = mcpOperation
	body.Metadata = map[string]any{metadataBodyResolved: true}
	if _, ok := runBody(t, p, body).(policy.ImmediateResponse); !ok {
		t.Error("the body hook must validate when the resolver is not the MCP one")
	}
}

func TestBodyHookStandsAsideOnAResolverRoute(t *testing.T) {
	p := newPolicy(t)
	reqCtx := newBodyRequest(`{"method":"tools/list","Method":"tools/call"}`)
	reqCtx.APIKind = policy.APIKindMCP
	reqCtx.ResolvedOperation = mcpOperation
	reqCtx.Metadata = map[string]any{metadataBodyResolved: true}
	if action := runBody(t, p, reqCtx); action != nil {
		t.Fatalf("expected nil, got %#v", action)
	}
}

// ─── Without the resolver: body readability only ─────────────────────────────

func TestUnreadableBodyIsRejectedWithoutTheResolver(t *testing.T) {
	p := newPolicy(t)
	cases := []struct {
		name string
		body string
		code int
	}{
		{"truncated JSON", `{"jsonrpc":"2.0","method":`, codeParseError},
		{"a batch", `[{"method":"tools/list"}]`, codeInvalidRequest},
		{"a bare scalar", `42`, codeInvalidRequest},
		{"a member of the wrong type", `{"method":42}`, codeInvalidRequest},
		{"method in another letter case", `{"method":"tools/list","Method":"tools/call"}`, codeInvalidRequest},
		{"method named twice", `{"method":"tools/list","method":"tools/call"}`, codeInvalidRequest},
		{"id named twice", `{"id":1,"id":2,"method":"ping"}`, codeInvalidRequest},
		{"params.name named twice", `{"method":"tools/call","params":{"name":"a","name":"b"}}`, codeInvalidRequest},
		{"params.uri in another letter case", `{"method":"resources/read","params":{"URI":"x"}}`, codeInvalidRequest},
		{"params._meta named twice", `{"method":"ping","params":{"_meta":{},"_meta":{}}}`, codeInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, ok := runBody(t, p, newBodyRequest(tc.body)).(policy.ImmediateResponse)
			if !ok {
				t.Fatal("expected the request to be rejected")
			}
			code, errObj := rejection(t, resp)
			if code != tc.code {
				t.Errorf("code = %d, want %d", code, tc.code)
			}
			if id, present := errObj["id"]; present && id != nil {
				t.Errorf("id = %v, want none: the resolver echoes none for an unreadable body", id)
			}
		})
	}
}

// The resolver accepts these, so the body path must too.
func TestReadableBodyIsForwardedWithoutTheResolver(t *testing.T) {
	p := newPolicy(t)
	for name, body := range map[string]string{
		"a legacy tools/call":                  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_forecast"}}`,
		"params that are not an object":        `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[1,2]}`,
		"a telemetry member of the wrong type": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_forecast","clientInfo":42}}`,
		"an unread member in another case":     `{"jsonrpc":"2.0","id":1,"method":"tools/list","Extra":1,"extra":2}`,
		"a JSON-RPC response":                  `{"jsonrpc":"2.0","id":7,"result":{}}`,
		"whitespace only":                      " \n\t ",
	} {
		t.Run(name, func(t *testing.T) {
			if action := runBody(t, p, newBodyRequest(body)); action != nil {
				t.Fatalf("expected the request to be forwarded, got %#v", action)
			}
		})
	}
}

func TestMirroredHeadersAreNotValidatedWithoutTheResolver(t *testing.T) {
	p := newPolicy(t)
	reqCtx := newBodyRequest(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}}`)
	reqCtx.Headers = policy.NewHeaders(map[string][]string{
		headerProtocolVersion: {modernVersion},
		headerMcpMethod:       {"tools/list"},
	})
	if action := runBody(t, p, reqCtx); action != nil {
		t.Fatalf("expected the request to be forwarded, got %#v", action)
	}
}

func TestBodylessRequestIsForwardedWithoutTheResolver(t *testing.T) {
	p := newPolicy(t)
	reqCtx := newBodyRequest("")
	reqCtx.Body = &policy.Body{EndOfStream: true, Present: false}
	if action := runBody(t, p, reqCtx); action != nil {
		t.Fatalf("expected the request to be forwarded, got %#v", action)
	}
	reqCtx.Body = nil
	if action := runBody(t, p, reqCtx); action != nil {
		t.Fatalf("expected a nil body to be forwarded, got %#v", action)
	}
}

func TestUnusableBodyReasonMatchesTheResolver(t *testing.T) {
	for body, want := range map[string]string{
		`{"method":`: reasonSyntaxError,
		// Trailing bytes after a complete object are a syntax error, even when a member
		// inside it was named twice: the duplicate check must not classify a body it
		// has not read to the end.
		`{"method":"a","method":"b"}x`: reasonSyntaxError,
		`{"method":"a"} trailing`:      reasonSyntaxError,
		`[]`:                           reasonNotAnObject,
		`"text"`:                       reasonNotAnObject,
		`{"method":{}}`:                reasonInvalidMemberType,
		`{"Method":"tools/list"}`:      reasonAmbiguous,
		// The client's identity decides nothing the server executes, so two spellings of it
		// must not suppress the facts. Mirrors the resolver.
		`{"params":{"clientInfo":{},"ClientInfo":{}}}`:             "",
		`{"params":{"requestState":"a","requestState":"b"}}`:       reasonAmbiguous,
		`{"params":{"protocolVersion":"a","PROTOCOLVERSION":"b"}}`: reasonAmbiguous,
		// A member a fact is read from, of the wrong type. The telemetry-first bodies are the
		// ones a single decode missed, since encoding/json reports only the first type error.
		`{"params":{"name":42}}`:                  reasonInvalidMemberType,
		`{"params":{"uri":["x"]}}`:                reasonInvalidMemberType,
		`{"params":{"protocolVersion":5}}`:        reasonInvalidMemberType,
		`{"params":{"clientInfo":42,"name":5}}`:   reasonInvalidMemberType,
		`{"params":{"requestState":1,"uri":5}}`:   reasonInvalidMemberType,
		`{"params":{"taskId":5}}`:                 reasonInvalidMemberType,
		`{"params":{"taskId":"t","TaskId":"u"}}`:  reasonAmbiguous,
		`{"params":{"name":"t","clientInfo":42}}`: "",
		`{"params":[1,2]}`:                        "",
		`{"method":"tools/list"}`:                 "",
		``:                                        "",
	} {
		if got := unusableBodyReason([]byte(body)); got != want {
			t.Errorf("unusableBodyReason(%s) = %q, want %q", body, got, want)
		}
	}
}

// ─── Era dispatch ────────────────────────────────────────────────────────────

// The era is the header's value, not its presence. 2025-06-18 defines
// MCP-Protocol-Version but mirrors nothing into Mcp-Method or Mcp-Name, so treating any
// version header as modern would reject every conformant legacy request.
func TestEraIsDecidedByVersionValueNotHeaderPresence(t *testing.T) {
	p := newPolicy(t)

	t.Run("no version header is pre-2025-06-18 and forwards", func(t *testing.T) {
		assertForwarded(t, run(t, p, newRequest(nil, nil)))
	})

	t.Run("a legacy version forwards despite a body method and no Mcp-Method", func(t *testing.T) {
		assertForwarded(t, run(t, p, newRequest(
			map[string]string{headerProtocolVersion: legacyVersion},
			map[string]string{attrBodyMethod: "tools/call"},
		)))
	})

	t.Run("a modern version applies the header checks", func(t *testing.T) {
		code, _ := rejection(t, run(t, p, newRequest(
			map[string]string{headerProtocolVersion: modernVersion}, // Mcp-Method missing
			nil,
		)))
		if code != codeHeaderMismatch {
			t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
		}
	})
}

// ─── Body validation, both eras ──────────────────────────────────────────────

// The resolver reports why it could not read a body; the policy turns that into the error
// the client should see. Broken syntax is a parse error, everything else an invalid
// request — collapsing them would answer -32700 for a document that parsed fine.
func TestUnreadableBodyIsRejectedWithTheMappedCode(t *testing.T) {
	p := newPolicy(t)

	tests := []struct {
		reason string
		want   int
	}{
		{reasonSyntaxError, codeParseError},
		{reasonInvalidMemberType, codeInvalidRequest},
		{reasonNotAnObject, codeInvalidRequest},
		{reasonAmbiguous, codeInvalidRequest},
		// A reason this build does not recognise still means the body was unreadable.
		{"something-new", codeInvalidRequest},
	}

	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			code, _ := rejection(t, run(t, p, newRequest(
				map[string]string{headerProtocolVersion: modernVersion},
				map[string]string{attrBodyUnusable: tc.reason},
			)))
			if code != tc.want {
				t.Errorf("code = %d, want %d", code, tc.want)
			}
		})
	}
}

// Body validation is era-independent. A legacy request skips every header check, but an
// unreadable body is still a fault the gateway must not pass on — this is the case the
// previous design silently forwarded.
func TestUnreadableBodyIsRejectedOnALegacyRequestToo(t *testing.T) {
	p := newPolicy(t)
	code, _ := rejection(t, run(t, p, newRequest(
		map[string]string{headerProtocolVersion: legacyVersion},
		map[string]string{attrBodyUnusable: reasonAmbiguous},
	)))
	if code != codeInvalidRequest {
		t.Errorf("code = %d, want %d", code, codeInvalidRequest)
	}
}

// ─── The modern header checks ────────────────────────────────────────────────

func TestModernChecks(t *testing.T) {
	p := newPolicy(t)

	tests := []struct {
		name    string
		headers map[string]string
		attrs   map[string]string
		reject  bool
	}{
		{
			name: "agreeing headers and body are forwarded",
			headers: map[string]string{
				headerProtocolVersion: modernVersion,
				headerMcpMethod:       "tools/call",
				headerMcpName:         "get_forecast",
			},
			attrs: modernAttrs(map[string]string{
				attrBodyMethod: "tools/call", attrBodyCapabilityName: "get_forecast",
			}),
		},
		{
			name:    "Mcp-Method missing",
			headers: map[string]string{headerProtocolVersion: modernVersion},
			reject:  true,
		},
		{
			name: "Mcp-Name missing for tools/call",
			headers: map[string]string{
				headerProtocolVersion: modernVersion, headerMcpMethod: "tools/call",
			},
			reject: true,
		},
		{
			name: "Mcp-Name not required for tools/list",
			headers: map[string]string{
				headerProtocolVersion: modernVersion, headerMcpMethod: "tools/list",
			},
			attrs: modernAttrs(map[string]string{attrBodyMethod: "tools/list"}),
		},
		{
			name: "the declared version disagrees with the body",
			headers: map[string]string{
				headerProtocolVersion: modernVersion, headerMcpMethod: "tools/list",
			},
			attrs: map[string]string{
				attrBodyMethod: "tools/list", attrBodyProtocolVersion: legacyVersion,
			},
			reject: true,
		},
		{
			name: "method disagrees with the body",
			headers: map[string]string{
				headerProtocolVersion: modernVersion, headerMcpMethod: "tools/list",
			},
			attrs:  modernAttrs(map[string]string{attrBodyMethod: "tools/call"}),
			reject: true,
		},
		{
			name: "capability name disagrees with the body",
			headers: map[string]string{
				headerProtocolVersion: modernVersion,
				headerMcpMethod:       "tools/call",
				headerMcpName:         "get_forecast",
			},
			attrs: modernAttrs(map[string]string{
				attrBodyMethod: "tools/call", attrBodyCapabilityName: "delete_everything",
			}),
			reject: true,
		},
		{
			name: "a sentinel-encoded name is decoded before comparing",
			headers: map[string]string{
				headerProtocolVersion: modernVersion,
				headerMcpMethod:       "tools/call",
				headerMcpName:         "=?base64?Z2V0X2ZvcmVjYXN0?=",
			},
			attrs: modernAttrs(map[string]string{
				attrBodyMethod: "tools/call", attrBodyCapabilityName: "get_forecast",
			}),
		},
		{
			name: "a malformed sentinel is rejected",
			headers: map[string]string{
				headerProtocolVersion: modernVersion,
				headerMcpMethod:       "tools/call",
				headerMcpName:         "=?base64?not!base64?=",
			},
			attrs:  modernAttrs(map[string]string{attrBodyMethod: "tools/call"}),
			reject: true,
		},
		{
			name: "a header carrying CRLF is rejected",
			headers: map[string]string{
				headerProtocolVersion: modernVersion,
				headerMcpMethod:       "tools/call\r\nX-Injected: 1",
			},
			reject: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			action := run(t, p, newRequest(tc.headers, tc.attrs))
			if !tc.reject {
				assertForwarded(t, action)
				return
			}
			if code, _ := rejection(t, action); code != codeHeaderMismatch {
				t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
			}
		})
	}
}

// Check order is load-bearing: the charset rule applies to what travelled on the wire, so
// a value that is both malformed and mismatched must report the format failure. If decode
// ran first, a payload could smuggle forbidden octets through the sentinel unexamined.
func TestFormatCheckPrecedesComparison(t *testing.T) {
	p := newPolicy(t)
	action := run(t, p, newRequest(
		map[string]string{
			headerProtocolVersion: modernVersion,
			headerMcpMethod:       "tools/call\n", // charset violation
		},
		modernAttrs(map[string]string{attrBodyMethod: "tools/list"}), // and a mismatch
	))

	_, errObj := rejection(t, action)
	message, _ := errObj["message"].(string)
	if !strings.Contains(message, "not permitted") {
		t.Errorf("message = %q, want the format failure to be reported first", message)
	}
}

// ─── The body must corroborate the headers ───────────────────────────────────

// On a modern request the client MUST mirror, so each header compared at step 7 has a body
// counterpart that is required to exist. A body carrying none fails exactly as a differing
// value does, and all three headers behave the same way.
//
// The cases are enumerated rather than sampled because the absent and differing forms take
// separate paths through the message, and because a guard added to any one of the three
// would silently make it forward where the other two reject.
func TestAbsentBodyValuesFailLikeDifferingOnes(t *testing.T) {
	p := newPolicy(t)
	headers := map[string]string{
		headerProtocolVersion: modernVersion,
		headerMcpMethod:       "tools/call",
		headerMcpName:         "get_forecast",
	}
	full := map[string]string{
		attrBodyProtocolVersion: modernVersion,
		attrBodyMethod:          "tools/call",
		attrBodyCapabilityName:  "get_forecast",
	}

	// The control: everything mirrored, so the request goes through.
	t.Run("a fully mirrored body forwards", func(t *testing.T) {
		assertForwarded(t, run(t, p, newRequest(headers, full)))
	})

	without := func(key string) map[string]string {
		attrs := map[string]string{}
		for k, v := range full {
			if k != key {
				attrs[k] = v
			}
		}
		return attrs
	}

	cases := []struct {
		name   string
		attrs  map[string]string
		wantIn string
		absent bool
	}{
		{"no protocol version in the body", without(attrBodyProtocolVersion), headerProtocolVersion, true},
		{"no method in the body", without(attrBodyMethod), headerMcpMethod, true},
		{"no capability name in the body", without(attrBodyCapabilityName), headerMcpName, true},
		{"a differing protocol version", map[string]string{
			attrBodyProtocolVersion: legacyVersion, attrBodyMethod: "tools/call",
			attrBodyCapabilityName: "get_forecast"}, headerProtocolVersion, false},
		{"a differing method", map[string]string{
			attrBodyProtocolVersion: modernVersion, attrBodyMethod: "tools/list",
			attrBodyCapabilityName: "get_forecast"}, headerMcpMethod, false},
		{"a differing capability name", map[string]string{
			attrBodyProtocolVersion: modernVersion, attrBodyMethod: "tools/call",
			attrBodyCapabilityName: "delete_everything"}, headerMcpName, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, errObj := rejection(t, run(t, p, newRequest(headers, tc.attrs)))
			if code != codeHeaderMismatch {
				t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
			}
			message, _ := errObj["message"].(string)
			if !strings.Contains(message, tc.wantIn) {
				t.Errorf("message = %q, want it to name %s", message, tc.wantIn)
			}
			// Same outcome, different diagnosis: "does not match" would send the reader
			// hunting for a value that differs when there is no value at all.
			if got := strings.Contains(message, "carries no"); got != tc.absent {
				t.Errorf("message = %q, absent-case wording = %v, want %v", message, got, tc.absent)
			}
		})
	}
}

// Required and compared are two different questions. methodsRequiringName answers the
// first — must the client send Mcp-Name at all. The second applies to every method but the
// task methods: a value that was sent is a claim about the body, so it has to hold whether or
// not the method obliged the client to make it.
func TestMcpNameIsComparedWheneverItIsSent(t *testing.T) {
	p := newPolicy(t)

	headers := func(method, name string) map[string]string {
		h := map[string]string{headerProtocolVersion: modernVersion, headerMcpMethod: method}
		if name != "" {
			h[headerMcpName] = name
		}
		return h
	}
	body := func(method, name string) map[string]string {
		attrs := map[string]string{attrBodyProtocolVersion: modernVersion, attrBodyMethod: method}
		if name != "" {
			attrs[attrBodyCapabilityName] = name
		}
		return attrs
	}

	cases := []struct {
		name       string
		method     string
		headerName string
		bodyName   string
		reject     bool
	}{
		{"not sent, nothing in the body either", "tools/list", "", "", false},
		{
			// The body saying more than the header is not a failure to mirror: the spec
			// asks the client to mirror only for the three methods that require the header.
			name: "not sent, though the body names something", method: "tools/list",
			headerName: "", bodyName: "get_forecast", reject: false,
		},
		{
			// The gap this test exists for. Downstream policies read Mcp-Name; before the
			// fix nothing checked it here on a method that did not require it.
			name: "sent on a method that names no capability", method: "tools/list",
			headerName: "delete_everything", bodyName: "", reject: true,
		},
		{"sent and agreeing", "tools/list", "get_forecast", "get_forecast", false},

		// resources/subscribe is the realistic non-required case: it carries params.uri,
		// which the resolver publishes under the same capability.name key.
		{
			name: "an optional header agreeing with params.uri", method: "resources/subscribe",
			headerName: "file:///a.txt", bodyName: "file:///a.txt", reject: false,
		},
		{
			name: "an optional header disagreeing with params.uri", method: "resources/subscribe",
			headerName: "file:///a.txt", bodyName: "file:///secrets.txt", reject: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action := run(t, p, newRequest(
				headers(tc.method, tc.headerName), body(tc.method, tc.bodyName)))
			if !tc.reject {
				assertForwarded(t, action)
				return
			}
			code, errObj := rejection(t, action)
			if code != codeHeaderMismatch {
				t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
			}
			if message, _ := errObj["message"].(string); !strings.Contains(message, headerMcpName) {
				t.Errorf("message = %q, want it to name %s", message, headerMcpName)
			}
		})
	}
}

// A task method mirrors params.taskId into Mcp-Name, so the header is required and compared
// against mcp.body.task.id rather than against a capability name, which a task call never
// carries. An intermediary routes on this header, so a header and body naming different tasks
// is the contradiction this policy exists to catch.
func TestTaskMethodsMirrorTheTaskID(t *testing.T) {
	p := newPolicy(t)
	const taskID = "786512e2-9e0d-44bd-8f29-789f320fe840"

	for _, method := range []string{"tasks/get", "tasks/update", "tasks/cancel"} {
		attrs := modernAttrs(map[string]string{attrBodyMethod: method, attrBodyTaskID: taskID})
		headers := func(name string) map[string]string {
			h := map[string]string{headerProtocolVersion: modernVersion, headerMcpMethod: method}
			if name != "" {
				h[headerMcpName] = name
			}
			return h
		}

		t.Run(method+" mirroring the task id", func(t *testing.T) {
			assertForwarded(t, run(t, p, newRequest(headers(taskID), attrs)))
		})

		t.Run(method+" naming another task", func(t *testing.T) {
			code, errObj := rejection(t, run(t, p, newRequest(headers("6f1d44f2-0000-0000-0000-000000000000"), attrs)))
			if code != codeHeaderMismatch {
				t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
			}
			if message, _ := errObj["message"].(string); !strings.Contains(message, "task id") {
				t.Errorf("message = %q, want it to name the task id", message)
			}
		})

		t.Run(method+" without Mcp-Name", func(t *testing.T) {
			code, errObj := rejection(t, run(t, p, newRequest(headers(""), attrs)))
			if code != codeHeaderMismatch {
				t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
			}
			if message, _ := errObj["message"].(string); !strings.Contains(message, "required") {
				t.Errorf("message = %q, want it to say the header is required", message)
			}
		})

		// An engine whose resolver predates mcp.body.task.id publishes none. The header is
		// still required, but there is nothing to compare it against, so it is forwarded
		// rather than rejected for a gap in the gateway.
		t.Run(method+" on an engine publishing no task id", func(t *testing.T) {
			older := modernAttrs(map[string]string{attrBodyMethod: method})
			assertForwarded(t, run(t, p, newRequest(headers(taskID), older)))
		})
	}
}

// The comparison is gated on the raw header, not the decoded value. "=?base64??=" is a
// well-formed sentinel carrying an empty payload, so it decodes without error to "" —
// gating on the decoded value would read that as "no header sent" and skip the comparison
// on a tools/call, where step 5 only guarantees the raw value is non-empty.
func TestAnEmptySentinelIsStillAHeaderThatWasSent(t *testing.T) {
	p := newPolicy(t)
	code, _ := rejection(t, run(t, p, newRequest(
		map[string]string{
			headerProtocolVersion: modernVersion,
			headerMcpMethod:       "tools/call",
			headerMcpName:         "=?base64??=",
		},
		map[string]string{
			attrBodyProtocolVersion: modernVersion,
			attrBodyMethod:          "tools/call",
			attrBodyCapabilityName:  "get_forecast",
		},
	)))
	if code != codeHeaderMismatch {
		t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
	}
}

// ─── Which headers belong to which revision ──────────────────────────────────

// The charset rule follows the revision, not the request. Mcp-Name is not part of
// 2025-06-18, so a legacy request carrying a malformed one is forwarded — the gateway does
// not adjudicate a header that revision never defined, and rejecting would newly break a
// client that works today. The same header on a modern request is rejected.
func TestMirroredHeaderCharsetIsCheckedOnlyOnModernRequests(t *testing.T) {
	p := newPolicy(t)
	malformed := map[string]string{headerMcpName: "get\nforecast"}

	t.Run("legacy request forwards", func(t *testing.T) {
		headers := map[string]string{headerProtocolVersion: legacyVersion}
		headers[headerMcpName] = malformed[headerMcpName]
		assertForwarded(t, run(t, p, newRequest(headers, nil)))
	})

	t.Run("modern request rejects", func(t *testing.T) {
		headers := map[string]string{
			headerProtocolVersion: modernVersion,
			headerMcpMethod:       "tools/call",
		}
		headers[headerMcpName] = malformed[headerMcpName]
		code, _ := rejection(t, run(t, p, newRequest(headers, nil)))
		if code != codeHeaderMismatch {
			t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
		}
	})
}

// Recognised, therefore validated — even where not required. The spec scopes only the
// missing-header failure to required headers; "a header value contains invalid characters"
// is unqualified, and Mcp-Name is a standard header of this revision whatever the method.
func TestMalformedMcpNameIsRejectedEvenWhereNotRequired(t *testing.T) {
	p := newPolicy(t)
	code, _ := rejection(t, run(t, p, newRequest(
		map[string]string{
			headerProtocolVersion: modernVersion,
			headerMcpMethod:       "tools/list", // does not require Mcp-Name
			headerMcpName:         "stray\nvalue",
		},
		modernAttrs(map[string]string{attrBodyMethod: "tools/list"}),
	)))
	if code != codeHeaderMismatch {
		t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
	}
}

// ─── Scope ───────────────────────────────────────────────────────────────────

// Only the multiplexed POST endpoint carries a JSON-RPC body and mirrored headers.
// GET/DELETE /mcp and the OAuth metadata route each mean one thing and have nothing to
// validate — not even the resolver check, which would otherwise reject them all.
func TestNonPostRequestsAreNotValidated(t *testing.T) {
	p := newPolicy(t)
	reqCtx := newRequest(nil, map[string]string{attrBodyUnusable: reasonAmbiguous})
	reqCtx.Method = "GET"
	assertForwarded(t, run(t, p, reqCtx))

	body := newBodyRequest(`{"method":"a","Method":"b"}`)
	body.Method = "DELETE"
	if action := runBody(t, p, body); action != nil {
		t.Fatalf("expected nil, got %#v", action)
	}
}

func TestModeAsksForBothRequestPhases(t *testing.T) {
	mode := newPolicy(t).Mode()
	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Error("the policy must run at the request-header phase")
	}
	if mode.RequestBodyMode != policy.BodyModeBuffer {
		t.Error("the policy must ask for the buffered request body")
	}
}

// ─── Configuration ───────────────────────────────────────────────────────────

// The policy takes no parameters, so there is nothing to misconfigure. This is the exact
// breakage the rework fixes: the previous version required a controller-injected list and
// failed the whole chain build without it.
func TestGetPolicyNeedsNoParameters(t *testing.T) {
	for _, params := range []map[string]interface{}{
		nil,
		{},
		{"supportedVersions": []interface{}{"2026-07-28"}}, // a stale value is simply ignored
	} {
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err != nil {
			t.Errorf("GetPolicy(%v) = %v, want no error", params, err)
		}
	}
}

// ─── Error rendering ─────────────────────────────────────────────────────────

func TestErrorEnvelopeCorrelatesWithTheRequest(t *testing.T) {
	p := newPolicy(t)
	resp := run(t, p, newRequest(
		map[string]string{headerProtocolVersion: modernVersion},
		map[string]string{attrBodyJSONRPCID: "7"},
	)).(policy.ImmediateResponse)

	var envelope map[string]any
	if err := json.Unmarshal(resp.Body, &envelope); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	// A numeric id must round-trip as a number, not as the string "7".
	if id, _ := envelope["id"].(float64); id != 7 {
		t.Errorf("id = %v, want the numeric id 7", envelope["id"])
	}
	if resp.AnalyticsMetadata["mcpErrorCode"] != codeHeaderMismatch {
		t.Errorf("the rejection must be countable in analytics, got %v", resp.AnalyticsMetadata)
	}
}

// The id round-trips as the JSON type the client sent, because that is what a client matches
// its pending request against. The resolver publishes the token it arrived as, and this policy
// echoes it verbatim — re-parsing it is what used to answer `"id":"7"` with `"id":7`, which no
// client would correlate.
func TestErrorIDRoundTripsItsJSONType(t *testing.T) {
	cases := []struct {
		name      string
		attribute string // as the resolver publishes it
		want      string // as it must appear in the envelope
	}{
		{"a number stays a number", `7`, `"id":7`},
		{"a numeric string stays a string", `"7"`, `"id":"7"`},
		{"a non-numeric string", `"req-7"`, `"id":"req-7"`},
		{"an empty string is an id, not an absence", `""`, `"id":""`},
		{"zero", `0`, `"id":0`},
		// Defensive only: the resolver cannot produce this, but a mangled attribute must not
		// yield a malformed response body.
		{"a value that is not JSON falls back to null", `not-json`, `"id":null`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPolicy(t)
			resp := run(t, p, newRequest(
				map[string]string{headerProtocolVersion: modernVersion},
				map[string]string{attrBodyJSONRPCID: tc.attribute},
			)).(policy.ImmediateResponse)

			if !strings.Contains(string(resp.Body), tc.want) {
				t.Errorf("body = %s, want it to contain %s", resp.Body, tc.want)
			}
			// Whatever the id, the envelope must stay valid JSON.
			var envelope map[string]any
			if err := json.Unmarshal(resp.Body, &envelope); err != nil {
				t.Fatalf("body is not valid JSON: %v", err)
			}
		})
	}
}

// A notification carries no id, so the resolver publishes none, and the spec permits an
// error response that has none. The envelope must render that as an explicit null rather
// than omitting the member or inventing an id — which is why the policy needs no special
// case for notifications at all.
func TestErrorWithoutARequestIDCarriesAnExplicitNull(t *testing.T) {
	p := newPolicy(t)
	resp := run(t, p, newRequest(
		map[string]string{headerProtocolVersion: modernVersion}, // Mcp-Method missing
		nil, // a notification publishes no mcp.body.jsonrpc.id
	)).(policy.ImmediateResponse)

	var envelope map[string]any
	if err := json.Unmarshal(resp.Body, &envelope); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if id, present := envelope["id"]; !present || id != nil {
		t.Errorf("id = %v (present=%v), want an explicit null", id, present)
	}
}

// A conformant client MUST list both formats, so Accept states what it can parse rather than what
// it wants. JSON is the pick: an immediate error is one terminal message, not a stream.
func TestErrorIsJsonWhenTheClientCanReadJson(t *testing.T) {
	for _, accept := range []string{
		"application/json, text/event-stream",
		"text/event-stream, application/json",
		"*/*",
		"text/event-stream, application/json;q=0.1",
	} {
		t.Run(accept, func(t *testing.T) {
			p := newPolicy(t)
			resp := run(t, p, newRequest(
				map[string]string{headerProtocolVersion: modernVersion, "Accept": accept},
				nil,
			)).(policy.ImmediateResponse)

			if got := resp.Headers["Content-Type"]; got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			var envelope map[string]any
			if err := json.Unmarshal(resp.Body, &envelope); err != nil {
				t.Fatalf("body is not JSON: %v", err)
			}
		})
	}
}

// q=0 is RFC 9110 for "not acceptable", so a client that spells JSON out that way is left with SSE.
func TestErrorIsSseFramedWhenJsonIsRejectedByQualityZero(t *testing.T) {
	p := newPolicy(t)
	resp := run(t, p, newRequest(
		map[string]string{headerProtocolVersion: modernVersion, "Accept": "application/json;q=0, text/event-stream"},
		nil,
	)).(policy.ImmediateResponse)

	if got := resp.Headers["Content-Type"]; got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
}

func TestErrorIsSseFramedWhenTheClientAsksForAStream(t *testing.T) {
	p := newPolicy(t)
	resp := run(t, p, newRequest(
		map[string]string{headerProtocolVersion: modernVersion, "Accept": "text/event-stream"},
		nil,
	)).(policy.ImmediateResponse)

	if got := resp.Headers["Content-Type"]; got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
	if !strings.HasPrefix(string(resp.Body), "event: message\ndata: ") {
		t.Errorf("body is not an SSE frame: %q", resp.Body)
	}
}

// ─── The version header is a date ────────────────────────────────────────────

// A revision identifier is a date. Anything else is malformed, and saying so is clearer than
// what the era branch used to produce: "draft" sorts above 2026-07-28 as a string, so the
// request was read as modern and rejected for missing headers that revision never defined.
func TestMalformedProtocolVersionIsRejected(t *testing.T) {
	p := newPolicy(t)
	for _, raw := range []string{"draft", "latest", "v2026-07-28", "2026-7-28", "2026-07-28-rc1", "0",
		// Date-shaped but impossible: a bare pattern match would let these sort as modern.
		"2026-99-99", "2026-13-01", "2026-02-30"} {
		t.Run(raw, func(t *testing.T) {
			code, errObj := rejection(t, run(t, p, newRequest(
				map[string]string{headerProtocolVersion: raw}, nil)))
			if code != codeHeaderMismatch {
				t.Errorf("code = %d, want %d", code, codeHeaderMismatch)
			}
			message, _ := errObj["message"].(string)
			if !strings.Contains(message, "not a valid protocol version") {
				t.Errorf("message = %q, want it to name the malformed version", message)
			}
		})
	}
}

// Every dated revision passes, including ones newer than this build: which versions a proxy
// accepts is a separate concern, and a future revision must not be rejected as malformed.
func TestWellFormedProtocolVersionsPassTheFormatCheck(t *testing.T) {
	p := newPolicy(t)

	t.Run("a legacy revision forwards", func(t *testing.T) {
		assertForwarded(t, run(t, p, newRequest(map[string]string{headerProtocolVersion: legacyVersion}, nil)))
	})

	t.Run("an absent header forwards", func(t *testing.T) {
		assertForwarded(t, run(t, p, newRequest(nil, nil)))
	})

	t.Run("a future revision is judged as modern, not as malformed", func(t *testing.T) {
		_, errObj := rejection(t, run(t, p, newRequest(
			map[string]string{headerProtocolVersion: "2027-01-01"}, nil)))
		message, _ := errObj["message"].(string)
		if !strings.Contains(message, headerMcpMethod) {
			t.Errorf("message = %q, want the modern mirroring check, not the format check", message)
		}
	})
}

// RFC 9110 ranks matching Accept ranges by specificity, so an exact type with q=0 makes the type
// unacceptable even when a wildcard would otherwise admit it.
func TestAcceptPrecedenceDecidesTheErrorFormat(t *testing.T) {
	tests := []struct {
		accept  string
		wantSSE bool
	}{
		{"application/json, text/event-stream", false},
		{"text/event-stream", true},
		{"application/json;q=0, text/event-stream", true},
		{"application/json;q=0, */*, text/event-stream", true},
		{"*/*, application/json;q=0, text/event-stream", true},
		{"application/*;q=0, text/event-stream", true},
		{"*/*", false},
		{"text/event-stream;q=0, application/json", false},
	}
	for _, tc := range tests {
		t.Run(tc.accept, func(t *testing.T) {
			headers := policy.NewHeaders(map[string][]string{"Accept": {tc.accept}})
			if got := acceptsOnlyEventStream(headers); got != tc.wantSSE {
				t.Errorf("acceptsOnlyEventStream = %v, want %v", got, tc.wantSSE)
			}
		})
	}
}
