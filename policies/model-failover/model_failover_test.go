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

package modelfailover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── test doubles ────────────────────────────────────────────────────────────

type fakeHTTPClient struct {
	calls []*http.Request
	resps []func(*http.Request) (*http.Response, error)
	next  int
}

func (f *fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	f.calls = append(f.calls, req)
	if f.next >= len(f.resps) {
		return nil, fmt.Errorf("fakeHTTPClient: no more responses queued (call %d)", f.next+1)
	}
	fn := f.resps[f.next]
	f.next++
	return fn(req)
}

func jsonResp(status int, body string) func(*http.Request) (*http.Response, error) {
	return func(*http.Request) (*http.Response, error) {
		h := http.Header{}
		h.Set("Content-Type", "application/json")
		h.Set("Connection", "keep-alive") // should never survive into the client response
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}, nil
	}
}

func errResp(err error) func(*http.Request) (*http.Response, error) {
	return func(*http.Request) (*http.Response, error) { return nil, err }
}

const testSelfBaseURL = "http://127.0.0.1:8080"

func baseResponseHeaderContext(t *testing.T, requestBody string, status int) *policy.ResponseHeaderContext {
	t.Helper()
	return &policy.ResponseHeaderContext{
		SharedContext: &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"},
		RequestHeaders: policy.NewHeaders(map[string][]string{
			"authorization":     {"Bearer original-token"},
			"content-type":      {"application/json"},
			"connection":        {"keep-alive"}, // must NOT be replayed
			"transfer-encoding": {"chunked"},    // must NOT be replayed
		}),
		RequestBody:    &policy.Body{Content: []byte(requestBody), Present: true},
		RequestPath:    "/v1/chat/completions",
		RequestMethod:  http.MethodPost,
		ResponseStatus: status,
		Upstream: &policy.UpstreamResponseContext{
			Name: "primary", URL: "https://api.openai.com", BasePath: "",
		},
		Downstream: &policy.DownstreamContext{Request: &policy.DownstreamRequest{
			Path: "/mf-proxy/chat/completions",
		}},
	}
}

func baseRequestContext(t *testing.T, requestBody string) *policy.RequestContext {
	t.Helper()
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"},
		Headers: policy.NewHeaders(map[string][]string{
			"authorization": {"Bearer original-token"},
			"content-type":  {"application/json"},
		}),
		Body:   &policy.Body{Content: []byte(requestBody), Present: true},
		Path:   "/v1/chat/completions",
		Method: http.MethodPost,
		Downstream: &policy.DownstreamContext{Request: &policy.DownstreamRequest{
			Path: "/mf-proxy/chat/completions",
		}},
	}
}

func newTestPolicy(t *testing.T, params map[string]interface{}) *Policy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: unexpected error: %v", err)
	}
	mfp, ok := p.(*Policy)
	if !ok {
		t.Fatalf("expected *Policy, got %T", p)
	}
	return mfp
}

// ─── GetPolicy: config validation ────────────────────────────────────────────

func TestGetPolicy_ValidMinimalConfig(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		"statusCodes": []interface{}{500},
	})
	if len(p.targets) != 1 || len(p.targets[0].fallbacks) != 0 || p.targets[0].provider != "" {
		t.Fatalf("expected one target with no fallbacks and no provider, got %+v", p.targets)
	}
}

func TestGetPolicy_MissingTargets_Errors(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"statusCodes": []interface{}{500},
	})
	if err == nil {
		t.Fatal("expected an error for missing targets")
	}
}

func TestGetPolicy_MissingStatusCodes_Errors(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{"model": "gpt-4o"}},
	})
	if err == nil {
		t.Fatal("expected an error for missing statusCodes")
	}
}

func TestGetPolicy_DuplicateTargetModel_Errors(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "gpt-4o"},
			map[string]interface{}{"model": "gpt-4o"},
		},
		"statusCodes": []interface{}{500},
	})
	if err == nil {
		t.Fatal("expected an error for a duplicated target model")
	}
}

func TestGetPolicy_TargetLevelProvider_NoSelfBaseURL_DefaultsRatherThanErrors(t *testing.T) {
	// This policy is standalone — gateway-controller never injects selfBaseURL (see the
	// package doc) — so an omitted selfBaseURL must default, never fail registration.
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "claude-direct", "provider": "anthropic-backup"},
		},
		"statusCodes": []interface{}{500},
	})
	if p.selfBaseURL != defaultSelfBaseURL {
		t.Fatalf("expected selfBaseURL to default to %q, got %q", defaultSelfBaseURL, p.selfBaseURL)
	}
}

func TestGetPolicy_TargetLevelProvider_WithSelfBaseURL_Succeeds(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "claude-direct", "provider": "anthropic-backup"},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	if p.targets[0].provider != "anthropic-backup" {
		t.Fatalf("expected target provider to be parsed, got %+v", p.targets[0])
	}
}

func TestGetPolicy_TargetProviderAndUpstreamDefinition_MutuallyExclusive(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "gpt-4o", "provider": "a", "upstreamDefinition": "b"},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	if err == nil {
		t.Fatal("expected an error when both provider and upstreamDefinition are set on a target")
	}
}

func TestGetPolicy_FallbackProvider_ParsesCorrectly(t *testing.T) {
	// A fallback-level provider reference resolves entirely via self-redial.
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "claude-3-5-sonnet", "provider": "anthropic-backup"},
				},
			},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	fb := p.targets[0].fallbacks[0]
	if fb.provider != "anthropic-backup" {
		t.Fatalf("expected the provider reference to be parsed, got %+v", fb)
	}
}

func TestGetPolicy_TargetRedirectsOwnPrimary_RequiresFallbacksToCrossProvider(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model":    "claude-direct",
				"provider": "anthropic-backup",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "claude-direct-retry"}, // bare reuse-primary — invalid here
				},
			},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	if err == nil {
		t.Fatal("expected an error: a target that redirects its own primary attempt has no primary left for a bare fallback to reuse")
	}
}

func TestGetPolicy_TargetRedirectsOwnPrimary_CrossingFallback_Succeeds(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model":    "claude-direct",
				"provider": "anthropic-backup",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "claude-direct-retry", "provider": "anthropic-secondary"},
				},
			},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	if len(p.targets[0].fallbacks) != 1 {
		t.Fatalf("expected the crossing fallback to be accepted, got %+v", p.targets[0])
	}
}

// ─── OnRequestBody ────────────────────────────────────────────────────────────

func TestOnRequestBody_ModelFailoverRedialHeader_PassesThroughUnchanged(t *testing.T) {
	// A request already carrying this policy's own marker must never be redirected again —
	// this is the recursion guard for a provider redial re-entering the operation. Deliberately
	// NOT internalLoopbackHeader: gateway-controller's own proxyInternalLoopbackMarkerPolicy
	// stamps that one unconditionally on every request through this proxy, including a
	// genuine client request — using it here would silently swallow real traffic.
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "claude-direct", "provider": "anthropic-backup"},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	rctx := baseRequestContext(t, `{"model":"claude-direct","messages":[]}`)
	rctx.Headers = policy.NewHeaders(map[string][]string{modelFailoverRedialHeader: {"1"}})

	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok || mods.UpstreamName != nil {
		t.Fatalf("expected a plain passthrough with no redirect, got %#v", action)
	}
}

func TestOnRequestBody_InternalLoopbackHeaderAlone_StillRedirects(t *testing.T) {
	// Regression test: gateway-controller's proxyInternalLoopbackMarkerPolicy stamps
	// internalLoopbackHeader unconditionally on EVERY request through this proxy, including a
	// genuine client request — a request carrying only that header (no modelFailoverRedialHeader)
	// must still be treated as genuine and redirected normally. Confirmed live: an earlier
	// version of this guard checked internalLoopbackHeader instead, which silently swallowed
	// every real client request and never redirected anything.
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "claude-direct", "provider": "anthropic-backup"},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(200, `{"id":"ok"}`)}}
	p.httpClient = fake
	rctx := baseRequestContext(t, `{"model":"claude-direct","messages":[]}`)
	rctx.Headers = policy.NewHeaders(map[string][]string{internalLoopbackHeader: {"1"}})

	action := p.OnRequestBody(context.Background(), rctx, nil)
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected the target's provider redial to still fire, got %#v", action)
	}
}

func TestOnRequestBody_UnmatchedModel_PassesThroughUnchanged(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		"statusCodes": []interface{}{500},
	})
	rctx := baseRequestContext(t, `{"model":"totally-unrelated","messages":[]}`)

	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok || mods.UpstreamName != nil {
		t.Fatalf("expected a plain passthrough, got %#v", action)
	}
}

func TestOnRequestBody_TargetUpstreamDefinition_RedirectsInProcess(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o-backup", "upstreamDefinition": "backend-b",
			},
		},
		"statusCodes": []interface{}{500},
	})
	rctx := baseRequestContext(t, `{"model":"gpt-4o-backup","messages":[]}`)

	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok || mods.UpstreamName == nil || *mods.UpstreamName != "backend-b" {
		t.Fatalf("expected an UpstreamName redirect to backend-b, got %#v", action)
	}
}

func TestOnRequestBody_TargetProvider_SuccessfulRedial(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "claude-direct", "provider": "anthropic-backup"},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(200, `{"id":"ok"}`)}}
	p.httpClient = fake
	rctx := baseRequestContext(t, `{"model":"claude-direct","messages":[{"role":"user","content":"hi"}]}`)

	action := p.OnRequestBody(context.Background(), rctx, nil)
	imm, ok := action.(policy.ImmediateResponse)
	if !ok || imm.StatusCode != 200 {
		t.Fatalf("expected a successful ImmediateResponse, got %#v", action)
	}

	req := fake.calls[0]
	if req.URL.String() != testSelfBaseURL+"/mf-proxy/chat/completions" {
		t.Fatalf("expected the redial to hit the operation's own downstream path via selfBaseURL, got %s", req.URL.String())
	}
	if got := req.Header.Get(providerHeaderName); got != "anthropic-backup" {
		t.Fatalf("expected %s to be set to the target's provider, got %q", providerHeaderName, got)
	}
	if req.Header.Get(internalLoopbackHeader) != "1" {
		t.Fatalf("expected the internal loopback marker to be set")
	}
	if req.Header.Get("Authorization") != "Bearer original-token" {
		t.Fatalf("expected the original credential to ride along on the redial (needed for the operation's own downstream auth), got %q", req.Header.Get("Authorization"))
	}

	var sentBody map[string]interface{}
	body, _ := io.ReadAll(req.Body)
	if err := json.Unmarshal(body, &sentBody); err != nil {
		t.Fatalf("redial body was not valid JSON: %v", err)
	}
	if sentBody["model"] != "claude-direct" {
		t.Fatalf("expected model to stay as the target's own model, got %v", sentBody["model"])
	}
}

func TestOnRequestBody_TargetProvider_RedialFailsThenFallbackSucceeds(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model":    "claude-direct",
				"provider": "anthropic-backup",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "claude-direct-retry", "provider": "anthropic-secondary"},
				},
			},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){
		jsonResp(500, `{"error":"down"}`),
		jsonResp(200, `{"id":"ok-from-secondary"}`),
	}}
	p.httpClient = fake
	rctx := baseRequestContext(t, `{"model":"claude-direct","messages":[{"role":"user","content":"hi"}]}`)

	action := p.OnRequestBody(context.Background(), rctx, nil)
	imm, ok := action.(policy.ImmediateResponse)
	if !ok || imm.StatusCode != 200 {
		t.Fatalf("expected the fallback's success, got %#v", action)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("expected two dial attempts (primary provider, then fallback), got %d", len(fake.calls))
	}
	if got := fake.calls[0].Header.Get(providerHeaderName); got != "anthropic-backup" {
		t.Fatalf("expected the first attempt to target anthropic-backup, got %q", got)
	}
	if got := fake.calls[1].Header.Get(providerHeaderName); got != "anthropic-secondary" {
		t.Fatalf("expected the second attempt to target anthropic-secondary, got %q", got)
	}
}

func TestOnRequestBody_TargetProvider_EverythingFails_ReturnsGenericFailure(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "claude-direct", "provider": "anthropic-backup"},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(500, `{"error":"down"}`)}}
	p.httpClient = fake
	rctx := baseRequestContext(t, `{"model":"claude-direct","messages":[{"role":"user","content":"hi"}]}`)

	action := p.OnRequestBody(context.Background(), rctx, nil)
	imm, ok := action.(policy.ImmediateResponse)
	if !ok || imm.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected an honest 502 (no primary response exists to relay), got %#v", action)
	}
}

// ─── OnResponseHeaders ────────────────────────────────────────────────────────

func TestOnResponseHeaders_NonFailingStatus_PassesThroughUnchanged(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o-mini"},
				},
			},
		},
		"statusCodes": []interface{}{500},
	})
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[]}`, 200)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a plain passthrough for a non-failing status, got %#v", action)
	}
}

// TestOnResponseHeaders_RedialHeaderPresent_SkipsFallbackWalkEvenIfModelMatchesAnotherTarget
// guards against a redial's own failing response driving a SECOND, nested fallback walk. Here
// the redialed request's own model ("claude-3-5-sonnet") happens to also be declared as its own
// independent target with a further fallback of its own — without the modelFailoverRedialHeader
// check in OnResponseHeaders, this response would trigger that target's own fallback chain too,
// and if any hop in a real config cycled back to an already-tried model, it would recurse
// indefinitely. The fix is symmetric with the existing OnRequestBody guard: a redial's outcome
// is decided once, by the dial that originated it, never by a nested walk from inside its own
// response processing.
func TestOnResponseHeaders_RedialHeaderPresent_SkipsFallbackWalkEvenIfModelMatchesAnotherTarget(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "claude-3-5-sonnet", "provider": "anthropic"},
				},
			},
			map[string]interface{}{
				"model": "claude-3-5-sonnet",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o", "provider": "openai"},
				},
			},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	// No responses queued: if OnResponseHeaders attempted any dial at all, fakeHTTPClient.Do
	// would return an error, and tryFallbackEntry would treat that as a failed attempt rather
	// than panicking — so this test also asserts zero calls were made, not just no crash.
	fake := &fakeHTTPClient{}
	p.httpClient = fake

	rhctx := baseResponseHeaderContext(t, `{"model":"claude-3-5-sonnet","messages":[]}`, 500)
	rhctx.RequestHeaders = policy.NewHeaders(map[string][]string{
		"authorization":           {"Bearer original-token"},
		"content-type":            {"application/json"},
		modelFailoverRedialHeader: {"1"},
		providerHeaderName:        {"anthropic"},
	})

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a plain passthrough for a redial's own response, got %#v", action)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no fallback dials for a redial's own failing response, got %d calls", len(fake.calls))
	}
}

func TestOnResponseHeaders_ReusePrimaryFallback_SelfRedialsWithNoProviderHeader(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o-mini"},
				},
			},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(200, `{"id":"ok"}`)}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected success, got %#v", action)
	}
	req := fake.calls[0]
	// A reuse-primary fallback is a self-redial like any other now — dialed at selfBaseURL +
	// the full downstream path, NOT the primary's own resolved upstream (no raw dial exists
	// anymore for this case; see dispatch.go's trySelfRedial).
	if req.URL.String() != testSelfBaseURL+"/mf-proxy/chat/completions" {
		t.Fatalf("expected a self-redial at selfBaseURL + the downstream path, got %s", req.URL.String())
	}
	if req.Header.Get("Authorization") != "Bearer original-token" {
		t.Fatalf("expected the original credential to be reused unchanged, got %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get(providerHeaderName) != "" {
		t.Fatalf("expected no provider header on a reuse-primary self-redial")
	}
	if req.Header.Get(modelFailoverRedialHeader) != "1" {
		t.Fatalf("expected the recursion-guard header to be set on a reuse-primary self-redial too")
	}
}

func TestOnResponseHeaders_ProviderFallback_SelfRedialsWithProviderHeader(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "claude-3-5-sonnet", "provider": "anthropic-backup"},
				},
			},
		},
		"statusCodes": []interface{}{500},
		"selfBaseURL": testSelfBaseURL,
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(200, `{"id":"ok"}`)}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	imm, ok := action.(policy.ImmediateResponse)
	if !ok || imm.StatusCode != 200 {
		t.Fatalf("expected a successful cross-provider response, got %#v", action)
	}

	req := fake.calls[0]
	if req.URL.String() != testSelfBaseURL+"/mf-proxy/chat/completions" {
		t.Fatalf("expected a self-redial to the operation's own downstream path, got %s", req.URL.String())
	}
	if got := req.Header.Get(providerHeaderName); got != "anthropic-backup" {
		t.Fatalf("expected %s to be set to the fallback's provider, got %q", providerHeaderName, got)
	}
	if req.Header.Get(internalLoopbackHeader) != "1" {
		t.Fatalf("expected the internal loopback marker to be set on a provider redial")
	}
	if req.Header.Get("Authorization") != "Bearer original-token" {
		t.Fatalf("expected the original credential to ride along on the redial (needed for the operation's own downstream auth), got %q", req.Header.Get("Authorization"))
	}

	var sentBody map[string]interface{}
	body, _ := io.ReadAll(req.Body)
	if err := json.Unmarshal(body, &sentBody); err != nil {
		t.Fatalf("redial body was not valid JSON: %v", err)
	}
	if sentBody["model"] != "claude-3-5-sonnet" {
		t.Fatalf("expected model to be rewritten to the fallback's own model, got %v", sentBody["model"])
	}
}

func TestOnResponseHeaders_NoSelfBaseURL_AllFallbacksFailClosed(t *testing.T) {
	// A defensive path: GetPolicy always defaults selfBaseURL, but if it's somehow empty at
	// dial time anyway, every fallback is now a self-redial (there is no raw-dial mechanism
	// left as a fallback that doesn't need it), so the whole chain must fail closed and let
	// the original failing response through — never dial an invalid URL.
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o-mini"},
				},
			},
		},
		"statusCodes": []interface{}{500},
	})
	p.selfBaseURL = "" // simulate the defensive case directly, bypassing GetPolicy's own guard
	fake := &fakeHTTPClient{}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected the original failing response to pass through unchanged, got %#v", action)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no dial attempts with an empty selfBaseURL, got %d", len(fake.calls))
	}
}

func TestOnResponseHeaders_AllFallbacksFail_OriginalResponsePassesThrough(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o-mini"},
				},
			},
		},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(500, `{"error":"still down"}`)}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected the original failing response to pass through unchanged, got %#v", action)
	}
}

func TestOnResponseHeaders_NetworkError_TriesNextFallback(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o-mini"},
					map[string]interface{}{"model": "gpt-4o-mini-2"},
				},
			},
		},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){
		errResp(fmt.Errorf("connection refused")),
		jsonResp(200, `{"id":"ok"}`),
	}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected the second fallback's success after the first's network error, got %#v", action)
	}
}

func TestOnResponseHeaders_UnmatchedModel_PassesThroughUnchanged(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model":     "gpt-4o",
				"fallbacks": []interface{}{map[string]interface{}{"model": "gpt-4o-mini"}},
			},
		},
		"statusCodes": []interface{}{500},
	})
	rhctx := baseResponseHeaderContext(t, `{"model":"totally-unrelated","messages":[]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a plain passthrough for an unmatched model, got %#v", action)
	}
}

func TestOnResponseHeaders_MissingRequestBody_PassesThroughUnchanged(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		"statusCodes": []interface{}{500},
	})
	rhctx := baseResponseHeaderContext(t, "", 500)
	rhctx.RequestBody = &policy.Body{Present: false}

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a plain passthrough with no body to replay, got %#v", action)
	}
}

func TestOnResponseHeaders_OversizedResponse_TriesNextFallback(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o-mini"},
				},
			},
		},
		"statusCodes":      []interface{}{500},
		"maxResponseBytes": 10,
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){
		jsonResp(200, `{"this response body is much longer than ten bytes"}`),
	}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected the oversized fallback response to be rejected and the original to pass through, got %#v", action)
	}
}

// ─── Suspend tracking ─────────────────────────────────────────────────────────

func TestOnResponseHeaders_SuspendsFailedFallback(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o-mini"},
				},
			},
		},
		"statusCodes":     []interface{}{500},
		"suspendDuration": "1m",
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(500, `{"error":"down"}`)}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[]}`, 500)

	p.OnResponseHeaders(context.Background(), rhctx, nil)

	key := suspendKey(rhctx.SharedContext, "gpt-4o", 0)
	if !p.suspend.IsSuspended(context.Background(), key) {
		t.Fatal("expected the failed fallback to be suspended")
	}
}

func TestOnResponseHeaders_DeprioritizesSuspendedFallback(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "gpt-4o-mini-suspended"},
					map[string]interface{}{"model": "gpt-4o-mini-healthy"},
				},
			},
		},
		"statusCodes":     []interface{}{500},
		"suspendDuration": "1m",
	})
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[]}`, 500)
	p.suspend.Suspend(context.Background(), suspendKey(rhctx.SharedContext, "gpt-4o", 0), p.suspendDuration)

	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(200, `{"id":"ok"}`)}}
	p.httpClient = fake

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected success, got %#v", action)
	}

	var sentBody map[string]interface{}
	body, _ := io.ReadAll(fake.calls[0].Body)
	json.Unmarshal(body, &sentBody)
	if sentBody["model"] != "gpt-4o-mini-healthy" {
		t.Fatalf("expected the non-suspended fallback to be tried first, got model=%v", sentBody["model"])
	}
}
