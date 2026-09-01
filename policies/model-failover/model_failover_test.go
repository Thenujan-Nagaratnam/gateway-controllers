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
	}
}

func baseRequestContext(t *testing.T, requestBody string) *policy.RequestContext {
	t.Helper()
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{APIId: "api-1", OperationPath: "/chat/completions"},
		Body:          &policy.Body{Content: []byte(requestBody), Present: true},
		Path:          "/v1/chat/completions",
		Method:        http.MethodPost,
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

func TestGetPolicy_TargetLevelProvider(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "claude-3-5-sonnet", "provider": "anthropic-backup"},
		},
		"statusCodes": []interface{}{500},
	})
	if p.targets[0].provider != "anthropic-backup" {
		t.Fatalf("expected target-level provider to be parsed, got %+v", p.targets[0])
	}
}

func TestGetPolicy_FallbackWithResolvedProvider(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{
						"model": "claude-3-5-sonnet", "provider": "anthropic-backup",
						"resolvedUpstreamURL": "http://127.0.0.1:9090/anthropic-provider/latest",
					},
				},
			},
		},
		"statusCodes": []interface{}{500},
	})
	fb := p.targets[0].fallbacks[0]
	if fb.provider != "anthropic-backup" || fb.resolvedUpstreamURL != "http://127.0.0.1:9090/anthropic-provider/latest" {
		t.Fatalf("expected provider+resolvedUpstreamURL to be parsed, got %+v", fb)
	}
}

func TestGetPolicy_FallbackProviderWithoutResolution_Errors(t *testing.T) {
	// Simulates a policy attached to an LlmProvider (no additionalProviders to resolve
	// against) or a hand-crafted config that bypassed gateway-controller's registration-time
	// resolution step entirely — must fail closed, not silently produce an undialable fallback.
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "claude-3-5-sonnet", "provider": "anthropic-backup"},
				},
			},
		},
		"statusCodes": []interface{}{500},
	})
	if err == nil {
		t.Fatalf("expected an error for a provider fallback with no resolved upstream URL")
	}
}

func TestGetPolicy_FallbackWithResolvedUpstreamDefinition(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o-chain",
				"fallbacks": []interface{}{
					map[string]interface{}{
						"model": "gpt-4o-chain-b", "upstreamDefinition": "backend-b",
						"resolvedUpstreamURL": "http://host.docker.internal:9712",
					},
				},
			},
		},
		"statusCodes": []interface{}{500},
	})
	fb := p.targets[0].fallbacks[0]
	if fb.upstreamDefinition != "backend-b" || fb.resolvedUpstreamURL != "http://host.docker.internal:9712" || fb.provider != "" {
		t.Fatalf("expected upstreamDefinition+resolvedUpstreamURL to be parsed, got %+v", fb)
	}
}

func TestGetPolicy_FallbackBothProviderAndUpstreamDefinition_Errors(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{
						"model": "x", "provider": "anthropic-backup", "upstreamDefinition": "backend-b",
						"resolvedUpstreamURL": "http://example.com",
					},
				},
			},
		},
		"statusCodes": []interface{}{500},
	})
	if err == nil {
		t.Fatalf("expected an error when both provider and upstreamDefinition are set on the same fallback")
	}
}

func TestGetPolicy_TargetBothProviderAndUpstreamDefinition_Errors(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "gpt-4o", "provider": "anthropic-backup", "upstreamDefinition": "backend-b"},
		},
		"statusCodes": []interface{}{500},
	})
	if err == nil {
		t.Fatalf("expected an error when both provider and upstreamDefinition are set on the same target")
	}
}

func TestGetPolicy_FallbackUpstreamDefinitionWithoutResolution_Errors(t *testing.T) {
	// Simulates a policy attached to an LlmProxy (no native upstreamDefinitions to resolve
	// against — see llm_transformer.go) — must fail closed.
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{"model": "x", "upstreamDefinition": "backend-b"},
				},
			},
		},
		"statusCodes": []interface{}{500},
	})
	if err == nil {
		t.Fatalf("expected an error for an upstreamDefinition fallback with no resolved upstream URL")
	}
}

func TestGetPolicy_UnsupportedTransformerType_Errors(t *testing.T) {
	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"model": "gpt-4o",
				"fallbacks": []interface{}{
					map[string]interface{}{
						"model": "x", "provider": "bedrock-backup",
						"resolvedUpstreamURL":     "http://127.0.0.1:9090/bedrock-provider/latest",
						"resolvedTransformerType": "openai-to-bedrock",
					},
				},
			},
		},
		"statusCodes": []interface{}{500},
	})
	if err == nil {
		t.Fatalf("expected an error for an unsupported transformer type")
	}
}

func TestGetPolicy_Errors(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]interface{}
	}{
		{"no targets", map[string]interface{}{"statusCodes": []interface{}{500}}},
		{"empty targets", map[string]interface{}{"targets": []interface{}{}, "statusCodes": []interface{}{500}}},
		{"no statusCodes", map[string]interface{}{"targets": []interface{}{map[string]interface{}{"model": "gpt-4o"}}}},
		{"duplicate model", map[string]interface{}{
			"targets": []interface{}{
				map[string]interface{}{"model": "gpt-4o"},
				map[string]interface{}{"model": "gpt-4o"},
			},
			"statusCodes": []interface{}{500},
		}},
		{"fallback missing model", map[string]interface{}{
			"targets": []interface{}{map[string]interface{}{
				"model":     "gpt-4o",
				"fallbacks": []interface{}{map[string]interface{}{}},
			}},
			"statusCodes": []interface{}{500},
		}},
		{"invalid requestTimeout", map[string]interface{}{
			"targets": []interface{}{map[string]interface{}{"model": "gpt-4o"}}, "statusCodes": []interface{}{500},
			"requestTimeout": "not-a-duration",
		}},
		{"invalid maxResponseBytes", map[string]interface{}{
			"targets": []interface{}{map[string]interface{}{"model": "gpt-4o"}}, "statusCodes": []interface{}{500},
			"maxResponseBytes": -1,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := GetPolicy(policy.PolicyMetadata{}, tc.params); err == nil {
				t.Fatalf("expected an error, got none")
			}
		})
	}
}

// ─── OnRequestBody: target-level provider redirect ───────────────────────────

func TestOnRequestBody_NoProvider_NoOp(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		"statusCodes": []interface{}{500},
	})
	rctx := baseRequestContext(t, `{"model":"gpt-4o"}`)
	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok || mods.UpstreamName != nil {
		t.Fatalf("expected a no-op with no UpstreamName, got %#v", action)
	}
	if _, set := rctx.SharedContext.Metadata[selectedProviderMetadataKey]; set {
		t.Fatalf("expected no selected_provider metadata to be set")
	}
}

func TestOnRequestBody_TargetProvider_RedirectsAndSetsMetadata(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "claude-3-5-sonnet", "provider": "anthropic-backup"},
		},
		"statusCodes": []interface{}{500},
	})
	rctx := baseRequestContext(t, `{"model":"claude-3-5-sonnet","messages":[]}`)
	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok || mods.UpstreamName == nil || *mods.UpstreamName != "anthropic-backup" {
		t.Fatalf("expected UpstreamName=anthropic-backup, got %#v", action)
	}
	if got := rctx.SharedContext.Metadata[selectedProviderMetadataKey]; got != "anthropic-backup" {
		t.Fatalf("expected selected_provider metadata to be set, got %v", got)
	}
	if mods.Body != nil {
		t.Fatalf("expected no body mutation from a target-level redirect, got %s", mods.Body)
	}
}

func TestOnRequestBody_TargetUpstreamDefinition_RedirectsWithNoMetadata(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"model": "gpt-4o", "upstreamDefinition": "backend-b"},
		},
		"statusCodes": []interface{}{500},
	})
	rctx := baseRequestContext(t, `{"model":"gpt-4o","messages":[]}`)
	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok || mods.UpstreamName == nil || *mods.UpstreamName != "backend-b" {
		t.Fatalf("expected UpstreamName=backend-b, got %#v", action)
	}
	if _, set := rctx.SharedContext.Metadata[selectedProviderMetadataKey]; set {
		t.Fatalf("a same-provider upstreamDefinition redirect must not set selected_provider metadata — there is no conditional policy to activate")
	}
}

func TestOnRequestBody_UnmatchedModel_NoOp(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "claude-3-5-sonnet", "provider": "anthropic-backup"}},
		"statusCodes": []interface{}{500},
	})
	rctx := baseRequestContext(t, `{"model":"some-other-model"}`)
	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok || mods.UpstreamName != nil {
		t.Fatalf("expected a no-op for an unmatched model, got %#v", action)
	}
}

func TestOnRequestBody_MalformedBody_NoOp(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "claude-3-5-sonnet", "provider": "anthropic-backup"}},
		"statusCodes": []interface{}{500},
	})
	rctx := baseRequestContext(t, `not-json`)
	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok || mods.UpstreamName != nil {
		t.Fatalf("expected a no-op for a malformed body, got %#v", action)
	}
}

func TestOnRequestBody_BodyAbsent_NoOp(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "claude-3-5-sonnet", "provider": "anthropic-backup"}},
		"statusCodes": []interface{}{500},
	})
	rctx := baseRequestContext(t, "")
	rctx.Body = &policy.Body{Present: false}
	action := p.OnRequestBody(context.Background(), rctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok || mods.UpstreamName != nil {
		t.Fatalf("expected a no-op when the request body wasn't buffered, got %#v", action)
	}
}

// ─── OnResponseHeaders: passthrough (no-op) cases ────────────────────────────

func TestOnResponseHeaders_StatusNotFailing_NoOp(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o", "fallbacks": []interface{}{map[string]interface{}{"model": "gpt-4o-mini"}}}},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o"}`, 200)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a no-op passthrough, got %#v", action)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no outbound calls, got %d", len(fake.calls))
	}
}

func TestOnResponseHeaders_UnmatchedModel_NoOp(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o", "fallbacks": []interface{}{map[string]interface{}{"model": "gpt-4o-mini"}}}},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"some-other-model"}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a no-op passthrough for an unmatched model, got %#v", action)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no outbound calls for an unmatched model, got %d", len(fake.calls))
	}
}

func TestOnResponseHeaders_NoFallbacksDeclared_NoOp(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o"}},
		"statusCodes": []interface{}{500},
	})
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o"}`, 500)
	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a no-op passthrough, got %#v", action)
	}
}

func TestOnResponseHeaders_MalformedRequestBody_NoOp(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o", "fallbacks": []interface{}{map[string]interface{}{"model": "gpt-4o-mini"}}}},
		"statusCodes": []interface{}{500},
	})
	rhctx := baseResponseHeaderContext(t, `not-json`, 500)
	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a no-op passthrough for a malformed body, got %#v", action)
	}
}

func TestOnResponseHeaders_RequestBodyAbsent_NoOp(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets":     []interface{}{map[string]interface{}{"model": "gpt-4o", "fallbacks": []interface{}{map[string]interface{}{"model": "gpt-4o-mini"}}}},
		"statusCodes": []interface{}{500},
	})
	rhctx := baseResponseHeaderContext(t, "", 500)
	rhctx.RequestBody = &policy.Body{Present: false}
	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a no-op passthrough when the request body wasn't buffered, got %#v", action)
	}
}

// ─── OnResponseHeaders: same-provider fallback (no provider) ─────────────────

func TestOnResponseHeaders_SameProviderFallback_Succeeds(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model":     "gpt-4o",
			"fallbacks": []interface{}{map[string]interface{}{"model": "gpt-4o-mini"}},
		}},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){
		jsonResp(200, `{"id":"resp-1","choices":[]}`),
	}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	imm, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %#v", action)
	}
	if imm.StatusCode != 200 || string(imm.Body) != `{"id":"resp-1","choices":[]}` {
		t.Fatalf("unexpected response: %+v", imm)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected exactly one outbound call, got %d", len(fake.calls))
	}

	req := fake.calls[0]
	if req.URL.String() != "https://api.openai.com/v1/chat/completions" {
		t.Fatalf("expected fallback to reuse the primary's own upstream+path, got %s", req.URL.String())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer original-token" {
		t.Fatalf("expected the original credential to be reused verbatim (no provider = same provider), got %q", got)
	}
	if req.Header.Get(internalLoopbackHeader) != "" {
		t.Fatalf("internal loopback header must only be set for a provider-loopback dial")
	}
	if req.Header.Get("Connection") != "" || req.Header.Get("Transfer-Encoding") != "" {
		t.Fatalf("hop-by-hop headers must not be replayed, got Connection=%q Transfer-Encoding=%q",
			req.Header.Get("Connection"), req.Header.Get("Transfer-Encoding"))
	}
	if _, hasConn := imm.Headers["Connection"]; hasConn {
		t.Fatalf("hop-by-hop response headers must not be forwarded to the client")
	}

	var sentBody map[string]interface{}
	bodyBytes, _ := io.ReadAll(req.Body)
	if err := json.Unmarshal(bodyBytes, &sentBody); err != nil {
		t.Fatalf("fallback request body was not valid JSON: %v", err)
	}
	if sentBody["model"] != "gpt-4o-mini" {
		t.Fatalf("expected model to be rewritten to the fallback's own model, got %v", sentBody["model"])
	}
}

func TestOnResponseHeaders_FirstFallbackFails_SecondSucceeds(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{"model": "gpt-4o-mini"},
				map[string]interface{}{"model": "gpt-4o-nano"},
			},
		}},
		"statusCodes": []interface{}{500, 503},
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){
		jsonResp(503, `{"error":"still down"}`),
		jsonResp(200, `{"id":"ok"}`),
	}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	imm, ok := action.(policy.ImmediateResponse)
	if !ok || imm.StatusCode != 200 {
		t.Fatalf("expected the second fallback's success, got %#v", action)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("expected two outbound calls, got %d", len(fake.calls))
	}
}

func TestOnResponseHeaders_AllFallbacksFail_PassesOriginalResponseThrough(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model":     "gpt-4o",
			"fallbacks": []interface{}{map[string]interface{}{"model": "gpt-4o-mini"}},
		}},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){
		jsonResp(500, `{"error":"also down"}`),
	}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o"}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a passthrough of the original failing response, got %#v", action)
	}
}

func TestOnResponseHeaders_NetworkError_TriesNextFallback(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{"model": "gpt-4o-mini"},
				map[string]interface{}{"model": "gpt-4o-nano"},
			},
		}},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){
		errResp(fmt.Errorf("connection refused")),
		jsonResp(200, `{"id":"ok"}`),
	}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o"}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if imm, ok := action.(policy.ImmediateResponse); !ok || imm.StatusCode != 200 {
		t.Fatalf("expected a network error on one fallback to fall through to the next, got %#v", action)
	}
}

func TestOnResponseHeaders_ResponseTooLarge_TriesNextFallback(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{"model": "gpt-4o-mini"},
				map[string]interface{}{"model": "gpt-4o-nano"},
			},
		}},
		"statusCodes":      []interface{}{500},
		"maxResponseBytes": 10,
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){
		jsonResp(200, `{"this response body is way over ten bytes"}`),
		jsonResp(200, `{"ok":1}`),
	}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o"}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if imm, ok := action.(policy.ImmediateResponse); !ok || imm.StatusCode != 200 || string(imm.Body) != `{"ok":1}` {
		t.Fatalf("expected the oversized response to be rejected and the next fallback used, got %#v", action)
	}
}

// ─── Suspend behavior ─────────────────────────────────────────────────────────

func TestOnResponseHeaders_Suspend_DeprioritizesRecentlyFailedFallback(t *testing.T) {
	params := map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{"model": "gpt-4o-mini"},
				map[string]interface{}{"model": "gpt-4o-nano"},
			},
		}},
		"statusCodes":     []interface{}{500},
		"suspendDuration": "1m",
	}
	p := newTestPolicy(t, params)
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){
		jsonResp(500, `{"error":"mini down"}`), // fallback[0] fails -> suspended
		jsonResp(200, `{"id":"nano-ok"}`),      // fallback[1] succeeds
	}}
	p.httpClient = fake
	rhctx1 := baseResponseHeaderContext(t, `{"model":"gpt-4o"}`, 500)
	if action := p.OnResponseHeaders(context.Background(), rhctx1, nil); action == nil {
		t.Fatalf("expected an action")
	}

	// Second, independent request: fallback[0] (gpt-4o-mini) is now suspended, so it should
	// be tried LAST — the first dial this time should go straight to fallback[1] (gpt-4o-nano).
	fake2 := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){
		jsonResp(200, `{"id":"nano-ok-2"}`),
	}}
	p.httpClient = fake2
	rhctx2 := baseResponseHeaderContext(t, `{"model":"gpt-4o"}`, 500)
	action := p.OnResponseHeaders(context.Background(), rhctx2, nil)
	imm, ok := action.(policy.ImmediateResponse)
	if !ok || imm.StatusCode != 200 {
		t.Fatalf("expected a successful response, got %#v", action)
	}
	if len(fake2.calls) != 1 {
		t.Fatalf("expected the suspended fallback to be skipped first, resolving in one call, got %d calls", len(fake2.calls))
	}
	var sentBody map[string]interface{}
	body, _ := io.ReadAll(fake2.calls[0].Body)
	_ = json.Unmarshal(body, &sentBody)
	if sentBody["model"] != "gpt-4o-nano" {
		t.Fatalf("expected the non-suspended fallback (gpt-4o-nano) to be tried first, got model=%v", sentBody["model"])
	}
}

// ─── Provider-loopback fallback (cross-provider) ──────────────────────────────

func TestOnResponseHeaders_ProviderFallback_DialsResolvedLoopbackURL(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{
					"model": "claude-3-5-sonnet", "provider": "anthropic-backup",
					"resolvedUpstreamURL":     "http://127.0.0.1:9090/anthropic-provider/latest",
					"resolvedTransformerType": "openai-to-anthropic-transformer",
				},
			},
		}},
		"statusCodes": []interface{}{500},
	})
	anthropicResponse := `{"id":"msg_1","model":"claude-3-5-sonnet","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":3}}`
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(200, anthropicResponse)}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[{"role":"system","content":"be nice"},{"role":"user","content":"hi"}]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	imm, ok := action.(policy.ImmediateResponse)
	if !ok || imm.StatusCode != 200 {
		t.Fatalf("expected a successful cross-provider response, got %#v", action)
	}

	req := fake.calls[0]
	// resolvedUpstreamURL already includes the target provider's own context (BasePath) —
	// the original request's own relative path is appended on top of it.
	if req.URL.String() != "http://127.0.0.1:9090/anthropic-provider/latest/v1/chat/completions" {
		t.Fatalf("expected the resolved loopback URL + original path, got %s", req.URL.String())
	}
	if req.Header.Get(internalLoopbackHeader) != "1" {
		t.Fatalf("expected the internal loopback header to be set on a provider dial")
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatalf("expected the original credential to be stripped on a provider-loopback dial, got %q", req.Header.Get("Authorization"))
	}
	if got := req.Header.Get("anthropic-version"); got == "" {
		t.Fatalf("expected the template adapter's required header to be set")
	}

	var sentToTarget map[string]interface{}
	body, _ := io.ReadAll(req.Body)
	if err := json.Unmarshal(body, &sentToTarget); err != nil {
		t.Fatalf("request to the loopback target was not valid JSON: %v", err)
	}
	if sentToTarget["system"] != "be nice" {
		t.Fatalf("expected the system message to be lifted to the top-level system field, got %v", sentToTarget)
	}
	if sentToTarget["model"] != "claude-3-5-sonnet" {
		t.Fatalf("expected model to be rewritten, got %v", sentToTarget["model"])
	}

	var clientBody map[string]interface{}
	if err := json.Unmarshal(imm.Body, &clientBody); err != nil {
		t.Fatalf("response back to the client was not valid JSON: %v", err)
	}
	choices, _ := clientBody["choices"].([]interface{})
	if len(choices) != 1 {
		t.Fatalf("expected exactly one choice in the openai-shaped response, got %v", clientBody)
	}
	msg := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	if msg["content"] != "hello" {
		t.Fatalf("expected the anthropic text block to be converted back to message.content, got %v", msg)
	}
}

func TestOnResponseHeaders_ProviderFallback_SetsResolvedAuthCredential(t *testing.T) {
	// resolvedAuthHeader/resolvedAuthValue are gateway-controller-injected from the target
	// provider's own additionalProviders[].auth (api-key type) - this fallback-level dial never
	// re-enters the proxy's own request-phase chain, so its conditional upstream-auth policy
	// never fires for it (see the package doc); the policy must set the credential itself.
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{
					"model": "claude-3-5-sonnet", "provider": "anthropic-backup",
					"resolvedUpstreamURL": "http://127.0.0.1:9090/anthropic-provider/latest",
					"resolvedAuthHeader":  "x-api-key",
					"resolvedAuthValue":   "anthropic-static-key",
				},
			},
		}},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(200, `{"id":"ok"}`)}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected success, got %#v", action)
	}

	req := fake.calls[0]
	if got := req.Header.Get("x-api-key"); got != "anthropic-static-key" {
		t.Fatalf("expected the resolved auth credential to be set on the fallback dial, got %q", got)
	}
}

func TestOnResponseHeaders_ProviderFallback_NoResolvedAuth_SendsNoCredential(t *testing.T) {
	// A provider declaring "none"/"other" auth (or none at all) resolves no
	// resolvedAuthHeader/resolvedAuthValue - the fallback dial must not invent a credential, and
	// the original request's own (unrelated) credential must stay stripped.
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{
					"model": "claude-3-5-sonnet", "provider": "anthropic-backup",
					"resolvedUpstreamURL": "http://127.0.0.1:9090/anthropic-provider/latest",
				},
			},
		}},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(200, `{"id":"ok"}`)}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected success, got %#v", action)
	}

	req := fake.calls[0]
	if got := req.Header.Get("x-api-key"); got != "" {
		t.Fatalf("expected no x-api-key header without a resolved auth credential, got %q", got)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected the original credential to stay stripped, got %q", got)
	}
}

func TestOnResponseHeaders_ProviderFallback_NoTransformer_BodyPassesThroughWithModelRewrite(t *testing.T) {
	// resolvedTransformerType empty means the target provider's own template already
	// matches the primary's - e.g. two OpenAI-compatible providers behind one proxy.
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{
					"model": "gpt-4o-mini", "provider": "openai-backup",
					"resolvedUpstreamURL": "http://127.0.0.1:9090/openai-backup-provider/latest",
				},
			},
		}},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(200, `{"id":"ok"}`)}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o","messages":[]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected success, got %#v", action)
	}
	req := fake.calls[0]
	if req.URL.String() != "http://127.0.0.1:9090/openai-backup-provider/latest/v1/chat/completions" {
		t.Fatalf("unexpected url: %s", req.URL.String())
	}
	var sentBody map[string]interface{}
	body, _ := io.ReadAll(req.Body)
	_ = json.Unmarshal(body, &sentBody)
	if sentBody["model"] != "gpt-4o-mini" {
		t.Fatalf("expected model rewrite with no other transformation, got %v", sentBody)
	}
}

// TestOnResponseHeaders_UpstreamDefinitionFallback_DialsResolvedURLWithOriginalCredential is
// the exact scenario that regressed in e2e when the schema redesign around `provider` first
// landed: a same-provider fallback naming an upstreamDefinition (a different backend of the
// SAME vendor, e.g. a backup region) must dial that backend's own resolved URL — NOT silently
// fall back to reusing the primary's own upstream — while still reusing the ORIGINAL
// credential (same provider, same auth) and setting neither the internal loopback header nor
// stripping any header, unlike a cross-provider dial.
func TestOnResponseHeaders_UpstreamDefinitionFallback_DialsResolvedURLWithOriginalCredential(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o-chain",
			"fallbacks": []interface{}{
				map[string]interface{}{
					"model": "gpt-4o-chain-b", "upstreamDefinition": "backend-b",
					"resolvedUpstreamURL": "http://host.docker.internal:9712",
				},
			},
		}},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{resps: []func(*http.Request) (*http.Response, error){jsonResp(200, `{"id":"ok"}`)}}
	p.httpClient = fake
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o-chain","messages":[]}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.ImmediateResponse); !ok {
		t.Fatalf("expected success, got %#v", action)
	}
	req := fake.calls[0]
	if req.URL.String() != "http://host.docker.internal:9712/v1/chat/completions" {
		t.Fatalf("expected the resolved upstreamDefinition URL (NOT the primary's own upstream), got %s", req.URL.String())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer original-token" {
		t.Fatalf("expected the original credential to be reused (same provider), got %q", got)
	}
	if req.Header.Get(internalLoopbackHeader) != "" {
		t.Fatalf("internal loopback header must only be set for a cross-provider dial, not a same-provider upstreamDefinition")
	}
}

func TestOnResponseHeaders_ProviderFallback_MalformedTransformSource_SkipsFallback(t *testing.T) {
	p := newTestPolicy(t, map[string]interface{}{
		"targets": []interface{}{map[string]interface{}{
			"model": "gpt-4o",
			"fallbacks": []interface{}{
				map[string]interface{}{
					"model": "claude-3-5-sonnet", "provider": "anthropic-backup",
					"resolvedUpstreamURL":     "http://127.0.0.1:9090/anthropic-provider/latest",
					"resolvedTransformerType": "openai-to-anthropic-transformer",
				},
			},
		}},
		"statusCodes": []interface{}{500},
	})
	fake := &fakeHTTPClient{}
	p.httpClient = fake
	// No "messages" array at all — the anthropic adapter can't build a request from this.
	rhctx := baseResponseHeaderContext(t, `{"model":"gpt-4o"}`, 500)

	action := p.OnResponseHeaders(context.Background(), rhctx, nil)
	if _, ok := action.(policy.DownstreamResponseHeaderModifications); !ok {
		t.Fatalf("expected a passthrough when the body can't be transformed, got %#v", action)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected the fallback to be skipped before any dial, got %d calls", len(fake.calls))
	}
}

// ─── URL resolution ────────────────────────────────────────────────────────────

func TestResolveTargetURL(t *testing.T) {
	upstream := &policy.UpstreamResponseContext{URL: "https://api.openai.com", BasePath: "/v1"}
	cases := []struct {
		name string
		fb   fallbackTarget
		path string
		want string
	}{
		{"no provider reuses primary url+basePath+path", fallbackTarget{}, "/chat/completions", "https://api.openai.com/v1/chat/completions"},
		{"provider dials its own resolved URL + original path", fallbackTarget{provider: "anthropic-backup", resolvedUpstreamURL: "http://127.0.0.1:9090/anthropic-provider/latest"}, "/chat/completions", "http://127.0.0.1:9090/anthropic-provider/latest/chat/completions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveTargetURL(tc.fb, upstream, tc.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveTargetURL_NoProviderAndNoUpstream_Errors(t *testing.T) {
	if _, err := resolveTargetURL(fallbackTarget{}, nil, "/x"); err == nil {
		t.Fatalf("expected an error when neither provider nor the primary upstream is known")
	}
}

// ─── anthropic template adapter ──────────────────────────────────────────────

func TestAnthropicAdapter_ToTarget_LiftsSystemMessage(t *testing.T) {
	body := map[string]interface{}{
		"model": "claude-3-5-sonnet",
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "be nice"},
			map[string]interface{}{"role": "system", "content": "be brief"},
			map[string]interface{}{"role": "user", "content": "hi"},
		},
	}
	out, err := anthropicAdapter{}.ToTarget(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed map[string]interface{}
	_ = json.Unmarshal(out, &parsed)
	if parsed["system"] != "be nice\n\nbe brief" {
		t.Fatalf("expected joined system message, got %v", parsed["system"])
	}
	msgs := parsed["messages"].([]interface{})
	if len(msgs) != 1 {
		t.Fatalf("expected only the non-system message to remain, got %v", msgs)
	}
	if parsed["max_tokens"] != float64(anthropicDefaultMaxTokens) {
		t.Fatalf("expected the default max_tokens, got %v", parsed["max_tokens"])
	}
}

func TestAnthropicAdapter_ToTarget_NoMessages_Errors(t *testing.T) {
	if _, err := (anthropicAdapter{}).ToTarget(map[string]interface{}{"model": "x"}); err == nil {
		t.Fatalf("expected an error for a body with no messages array")
	}
}

func TestAnthropicAdapter_ToTarget_NonStringContent_Errors(t *testing.T) {
	body := map[string]interface{}{
		"model": "x",
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": []interface{}{map[string]interface{}{"type": "text", "text": "hi"}}},
		},
	}
	if _, err := (anthropicAdapter{}).ToTarget(body); err == nil {
		t.Fatalf("expected an error for multi-part (non-string) content, which this adapter doesn't support")
	}
}

func TestAnthropicAdapter_FromTarget_ConcatenatesTextBlocks(t *testing.T) {
	resp := `{"id":"1","model":"claude","content":[{"type":"text","text":"hello "},{"type":"text","text":"world"}],"stop_reason":"max_tokens","usage":{"input_tokens":1,"output_tokens":2}}`
	out, err := (anthropicAdapter{}).FromTarget([]byte(resp))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed map[string]interface{}
	_ = json.Unmarshal(out, &parsed)
	choice := parsed["choices"].([]interface{})[0].(map[string]interface{})
	if choice["message"].(map[string]interface{})["content"] != "hello world" {
		t.Fatalf("expected concatenated text blocks, got %v", choice)
	}
	if choice["finish_reason"] != "length" {
		t.Fatalf("expected max_tokens to map to length, got %v", choice["finish_reason"])
	}
	usage := parsed["usage"].(map[string]interface{})
	if usage["total_tokens"] != float64(3) {
		t.Fatalf("expected total_tokens to be the sum, got %v", usage)
	}
}

func TestAnthropicAdapter_FromTarget_NoTextContent_Errors(t *testing.T) {
	resp := `{"id":"1","content":[{"type":"tool_use","text":""}],"usage":{}}`
	if _, err := (anthropicAdapter{}).FromTarget([]byte(resp)); err == nil {
		t.Fatalf("expected an error for a response with no text content block")
	}
}
