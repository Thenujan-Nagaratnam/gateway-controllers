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

package openaitoazureopenai

import (
	"context"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestGetPolicy_RequiresAPIVersion(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"model": "gpt-4o"}); err == nil {
		t.Fatal("expected error when 'apiVersion' param is missing")
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"apiVersion": "2024-02-15-preview",
		"model":      "gpt-4o",
		"providerId": "azure-openai-provider",
	}); err != nil {
		t.Fatalf("unexpected error for valid params: %v", err)
	}
}

func TestBuildAzurePath(t *testing.T) {
	got := buildAzurePath("gpt-4o", DefaultPathSuffix, "2024-02-15-preview")
	want := "/openai/deployments/gpt-4o/chat/completions?api-version=2024-02-15-preview"
	if got != want {
		t.Errorf("buildAzurePath = %q, want %q", got, want)
	}
}

func TestParseParams_PathSuffixLeadingSlash(t *testing.T) {
	// A pathSuffix without a leading slash must be normalised so buildAzurePath
	// concatenates cleanly.
	p, err := parseParams(map[string]interface{}{
		"apiVersion": "2024-02-15-preview",
		"model":      "gpt-4o",
		"pathSuffix": "embeddings",
	})
	if err != nil {
		t.Fatalf("parseParams failed: %v", err)
	}
	if p.PathSuffix != "/embeddings" {
		t.Errorf("expected normalised pathSuffix '/embeddings', got %q", p.PathSuffix)
	}
}

func TestReadModelFromBody(t *testing.T) {
	reqCtx := &policy.RequestContext{
		Body: &policy.Body{Present: true, Content: []byte(`{"model":"gpt-4o-mini","messages":[]}`)},
	}
	if got := readModelFromBody(reqCtx, requestModelConfig{}); got != "gpt-4o-mini" {
		t.Errorf("expected model read from body 'gpt-4o-mini', got %q", got)
	}
	// Empty/absent body yields no deployment.
	if got := readModelFromBody(&policy.RequestContext{}, requestModelConfig{}); got != "" {
		t.Errorf("expected empty string for missing body, got %q", got)
	}
}

func TestGetPolicy_ParsesRequestModel(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"apiVersion":   "2024-02-15-preview",
		"requestModel": map[string]interface{}{"location": "payload", "identifier": "$.model"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tp := p.(*TranslatorPolicy)
	if tp.params.RequestModel.Location != "payload" || tp.params.RequestModel.Identifier != "$.model" {
		t.Fatalf("requestModel not parsed into params: %#v", tp.params.RequestModel)
	}

	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"apiVersion": "2024-02-15-preview"}); err != nil {
		t.Fatalf("requestModel should be optional: %v", err)
	}

	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{
		"apiVersion":   "2024-02-15-preview",
		"requestModel": map[string]interface{}{"location": "header", "identifier": "x-model"},
	}); err == nil {
		t.Fatal("expected an error for a non-payload requestModel.location")
	}
}

// TestOnRequestBody_UsesInjectedRequestModelJsonPath proves readModelFromBody
// actually follows the PROXY's own template's requestModel identifier (here
// deliberately NOT the default "$.model", so a pass can't be a coincidence of
// a hardcoded lookup) rather than always reading a fixed top-level field.
func TestOnRequestBody_UsesInjectedRequestModelJsonPath(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{
		APIVersion:   "2024-02-15-preview",
		PathSuffix:   DefaultPathSuffix,
		RequestModel: requestModelConfig{Location: "payload", Identifier: "$.routing.modelName"},
	}}
	action := p.OnRequestBody(context.Background(), newReqCtx(
		`{"routing":{"modelName":"gpt-4o-via-custom-path"},"messages":[]}`, map[string]interface{}{}), nil)

	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	want := "/openai/deployments/gpt-4o-via-custom-path/chat/completions?api-version=2024-02-15-preview"
	if mods.Path == nil || *mods.Path != want {
		t.Errorf("expected the model read via requestModel's JSONPath, path %q, got %v", want, mods.Path)
	}
}

// TestBuildAzurePath_EscapesUntrustedDeployment verifies the deployment id —
// which may come from the request body's "model" field — cannot inject extra
// path segments or query parameters into the Azure URL.
func TestBuildAzurePath_EscapesUntrustedDeployment(t *testing.T) {
	got := buildAzurePath("evil?api-version=hacked&x=", DefaultPathSuffix, "2024-02-15-preview")
	if strings.Contains(got, "?api-version=hacked") {
		t.Errorf("query injection via deployment not escaped: %s", got)
	}
	got = buildAzurePath("a/../../b", DefaultPathSuffix, "2024-02-15-preview")
	if strings.Contains(got, "/../") {
		t.Errorf("path traversal via deployment not escaped: %s", got)
	}
}

func newReqCtx(body string, metadata map[string]interface{}) *policy.RequestContext {
	ctx := &policy.RequestContext{
		SharedContext: &policy.SharedContext{Metadata: metadata},
	}
	if body != "" {
		ctx.Body = &policy.Body{Present: true, Content: []byte(body)}
	}
	return ctx
}

func TestOnRequestBody_RewritesPathAndSetsUpstream(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{
		APIVersion: "2024-02-15-preview",
		Model:      "gpt-4o",
		PathSuffix: DefaultPathSuffix,
		ProviderID: "azure-openai-provider",
	}}
	action := p.OnRequestBody(context.Background(), newReqCtx(`{"messages":[]}`, map[string]interface{}{}), nil)

	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	want := "/openai/deployments/gpt-4o/chat/completions?api-version=2024-02-15-preview"
	if mods.Path == nil || *mods.Path != want {
		t.Errorf("expected path %q, got %v", want, mods.Path)
	}
	if mods.UpstreamName == nil || *mods.UpstreamName != "azure-openai-provider" {
		t.Errorf("expected UpstreamName azure-openai-provider, got %v", mods.UpstreamName)
	}
}

// TestOnRequestBody_PayloadModelWinsOverConfiguredModel covers the case where
// both a static deployment and the request body's own "model" are present -
// the request-supplied one must win (e.g. so model-failover's own
// per-fallback model reaches Azure instead of being silently ignored).
func TestOnRequestBody_PayloadModelWinsOverConfiguredModel(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{
		APIVersion: "2024-02-15-preview",
		Model:      "gpt-4o-configured",
		PathSuffix: DefaultPathSuffix,
	}}
	action := p.OnRequestBody(context.Background(), newReqCtx(`{"model":"gpt-4o-from-payload","messages":[]}`, map[string]interface{}{}), nil)

	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	want := "/openai/deployments/gpt-4o-from-payload/chat/completions?api-version=2024-02-15-preview"
	if mods.Path == nil || *mods.Path != want {
		t.Errorf("expected the payload's model to win, path %q, got %v", want, mods.Path)
	}
}

// TestOnRequestBody_MissingDeploymentErrors covers the case where neither the
// policy param nor the request body supplies a model to use as the deployment.
func TestOnRequestBody_MissingDeploymentErrors(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{APIVersion: "2024-02-15-preview", PathSuffix: DefaultPathSuffix}}
	action := p.OnRequestBody(context.Background(), newReqCtx(`{"messages":[]}`, map[string]interface{}{}), nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// TestShouldRun_RoutingGates covers single-provider mode (no selection -> run)
// and multi-provider mode (run only on a matching selected_provider).
func TestShouldRun_RoutingGates(t *testing.T) {
	p := &TranslatorPolicy{params: PolicyParams{ProviderID: "azure-openai-provider"}}

	if !p.shouldRun(newReqCtx("", map[string]interface{}{})) {
		t.Error("single-provider mode (no selected_provider): expected to run")
	}
	if !p.shouldRun(newReqCtx("", map[string]interface{}{"selected_provider": "azure-openai-provider"})) {
		t.Error("matching selected_provider: expected to run")
	}
	if !p.shouldRun(newReqCtx("", map[string]interface{}{"selected_provider": "AZURE-OPENAI-PROVIDER"})) {
		t.Error("selected_provider match must be case-insensitive")
	}
	if p.shouldRun(newReqCtx("", map[string]interface{}{"selected_provider": "gemini-provider"})) {
		t.Error("non-matching selected_provider: expected to be skipped")
	}
}
