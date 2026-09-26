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
	"io"
	"log/slog"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// BenchmarkHealthyPrimaryRequest measures the policy's own work for one
// request served by a healthy primary: every hook of both roles, as the policy
// engine would call them (plan build, dispatch pick, model rewrite, response
// classification, plan close).
func BenchmarkHealthyPrimaryRequest(b *testing.B) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer slog.SetDefault(prev)

	t := &testing.T{}
	pl := newPipeline(t, nil)
	body := []byte(`{"model":"client","messages":[{"role":"user","content":"hello"}],"temperature":0.2}`)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		front := &policy.SharedContext{Metadata: map[string]interface{}{}}
		act := pl.front.OnRequestHeaders(ctx, &policy.RequestHeaderContext{SharedContext: front, Headers: policy.NewHeaders(nil)}, nil)
		nonce := act.(policy.UpstreamRequestHeaderModifications).HeadersToSet[headerPlan]

		disp := &policy.SharedContext{Metadata: map[string]interface{}{}}
		pl.dispatch.OnRequestHeaders(ctx, &policy.RequestHeaderContext{SharedContext: disp, Headers: policy.NewHeaders(map[string][]string{headerPlan: {nonce}})}, nil)
		pl.dispatch.OnRequestBody(ctx, &policy.RequestContext{SharedContext: disp, Body: &policy.Body{Content: body, Present: true, EndOfStream: true}}, nil)
		pl.dispatch.OnResponseHeaders(ctx, &policy.ResponseHeaderContext{SharedContext: disp, ResponseStatus: 200}, nil)
		pl.front.OnResponseHeaders(ctx, &policy.ResponseHeaderContext{SharedContext: front, ResponseStatus: 200}, nil)
	}
}
