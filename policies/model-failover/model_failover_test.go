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
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestGetPolicy_ValidConfig(t *testing.T) {
	params := map[string]interface{}{
		"models": []interface{}{
			map[string]interface{}{"name": "gpt-4o", "upstreamDefinition": "primary"},
			map[string]interface{}{"name": "gpt-4o-mini", "upstreamDefinition": "fallback-1"},
		},
		"statusCodes": []interface{}{500, 502, 503},
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mfp, ok := p.(*Policy)
	if !ok {
		t.Fatalf("expected *Policy, got %T", p)
	}
	if len(mfp.models) != 2 || mfp.models[0].name != "gpt-4o" {
		t.Errorf("unexpected models: %#v", mfp.models)
	}
	if _, ok := mfp.statusCodes[500]; !ok {
		t.Error("expected 500 in statusCodes")
	}
}

func TestGetPolicy_RejectsSingleModel(t *testing.T) {
	params := map[string]interface{}{
		"models":      []interface{}{map[string]interface{}{"name": "gpt-4o", "upstreamDefinition": "primary"}},
		"statusCodes": []interface{}{500},
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
		t.Error("expected an error for a single-target models list")
	}
}
