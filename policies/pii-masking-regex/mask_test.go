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

package piimaskingregex

import (
	"testing"
)

func builtinMasker(t *testing.T, params map[string]interface{}) *masker {
	t.Helper()
	parsed, err := parseParams(params)
	if err != nil {
		t.Fatal(err)
	}
	return newMasker(parsed.PIIEntities)
}

func maskText(m *masker, text string) string {
	m.collect(text)
	m.assign()
	return m.apply(text)
}

func TestMasker_RedactReplacesWithMarker(t *testing.T) {
	m := builtinMasker(t, map[string]interface{}{"email": true, "redactPII": true})
	m.collect("mail bob@example.org now")
	if got := m.redact("mail bob@example.org now"); got != "mail ***** now" {
		t.Fatalf("got %q", got)
	}
}
