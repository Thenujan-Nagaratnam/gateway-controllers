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
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// userAndToolContentPath selects the text of user messages and tool results,
// and nothing else: not the system prompt, not tool definitions, not assistant turns.
const userAndToolContentPath = `$.messages[?(@.role=='user')]..['text','content']`

var maximumIntact = regexp.MustCompile(`"maximum":\s*9007199254740991[,\s}]`)

func maskRequest(t *testing.T, p *PIIMaskingRegexPolicy, body string) (string, map[string]interface{}) {
	t.Helper()
	ctx := piiRequestContext(body)
	action := p.OnRequestBody(context.Background(), ctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", action)
	}
	if len(mods.Body) == 0 {
		return body, ctx.Metadata
	}
	if !json.Valid(mods.Body) {
		t.Fatalf("masked body is not valid JSON: %s", mods.Body)
	}
	return string(mods.Body), ctx.Metadata
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Item 1: an email right after a JSON escape must not break the JSON.
func TestRequest_EmailAfterEscapeStaysValidJSON(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$"})
	for _, esc := range []string{`\n`, `\t`, `\r`, `<`, `\\`, `\"`} {
		t.Run(esc, func(t *testing.T) {
			body := `{"messages":[{"role":"user","content":"line1` + esc + `bob@example.org"}]}`
			out, md := maskRequest(t, p, body)
			if strings.Contains(out, "bob@example.org") {
				t.Fatalf("email not masked: %s", out)
			}
			if !strings.Contains(out, `line1`+esc+`[EMAIL_`) {
				t.Fatalf("the escape must survive in front of the placeholder: %s", out)
			}
			if len(md[MetadataKeyPIIEntities].(map[string]string)) != 1 {
				t.Fatalf("expected one mapped value, got %v", md[MetadataKeyPIIEntities])
			}
		})
	}
}

// Item 2: a number in the body is never rewritten, whatever the phone pattern says.
func TestRequest_NumbersAreNeverRewritten(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "phone": true, "jsonPath": "$"})
	body := `{"tools":[{"name":"t","input_schema":{"maximum":9007199254740991,"min":4155550199}}],"messages":[{"role":"user","content":"mail bob@example.org"}]}`
	out, _ := maskRequest(t, p, body)
	if !strings.Contains(out, `"maximum":9007199254740991`) || !strings.Contains(out, `"min":4155550199`) {
		t.Fatalf("numbers were rewritten: %s", out)
	}
	if strings.Contains(out, "bob@example.org") {
		t.Fatalf("string value was not masked: %s", out)
	}
}

// FR-003: with the whole-payload setting everything masked today stays masked,
// system prompt and tool descriptions included.
func TestRequest_WholePayloadStillMasksSystemPromptAndToolDescriptions(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$"})
	out, _ := maskRequest(t, p, readFixture(t, "testdata/messages/request.json"))
	for _, leaked := range []string{"help@corp.example", "ops@corp.example", "bob@example.org", "alice@example.com"} {
		if strings.Contains(out, leaked) {
			t.Errorf("%s must still be masked under the whole-payload setting", leaked)
		}
	}
	if !maximumIntact.MatchString(out) {
		t.Errorf("number rewritten: %s", out)
	}
}

func TestRequest_NonJSONPayloadIsMaskedAsPlainText(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$"})
	ctx := piiRequestContext("plain text for bob@example.org")
	mods := mustPIIRequestMods(t, p.OnRequestBody(context.Background(), ctx, nil))
	if strings.Contains(string(mods.Body), "bob@example.org") || !strings.HasPrefix(string(mods.Body), "plain text for [EMAIL_") {
		t.Fatalf("got %q", mods.Body)
	}
}

// Item 4: the same body masked many times gives one result, whatever entities are on.
func TestRequest_SameBodyGivesOneUpstreamBody(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "phone": true, "ssn": true, "jsonPath": "$"})
	body := `{"messages":[{"role":"user","content":"bob@example.org, (415) 555-0199, 123-45-6789, alice@example.com"}]}`
	seen := map[string]int{}
	for i := 0; i < 20; i++ {
		out, _ := maskRequest(t, p, body)
		seen[out]++
	}
	if len(seen) != 1 {
		t.Fatalf("expected one distinct upstream body, got %d", len(seen))
	}
}

// Prompt caching needs the unchanged prefix of a growing conversation to stay byte-identical.
func TestRequest_GrowingConversationKeepsItsMaskedPrefix(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "phone": true, "jsonPath": "$"})
	turn := func(i int) string {
		var parts []string
		for j := 0; j <= i; j++ {
			parts = append(parts, `{"role":"user","content":"msg `+string(rune('a'+j))+` from user`+string(rune('a'+j))+`@example.org or (415) 555-01`+string(rune('0'+j))+`0"}`)
		}
		return `{"messages":[` + strings.Join(parts, ",") + `]}`
	}
	prev, _ := maskRequest(t, p, turn(0))
	prevPrefix := strings.TrimSuffix(prev, `"}]}`)
	for i := 1; i < 10; i++ {
		cur, _ := maskRequest(t, p, turn(i))
		if !strings.HasPrefix(cur, prevPrefix) {
			t.Fatalf("turn %d changed the masked prefix:\nprev %s\ncur  %s", i, prevPrefix, cur)
		}
		prevPrefix = strings.TrimSuffix(cur, `"}]}`)
	}
}

// Item 7: two instances on one route must both be restorable.
func TestRequest_TwoInstancesMergeTheirMappings(t *testing.T) {
	emailPolicy := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$"})
	phonePolicy := mustGetPIIPolicy(t, map[string]interface{}{"phone": true, "jsonPath": "$"})

	ctx := piiRequestContext(`{"messages":[{"role":"user","content":"bob@example.org (415) 555-0199"}]}`)
	mods := mustPIIRequestMods(t, emailPolicy.OnRequestBody(context.Background(), ctx, nil))
	ctx.Body.Content = mods.Body
	mustPIIRequestMods(t, phonePolicy.OnRequestBody(context.Background(), ctx, nil))

	mapping, _ := ctx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	if mapping["bob@example.org"] == "" || mapping["(415) 555-0199"] == "" {
		t.Fatalf("both instances' values must be restorable, got %v", mapping)
	}
}

func TestRequest_RedactModeStoresNothingAndStaysValid(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "redactPII": true, "jsonPath": "$"})
	out, md := maskRequest(t, p, `{"max":9007199254740991,"messages":[{"role":"user","content":"a\nbob@example.org"}]}`)
	if !strings.Contains(out, `a\n*****`) || !strings.Contains(out, `"max":9007199254740991`) {
		t.Fatalf("got %s", out)
	}
	if _, ok := md[MetadataKeyPIIEntities]; ok {
		t.Fatal("redaction is one-way and must store no mapping")
	}
}
