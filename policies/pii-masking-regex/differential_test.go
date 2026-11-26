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

// Differential tests against the frozen v1.1.0 policy (internal/legacy).
//
// They exist to stop regressions: the same request or response goes through the
// previous release and through this one, and the results are compared.
//
//   - Request side: everything v1.1.0 masked validly must still be masked. The
//     only values allowed to stop being masked are digit runs inside longer runs
//     of digits (the deliberate item 9 change). A request v1.1.0 turned into
//     invalid JSON is not a valid masking, so it is not held against the new code.
//   - Response side: for every response shape v1.1.0 restored, the bytes handed to
//     the client are identical.
//
// DIFF_ITERATIONS (default 1500) and DIFF_SEED (default 1) size the random corpus.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/gateway-controllers/policies/pii-masking-regex/internal/legacy"
)

// ─────────────────────────────── request side ───────────────────────────────

type requestOutcome struct {
	rejected bool
	body     []byte // nil when the policy left the request alone
	mapping  map[string]string
}

func runNewRequest(t *testing.T, p map[string]interface{}, body string) requestOutcome {
	t.Helper()
	pi := mustGetPIIPolicy(t, p)
	ctx := piiRequestContext(body)
	out := requestOutcome{}
	switch a := pi.OnRequestBody(context.Background(), ctx, nil).(type) {
	case policy.UpstreamRequestModifications:
		out.body = a.Body
	case policy.ImmediateResponse:
		out.rejected = true
	}
	out.mapping, _ = ctx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	return out
}

func runLegacyRequest(t *testing.T, p map[string]interface{}, body string) requestOutcome {
	t.Helper()
	pi, err := legacy.GetPolicy(policy.PolicyMetadata{}, p)
	if err != nil {
		t.Fatalf("legacy policy: %v", err)
	}
	ctx := piiRequestContext(body)
	out := requestOutcome{}
	switch a := pi.(*legacy.PIIMaskingRegexPolicy).OnRequestBody(context.Background(), ctx, nil).(type) {
	case policy.UpstreamRequestModifications:
		out.body = a.Body
	case policy.ImmediateResponse:
		out.rejected = true
	}
	out.mapping, _ = ctx.Metadata[legacy.MetadataKeyPIIEntities].(map[string]string)
	return out
}

type diffRequest struct {
	name   string
	params map[string]interface{}
	body   string
}

// requestShape wraps text the way each provider's request carries it.
type requestShape struct {
	name string
	wrap func(text string, rng *rand.Rand) string
	// paths that point at the text, besides "$", "" and the default.
	paths []string
}

func marshalJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

var requestShapes = []requestShape{
	{"openai-chat", func(text string, _ *rand.Rand) string {
		return marshalJSON(map[string]interface{}{"model": "gpt", "temperature": 0.2, "messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "be brief"},
			map[string]interface{}{"role": "user", "content": text}}})
	}, []string{"$.messages[-1].content", "$.messages[1].content"}},
	{"openai-chat-array-content", func(text string, _ *rand.Rand) string {
		return marshalJSON(map[string]interface{}{"model": "gpt", "messages": []interface{}{
			map[string]interface{}{"role": "user", "content": []interface{}{map[string]interface{}{"type": "text", "text": text}}}}})
	}, []string{"$.messages[0].content[0].text"}},
	{"anthropic-messages", func(text string, _ *rand.Rand) string {
		return marshalJSON(map[string]interface{}{"model": "claude", "max_tokens": 64, "messages": []interface{}{
			map[string]interface{}{"role": "user", "content": text}}})
	}, []string{"$.messages[-1].content"}},
	{"gemini", func(text string, _ *rand.Rand) string {
		return marshalJSON(map[string]interface{}{"contents": []interface{}{
			map[string]interface{}{"role": "user", "parts": []interface{}{map[string]interface{}{"text": text}}}}})
	}, []string{"$.contents[0].parts[0].text"}},
	{"bedrock-converse", func(text string, _ *rand.Rand) string {
		return marshalJSON(map[string]interface{}{"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": []interface{}{map[string]interface{}{"text": text}}}}})
	}, []string{"$.messages[0].content[0].text"}},
	{"responses-api", func(text string, _ *rand.Rand) string {
		return marshalJSON(map[string]interface{}{"model": "gpt", "input": text})
	}, []string{"$.input"}},
	{"legacy-completions", func(text string, _ *rand.Rand) string {
		return marshalJSON(map[string]interface{}{"model": "m", "prompt": text, "max_tokens": 16})
	}, []string{"$.prompt"}},
	{"generic-object", func(text string, _ *rand.Rand) string {
		return marshalJSON(map[string]interface{}{"user": map[string]interface{}{"name": "Sam", "note": text}, "id": 12345})
	}, []string{"$.user.note"}},
	{"plain-text", func(text string, _ *rand.Rand) string { return text }, nil},
}

var entitySets = []map[string]interface{}{
	{"email": true},
	{"phone": true},
	{"ssn": true},
	{"email": true, "phone": true, "ssn": true},
	{"customPIIEntities": []interface{}{map[string]interface{}{"piiEntity": "EMPID", "piiRegex": "EMP-[0-9]{6}"}}},
	{"email": true, "customPIIEntities": []interface{}{map[string]interface{}{"piiEntity": "CODE", "piiRegex": `(?i)code-[a-z]{3}`}}},
}

// gluePrefixes and glueSuffixes are stuck directly onto a value, with no space,
// which is where raw-text masking used to swallow a JSON escape or break a number.
var (
	gluePrefixes = []string{"\n", "\t", "\r", "<", "\"", "\\", "(", "id:", "x", "\u2028", "😀", "'", "="}
	glueSuffixes = []string{"\n", ".", ",", ")", ">", "\"", ";", "😀", "!", ""}
)

func diffText(rng *rand.Rand) string {
	var parts []string
	for i, n := 0, 1+rng.Intn(7); i < n; i++ {
		var v string
		switch rng.Intn(8) {
		case 0, 1:
			v = pools.emails[rng.Intn(len(pools.emails))]
		case 2:
			v = pools.phones[rng.Intn(len(pools.phones))]
		case 3:
			v = pools.ssns[rng.Intn(len(pools.ssns))]
		case 4:
			v = pools.awkward[rng.Intn(len(pools.awkward))]
		case 5:
			v = []string{"4155550199", "2147483647", "1795104230191", "99123-45-6789", "EMP-123456", "code-abc", "CODE-XyZ"}[rng.Intn(7)]
		default:
			v = pools.words[rng.Intn(len(pools.words))]
		}
		if rng.Intn(2) == 0 {
			v = gluePrefixes[rng.Intn(len(gluePrefixes))] + v + glueSuffixes[rng.Intn(len(glueSuffixes))]
		}
		parts = append(parts, v)
	}
	sep := " "
	if rng.Intn(4) == 0 {
		sep = "\n"
	}
	return strings.Join(parts, sep)
}

func buildDiffRequests(seed int64, n int) []diffRequest {
	rng := rand.New(rand.NewSource(seed))
	var out []diffRequest
	for i := 0; i < n; i++ {
		shape := requestShapes[rng.Intn(len(requestShapes))]
		text := diffText(rng)
		params := map[string]interface{}{}
		for k, v := range entitySets[rng.Intn(len(entitySets))] {
			params[k] = v
		}
		if rng.Intn(5) == 0 {
			params["redactPII"] = true
		}
		paths := append([]string{"$", "", "<default>"}, shape.paths...)
		path := paths[rng.Intn(len(paths))]
		if path != "<default>" {
			params["jsonPath"] = path
		}
		out = append(out, diffRequest{
			name:   fmt.Sprintf("%03d-%s-%s", i, shape.name, strings.NewReplacer("$", "root", "[", "_", "]", "_", ".", "_").Replace(path)),
			params: params,
			body:   shape.wrap(text, rng),
		})
	}
	return out
}

// insideLongerDigitRun reports whether every occurrence of v in s sits directly
// after a digit, so a number-shaped match of it would have been cut out of a
// longer number.
func insideLongerDigitRun(s, v string) bool { return !containsStandalone(s, v) }

// TestDifferential_RequestsKeepEveryValidMasking is the main regression guard on
// the request side.
func TestDifferential_RequestsKeepEveryValidMasking(t *testing.T) {
	n := envInt("DIFF_ITERATIONS", 1500)
	seed := int64(envInt("DIFF_SEED", 1))
	var comparedMasked, skippedInvalidOld, newMasksMore int
	var extras []string

	for _, c := range buildDiffRequests(seed, n) {
		c := c
		oldOut := runLegacyRequest(t, c.params, c.body)
		newOut := runNewRequest(t, c.params, c.body)

		if oldOut.rejected != newOut.rejected {
			t.Errorf("%s: v1.1.0 rejected=%v but the new policy rejected=%v\nparams %v\nbody %.300s", c.name, oldOut.rejected, newOut.rejected, c.params, c.body)
			continue
		}
		if oldOut.rejected {
			continue
		}

		isJSON := json.Valid([]byte(c.body))
		newBody := c.body
		if newOut.body != nil {
			newBody = string(newOut.body)
		}
		if isJSON && !json.Valid([]byte(newBody)) {
			t.Errorf("%s: valid JSON in, invalid JSON out\nparams %v\nbody %.300s\nout  %.300s", c.name, c.params, c.body, newBody)
			continue
		}

		// A v1.1.0 result that is not valid JSON, from valid JSON, was not a valid masking.
		if oldOut.body != nil && isJSON && !json.Valid(oldOut.body) {
			skippedInvalidOld++
			continue
		}

		redact, _ := c.params["redactPII"].(bool)
		var oldMasked []string
		if redact {
			// Redaction leaves no mapping; compare against the values v1.1.0 removed.
			if oldOut.body != nil {
				oldMasked = removedValues(c.body, string(oldOut.body), c.params)
			}
		} else {
			for original := range oldOut.mapping {
				oldMasked = append(oldMasked, original)
			}
		}
		sort.Strings(oldMasked)

		newText, oldInput := decodedText(newBody), decodedText(c.body)
		for _, original := range oldMasked {
			comparedMasked++
			if !containsStandalone(newText, original) {
				continue // masked, or removed from a position where it was part of a longer number
			}
			if keyOccurrence(c.body, original) {
				continue // an object key: keys are deliberately never masked
			}
			if insideLongerDigitRun(oldInput, original) {
				continue
			}
			t.Errorf("%s: REGRESSION: %q was masked by v1.1.0 and is not masked now\nparams %v\nbody %.400s\nout  %.400s", c.name, original, c.params, c.body, newBody)
		}

		// Informational: values the new code masks and v1.1.0 did not (when v1.1.0 produced a valid result).
		if !redact && newOut.mapping != nil {
			for original := range newOut.mapping {
				if _, ok := oldOut.mapping[original]; !ok {
					newMasksMore++
					extras = append(extras, fmt.Sprintf("%s: %q (params %v)", c.name, original, c.params))
				}
			}
		}
	}

	t.Logf("compared %d previously masked values across %d requests (%d skipped because v1.1.0 broke the JSON); the new policy masked %d additional values", comparedMasked, n, skippedInvalidOld, newMasksMore)
	for i, e := range extras {
		if i >= 15 {
			t.Logf("… and %d more", len(extras)-15)
			break
		}
		t.Logf("additional masking: %s", e)
	}
	if comparedMasked == 0 {
		t.Fatal("the corpus compared nothing; the generator is broken")
	}
}

// decodedText is the text a policy actually reads: the decoded string values of a
// JSON body joined by a separator that cannot fuse digits, or the raw text of a
// body that is not JSON.
func decodedText(body string) string {
	if !json.Valid([]byte(body)) {
		return body
	}
	var leaves []string
	_, _, _ = scanJSONStrings([]byte(body), false, func(_, text string) (string, bool) {
		leaves = append(leaves, text)
		return text, false
	})
	return strings.Join(leaves, "\x00")
}

// removedValues lists the PII values that v1.1.0 redacted out of a request.
func removedValues(before, after string, params map[string]interface{}) []string {
	m := newMasker(mustParseEntities(params))
	for _, leaf := range strings.Split(decodedText(before), "\x00") {
		m.collect(leaf)
	}
	afterText := decodedText(after)
	var removed []string
	for original := range m.found {
		if !strings.Contains(afterText, original) {
			removed = append(removed, original)
		}
	}
	return removed
}

func mustParseEntities(params map[string]interface{}) (map[string]*regexp.Regexp, map[string]bool) {
	parsed, err := parseParams(params)
	if err != nil {
		panic(err)
	}
	return parsed.PIIEntities, parsed.DigitBoundary
}

// keyOccurrence reports whether v appears in body as an object key.
func keyOccurrence(body, v string) bool {
	return strings.Contains(body, `"`+v+`":`) || strings.Contains(body, `"`+v+`" :`)
}
