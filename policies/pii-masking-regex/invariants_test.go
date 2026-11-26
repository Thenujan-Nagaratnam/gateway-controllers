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

// Golden snapshots and property tests.
//
// The golden files pin the exact output of the policy for a fixed corpus, so any
// future change in behaviour shows up as a diff to review. After an intended
// change, review the diff and refresh them with:
//
//	UPDATE_GOLDEN=1 go test -run TestGolden .
//
// The fuzz targets check properties that must hold for any input:
//
//	go test -run xxx -fuzz FuzzMaskRequest -fuzztime 60s .
//	go test -run xxx -fuzz FuzzRestoreStream -fuzztime 60s .

import (
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─────────────────────────────── golden snapshots ───────────────────────────────

type goldenRequest struct {
	Params   map[string]interface{} `json:"params"`
	Body     string                 `json:"body"`
	Rejected bool                   `json:"rejected,omitempty"`
	Upstream string                 `json:"upstream,omitempty"`
	Mapping  map[string]string      `json:"mapping,omitempty"`
}

func goldenRequestCorpus(t *testing.T) map[string]goldenRequest {
	t.Helper()
	corpus := map[string]goldenRequest{}
	for _, sc := range e2eScenarios(t) {
		if len(sc.chain) != 1 || sc.big {
			continue
		}
		corpus["e2e/"+sc.name] = goldenRequest{Params: sc.chain[0], Body: sc.body}
	}
	var cases []struct {
		Name   string                 `json:"name"`
		Params map[string]interface{} `json:"params"`
		Body   json.RawMessage        `json:"body"`
	}
	if err := json.Unmarshal([]byte(readFixture(t, "testdata/regression/cases.json")), &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		corpus["regression/"+c.Name] = goldenRequest{Params: c.Params, Body: string(c.Body)}
	}
	msg := readFixture(t, "testdata/messages/request.json")
	corpus["messages/whole-payload"] = goldenRequest{Params: params{"email": true, "phone": true, "jsonPath": "$"}, Body: msg}
	corpus["messages/user-and-tool-content"] = goldenRequest{Params: params{"email": true, "phone": true, "jsonPath": userAndToolContentPath}, Body: msg}
	corpus["messages/redact"] = goldenRequest{Params: params{"email": true, "phone": true, "redactPII": true, "jsonPath": "$"}, Body: msg}
	for i, c := range buildDiffRequests(7, 60) {
		corpus["generated/"+c.name+"-"+string(rune('a'+i%26))] = goldenRequest{Params: c.params, Body: c.body}
	}
	return corpus
}

type goldenStream struct {
	Mapping map[string]string `json:"mapping"`
	Input   string            `json:"input"`
	Output  string            `json:"output"`
}

func goldenStreamCorpus(t *testing.T) map[string]goldenStream {
	t.Helper()
	p := mustGetPIIPolicy(t, allBuiltins)
	mapping := map[string]string{
		"bob@example.org": "[EMAIL_3fa91c0b]",
		"(415) 555-0199":  "[PHONE_0a1b2c3d]",
		"123-45-6789":     "[SSN_deadbeef]",
	}
	texts := []string{
		"Hi [EMAIL_3fa91c0b], call [PHONE_0a1b2c3d] about [SSN_deadbeef]; [not] one.",
		"plain answer without placeholders",
		"split ends here [EMAIL_3fa9",
	}
	out := map[string]goldenStream{}
	for _, shape := range responseShapes {
		for ti, text := range texts {
			for _, mode := range []int{0, 2} {
				body := shape.build(piecesOf(rand.New(rand.NewSource(int64(ti+mode))), text, mode))
				chunks := chunkers[4].fn(rand.New(rand.NewSource(5)), []byte(body))
				name := shape.name + "/text" + string(rune('0'+ti)) + "/pieces" + string(rune('0'+mode))
				out[name] = goldenStream{Mapping: mapping, Input: body, Output: driveAny(t, p, mapping, chunks)}
			}
		}
	}
	// Anthropic content blocks the old release could not restore.
	for _, f := range []string{"stream_tool_args.sse", "stream_thinking.sse", "stream_two_text_blocks.sse"} {
		body := readFixture(t, "testdata/messages/"+f)
		chunks := chunkers[4].fn(rand.New(rand.NewSource(9)), []byte(body))
		out["anthropic-blocks/"+f] = goldenStream{Mapping: mapping, Input: body, Output: driveAny(t, p, mapping, chunks)}
	}
	return out
}

func compareGolden(t *testing.T, file string, got interface{}) {
	t.Helper()
	path := filepath.Join("testdata", "golden", file)
	gotJSON, err := json.MarshalIndent(got, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	gotJSON = append(gotJSON, '\n')
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, gotJSON, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file %s (create it with UPDATE_GOLDEN=1): %v", path, err)
	}
	if string(want) == string(gotJSON) {
		return
	}
	// Show which entries moved.
	var a, b map[string]json.RawMessage
	_ = json.Unmarshal(want, &a)
	_ = json.Unmarshal(gotJSON, &b)
	var changed []string
	for k, v := range b {
		if w, ok := a[k]; !ok || string(w) != string(v) {
			changed = append(changed, k)
		}
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			changed = append(changed, k+" (removed)")
		}
	}
	sort.Strings(changed)
	if len(changed) > 12 {
		changed = append(changed[:12], "…")
	}
	t.Fatalf("output differs from %s in %d entries: %v\nReview the change; if it is intended, run UPDATE_GOLDEN=1 go test -run TestGolden .", path, len(changed), changed)
}

func TestGolden_Requests(t *testing.T) {
	corpus := goldenRequestCorpus(t)
	for name, c := range corpus {
		out := runNewRequest(t, c.Params, c.Body)
		c.Rejected = out.rejected
		if out.body != nil {
			c.Upstream = string(out.body)
		}
		c.Mapping = out.mapping
		corpus[name] = c
	}
	compareGolden(t, "requests.json", corpus)
}

func TestGolden_Streams(t *testing.T) {
	compareGolden(t, "streams.json", goldenStreamCorpus(t))
}

// ─────────────────────────────── properties ───────────────────────────────

// skeleton is a JSON document with the text of every string value removed. Masking
// may only change string values, so the skeleton must be unchanged.
func skeleton(body []byte) string {
	out, _, err := scanJSONStrings(body, false, func(_, text string) (string, bool) { return "", text != "" })
	if err != nil {
		return "invalid"
	}
	return string(out)
}

func leavesOf(body []byte) []string {
	var leaves []string
	_, _, _ = scanJSONStrings(body, false, func(_, text string) (string, bool) {
		leaves = append(leaves, text)
		return text, false
	})
	return leaves
}

// checkMaskProperties asserts the invariants of masking one request.
func checkMaskProperties(t *testing.T, cfg params, body []byte) {
	t.Helper()
	if !json.Valid(body) {
		return
	}
	p := mustGetPIIPolicy(t, cfg)
	ctx := piiRequestContext(string(body))
	action := p.OnRequestBody(context.Background(), ctx, nil)
	mods, ok := action.(policy.UpstreamRequestModifications)
	if !ok {
		return // a rejection is allowed (for example an invalid path), never a panic
	}
	out := body
	if mods.Body != nil {
		out = mods.Body
	}
	if !json.Valid(out) {
		t.Fatalf("valid JSON became invalid\nin  %q\nout %q", body, out)
	}
	if skeleton(out) != skeleton(body) {
		t.Fatalf("something other than string text changed\nin  %q\nout %q", body, out)
	}

	// Masking again changes nothing: the placeholders are not masked a second time.
	ctx2 := piiRequestContext(string(out))
	if mods2, ok := p.OnRequestBody(context.Background(), ctx2, nil).(policy.UpstreamRequestModifications); ok && mods2.Body != nil && string(mods2.Body) != string(out) {
		t.Fatalf("masking is not idempotent\nonce  %q\ntwice %q", out, mods2.Body)
	}

	if cfg["redactPII"] == true || cfg["jsonPath"] != "$" {
		return
	}
	// Nothing detectable is left, and restoring the placeholders gives back the input.
	mapping, _ := ctx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	inverse := map[string]string{}
	for original, ph := range mapping {
		inverse[ph] = original
	}
	inLeaves, outLeaves := leavesOf(body), leavesOf(out)
	if len(inLeaves) != len(outLeaves) {
		t.Fatalf("the number of string values changed")
	}
	detector := builtinMasker(t, cfg)
	for i := range inLeaves {
		detector.found = map[string]string{}
		detector.collect(outLeaves[i])
		if len(detector.found) != 0 {
			t.Fatalf("PII is still detectable after masking: %v in %q", detector.found, outLeaves[i])
		}
		if strings.Contains(inLeaves[i], "[") || !utf8.ValidString(inLeaves[i]) {
			continue // text that already looks like a placeholder cannot be told apart
		}
		if restored := restore(outLeaves[i], inverse); restored != inLeaves[i] {
			t.Fatalf("restoring the masked text does not give back the input\nin       %q\nmasked   %q\nrestored %q", inLeaves[i], outLeaves[i], restored)
		}
	}
}

func fuzzConfigs() []params {
	return []params{emailWhole, phoneWhole, ssnWhole, allBuiltins,
		{"email": true, "redactPII": true, "jsonPath": "$"},
		{"email": true, "jsonPath": userAndToolContentPath},
		{"email": true, "phone": true}, // default path
	}
}

func FuzzMaskRequest(f *testing.F) {
	for _, sc := range []string{
		`{"messages":[{"role":"user","content":"line1\nbob@example.org (415) 555-0199 123-45-6789"}]}`,
		`{"a":["bob@example.org",{"b":"carol@example.org"}],"n":9007199254740991}`,
		`"bob@example.org"`, `[]`, `{}`, `null`, `{"k":"x\u0000y😀bob@example.org"}`,
		`{"bob@example.org":"v","t":"1795104230191 99123-45-6789 4155550199"}`,
	} {
		for i := range fuzzConfigs() {
			f.Add([]byte(sc), uint8(i))
		}
	}
	f.Add([]byte(readFixtureForFuzz("testdata/messages/request.json")), uint8(5))
	f.Fuzz(func(t *testing.T, body []byte, cfg uint8) {
		cfgs := fuzzConfigs()
		checkMaskProperties(t, cfgs[int(cfg)%len(cfgs)], body)
	})
}

func readFixtureForFuzz(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// TestProperties_RandomRequests runs the same properties over generated requests
// on every normal test run.
func TestProperties_RandomRequests(t *testing.T) {
	n := envInt("PROP_ITERATIONS", 3000)
	rng := rand.New(rand.NewSource(int64(envInt("PROP_SEED", 1))))
	cfgs := fuzzConfigs()
	for i := 0; i < n; i++ {
		shape := requestShapes[rng.Intn(len(requestShapes)-1)] // JSON shapes only
		body := shape.wrap(diffText(rng), rng)
		checkMaskProperties(t, cfgs[rng.Intn(len(cfgs))], []byte(body))
	}
}

// FuzzRestoreStream: however the upstream tokenises an answer and however the
// network chunks it, the client receives exactly the restored text.
func FuzzRestoreStream(f *testing.F) {
	f.Add("Hi [EMAIL_3fa91c0b], call [PHONE_0a1b2c3d].", int64(1), uint8(0))
	f.Add("[EMAIL_3fa91c0b][EMAIL_3fa91c0b]", int64(2), uint8(1))
	f.Add("open [ bracket and [EMAIL_3fa9", int64(3), uint8(2))
	f.Add("héllo 日本語 \"q\" \\ [PHONE_0a1b2c3d]", int64(4), uint8(3))
	mapping := map[string]string{"bob@example.org": "[EMAIL_3fa91c0b]", "(415) 555-0199": "[PHONE_0a1b2c3d]"}
	inverse := map[string]string{"[EMAIL_3fa91c0b]": "bob@example.org", "[PHONE_0a1b2c3d]": "(415) 555-0199"}
	f.Fuzz(func(t *testing.T, text string, seed int64, shapeIdx uint8) {
		if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return
		}
		shape := responseShapes[int(shapeIdx)%len(responseShapes)]
		// Shapes that carry the text in a field this test cannot read back are skipped.
		switch shape.name {
		case "plain-text", "generic-json-object", "openai-chat-sse-with-comments-and-usage":
			return
		}
		rng := rand.New(rand.NewSource(seed))
		body := shape.build(piecesOf(rng, text, int(uint64(seed)%3)))
		ck := chunkers[int(uint64(seed)%uint64(len(chunkers)))]
		p := mustGetPIIPolicy(t, allBuiltins)
		out := driveAny(t, p, mapping, ck.fn(rand.New(rand.NewSource(seed)), []byte(body)))

		want := restore(text, inverse)
		got := assembleAnyText(t, shape.name, out)
		if got != want {
			t.Fatalf("shape %s: the client got %q, want %q\nbody %q", shape.name, got, want, body)
		}
	})
}

// assembleAnyText reads the assistant text back out of a response of any shape.
func assembleAnyText(t *testing.T, shape, raw string) string {
	t.Helper()
	switch {
	case strings.HasSuffix(shape, "-json"):
		var doc map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatalf("response is not valid JSON: %v\n%s", err, raw)
		}
		switch {
		case doc["choices"] != nil:
			return doc["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"].(string)
		default:
			return doc["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
		}
	default:
		var sb strings.Builder
		for _, line := range strings.Split(raw, "\n") {
			payload, ok := sseDataPayload(line)
			if !ok || payload == sseDone {
				continue
			}
			sb.WriteString(extractFirstDeltaContent(payload, DefaultStreamingJSONPaths))
		}
		return sb.String()
	}
}
