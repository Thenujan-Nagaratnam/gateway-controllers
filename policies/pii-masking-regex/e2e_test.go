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

// Run these as often as you like:
//
//	go test -run TestE2E -count=20 -race .
//	E2E_ITERATIONS=2000 E2E_SEED=42 go test -run TestE2E_RandomRoundTrip -v .
//
// Every test is deterministic for a given seed, so a failure is reproducible.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"
)

type params = map[string]interface{}

var (
	emailWhole  = params{"email": true, "jsonPath": "$"}
	phoneWhole  = params{"phone": true, "jsonPath": "$"}
	ssnWhole    = params{"ssn": true, "jsonPath": "$"}
	allBuiltins = params{"email": true, "phone": true, "ssn": true, "jsonPath": "$"}
)

type e2eScenario struct {
	name  string
	chain []params
	body  string

	masked []string // originals that must not reach the upstream (and must come back to the client)
	kept   []string // substrings that must reach the upstream verbatim

	unchanged    bool     // the upstream must receive the body byte for byte
	gatewayError bool     // the request is rejected and the upstream is never called
	nonJSON      bool     // the body is not JSON
	redact       bool     // one-way: nothing comes back
	allowedLeft  []string // placeholder-shaped text the user wrote, which must survive untouched
	big          bool     // skip the slowest chunk sizes
}

func jsonMsg(t *testing.T, role string, content interface{}) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"role": role, "content": content})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func e2eScenarios(t *testing.T) []e2eScenario {
	t.Helper()
	manyEmails := make([]string, 300)
	for i := range manyEmails {
		manyEmails[i] = fmt.Sprintf("user%d@example.org", i)
	}
	manyBody := `{"messages":[` + jsonMsg(t, "user", "list: "+strings.Join(manyEmails, " ")) + `]}`
	longBody := `{"messages":[` + jsonMsg(t, "user", strings.Repeat("lorem ipsum dolor sit amet ", 8000)+" reach me at tail@example.org") + `]}`

	return []e2eScenario{
		{name: "simple email", chain: []params{emailWhole},
			body:   `{"model":"m","messages":[{"role":"user","content":"mail bob@example.org please"}]}`,
			masked: []string{"bob@example.org"}},

		{name: "emails after every JSON escape", chain: []params{emailWhole},
			body: `{"messages":[{"role":"user","content":"a\nbob@example.org \tcarol@example.org \rdave@example.org <eve@example.org \\frank@example.org \"gina@example.org"}]}`,
			masked: []string{"bob@example.org", "carol@example.org", "dave@example.org", "eve@example.org",
				"frank@example.org", "gina@example.org"}},

		{name: "all built-in entities", chain: []params{allBuiltins},
			body:   `{"messages":[{"role":"user","content":"bob@example.org (415) 555-0199 +1 650-555-0142 212.555.0173 ssn 123-45-6789"}]}`,
			masked: []string{"bob@example.org", "(415) 555-0199", "+1 650-555-0142", "212.555.0173", "123-45-6789"}},

		{name: "same value repeated across turns", chain: []params{emailWhole},
			body: `{"messages":[` + jsonMsg(t, "user", "bob@example.org") + `,` + jsonMsg(t, "assistant", "noted bob@example.org") + `,` +
				jsonMsg(t, "user", "again bob@example.org and carol@example.org") + `]}`,
			masked: []string{"bob@example.org", "carol@example.org"}},

		{name: "unicode and emoji around values", chain: []params{emailWhole},
			body:   `{"messages":[{"role":"user","content":"héllo 日本語 😀 bob@example.org ✓ 😀carol@example.org 😀dave@example.org"}]}`,
			masked: []string{"bob@example.org", "carol@example.org", "dave@example.org"}},

		{name: "numbers and timestamps are untouched", chain: []params{{"email": true, "phone": true, "jsonPath": "$"}},
			body: `{"tools":[{"name":"t","input_schema":{"maximum":9007199254740991,"neg":-0.5e+10,"ts":1795104230191}}],` +
				`"messages":[{"role":"user","content":"bob@example.org started 1795104230191 id 9007199254740991"}]}`,
			masked: []string{"bob@example.org"},
			kept:   []string{`"maximum":9007199254740991`, `"neg":-0.5e+10`, `"ts":1795104230191`, "started 1795104230191 id 9007199254740991"}},

		{name: "standalone 10-digit numbers are still masked", chain: []params{phoneWhole},
			body:   `{"messages":[{"role":"user","content":"ids 4155550199 and 2147483647 here"}]}`,
			masked: []string{"4155550199", "2147483647"}},

		{name: "digits inside longer runs are left alone", chain: []params{{"ssn": true, "phone": true, "jsonPath": "$"}},
			body:      `{"messages":[{"role":"user","content":"ref 99123-45-6789 and 1234155550199 and 1795104230191"}]}`,
			unchanged: true, kept: []string{"99123-45-6789", "1234155550199", "1795104230191"}},

		{name: "whole payload masks system prompt and tool descriptions", chain: []params{emailWhole},
			body: `{"system":"Escalate to help@corp.example","tools":[{"name":"t","description":"owner ops@corp.example","input_schema":{"type":"object"}}],` +
				`"messages":[{"role":"user","content":"mail bob@example.org"}]}`,
			masked: []string{"help@corp.example", "ops@corp.example", "bob@example.org"}},

		{name: "scoped path keeps system prompt, tool definitions and assistant turns", chain: []params{{"email": true, "jsonPath": userAndToolContentPath}},
			body: `{"system":"Escalate to help@corp.example","tools":[{"name":"t","description":"owner ops@corp.example"}],"messages":[` +
				`{"role":"user","content":[{"type":"text","text":"line1\nbob@example.org"}]},` +
				`{"role":"assistant","content":[{"type":"thinking","thinking":"I saw carol@example.org","signature":"c2ln"}]},` +
				`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"owner alice@example.com"}]}]}]}`,
			masked: []string{"bob@example.org", "alice@example.com"},
			kept:   []string{"help@corp.example", "ops@corp.example", "carol@example.org"}},

		{name: "deeply nested tool_use input and tool_result", chain: []params{emailWhole},
			body: `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"n","input":{"a":{"b":[{"c":"bob@example.org"}]}}}]},` +
				`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"carol@example.org"}]}]}]}`,
			masked: []string{"bob@example.org", "carol@example.org"}},

		{name: "punctuation around emails", chain: []params{emailWhole},
			body:   `{"messages":[{"role":"user","content":"(\"bob@example.org\"), <carol@example.org>; dave@example.org."}]}`,
			masked: []string{"bob@example.org", "carol@example.org", "dave@example.org"}},

		{name: "no PII leaves the body byte-identical", chain: []params{allBuiltins},
			body:      `{ "model" : "m",  "messages":[ {"role":"user","content":"hello there"} ] }` + "\n",
			unchanged: true},

		{name: "empty strings and empty arrays", chain: []params{allBuiltins},
			body:      `{"system":"","messages":[],"tools":[],"x":{"a":""},"y":[""]}`,
			unchanged: true},

		{name: "non-JSON body is masked as plain text", chain: []params{emailWhole},
			body: "plain text for bob@example.org", nonJSON: true, masked: []string{"bob@example.org"}},

		{name: "placeholder-looking text typed by the user is left alone", chain: []params{emailWhole},
			body:        `{"messages":[{"role":"user","content":"keep [EMAIL_deadbeef] but hide bob@example.org"}]}`,
			masked:      []string{"bob@example.org"},
			kept:        []string{"[EMAIL_deadbeef]"},
			allowedLeft: []string{"[EMAIL_deadbeef]"}},

		{name: "redaction is one-way", chain: []params{{"email": true, "redactPII": true, "jsonPath": "$"}},
			body:   `{"max":9007199254740991,"messages":[{"role":"user","content":"a\nbob@example.org"}]}`,
			masked: []string{"bob@example.org"}, redact: true,
			kept: []string{`"max":9007199254740991`, `a\n*****`}},

		{name: "two instances, email then phone", chain: []params{emailWhole, phoneWhole},
			body:   `{"messages":[{"role":"user","content":"bob@example.org (415) 555-0199"}]}`,
			masked: []string{"bob@example.org", "(415) 555-0199"}},

		{name: "two instances, phone then email", chain: []params{phoneWhole, emailWhole},
			body:   `{"messages":[{"role":"user","content":"bob@example.org (415) 555-0199"}]}`,
			masked: []string{"bob@example.org", "(415) 555-0199"}},

		{name: "three instances, one entity each", chain: []params{emailWhole, phoneWhole, ssnWhole},
			body:   `{"messages":[{"role":"user","content":"bob@example.org (415) 555-0199 123-45-6789"}]}`,
			masked: []string{"bob@example.org", "(415) 555-0199", "123-45-6789"}},

		{name: "built-in plus custom entity", chain: []params{{"email": true, "jsonPath": "$",
			"customPIIEntities": []interface{}{map[string]interface{}{"piiEntity": "EMPID", "piiRegex": "EMP-[0-9]{6}"}}}},
			body:   `{"messages":[{"role":"user","content":"bob@example.org EMP-123456 EMP-654321"}]}`,
			masked: []string{"bob@example.org", "EMP-123456", "EMP-654321"}},

		{name: "original value with a quote and a backslash", chain: []params{{"jsonPath": "$",
			"customPIIEntities": []interface{}{map[string]interface{}{"piiEntity": "NOTE", "piiRegex": `code "[A-Z]+" \\ end`}}}},
			body:   `{"messages":[{"role":"user","content":"my code \"ABC\" \\ end ok"}]}`,
			masked: []string{`code "ABC" \ end`}},

		{name: "many distinct values", chain: []params{emailWhole}, body: manyBody, masked: manyEmails, big: true},

		{name: "long text with the value at the end", chain: []params{emailWhole}, body: longBody,
			masked: []string{"tail@example.org"}, big: true},

		{name: "multimodal content array with the default path is skipped", chain: []params{{"email": true}},
			body:      `{"messages":[{"role":"user","content":[{"type":"text","text":"bob@example.org"}]}]}`,
			unchanged: true, kept: []string{"bob@example.org"}},

		{name: "default path masks the last message only", chain: []params{{"email": true}},
			body:   `{"messages":[{"role":"user","content":"first bob@example.org"},{"role":"user","content":"last carol@example.org"}]}`,
			masked: []string{"carol@example.org"}, kept: []string{"first bob@example.org"}},

		{name: "scoped path that matches nothing", chain: []params{{"email": true, "jsonPath": `$.messages[?(@.role=='nobody')].content`}},
			body:      `{"messages":[{"role":"user","content":"bob@example.org"}]}`,
			unchanged: true, kept: []string{"bob@example.org"}},

		{name: "invalid selection path is rejected", chain: []params{{"email": true, "jsonPath": `$.messages[?(@.role==)]`}},
			body: `{"messages":[]}`, gatewayError: true},

		{name: "missing single-value path is rejected", chain: []params{{"email": true, "jsonPath": `$.missing.field`}},
			body: `{"messages":[]}`, gatewayError: true},

		{name: "JSON text inside a string", chain: []params{emailWhole},
			body:   `{"messages":[{"role":"user","content":"{\"to\":\"bob@example.org\",\"n\":1}"}]}`,
			masked: []string{"bob@example.org"}},

		{name: "keys that look like values are never masked", chain: []params{emailWhole},
			body:   `{"bob@example.org":"value","messages":[{"role":"user","content":"carol@example.org"}]}`,
			masked: []string{"carol@example.org"}, kept: []string{`"bob@example.org":"value"`}},
	}
}

// checkRequestSide asserts what the upstream received.
func checkRequestSide(t *testing.T, sc e2eScenario, ex exchange) {
	t.Helper()
	if sc.gatewayError {
		if !ex.gatewayError {
			t.Fatalf("expected the gateway to reject the request, but it was forwarded: %.200s", ex.upstreamSaw)
		}
		if ex.upstreamCalls != 0 {
			t.Fatalf("a rejected request must never reach the upstream")
		}
		return
	}
	if ex.gatewayError {
		t.Fatalf("unexpected gateway error: %s", ex.errorBody)
	}
	if ex.upstreamCalls != 1 {
		t.Fatalf("expected exactly one upstream call, got %d", ex.upstreamCalls)
	}
	if !sc.nonJSON && !json.Valid([]byte(ex.upstreamSaw)) {
		t.Fatalf("the upstream received invalid JSON:\n%.400s", ex.upstreamSaw)
	}
	if sc.unchanged && ex.upstreamSaw != sc.body {
		t.Fatalf("the body must reach the upstream byte for byte\nsent %.300q\ngot  %.300q", sc.body, ex.upstreamSaw)
	}
	for _, original := range sc.masked {
		if strings.Contains(ex.upstreamSaw, original) {
			t.Fatalf("%q reached the upstream unmasked", original)
		}
	}
	for _, kept := range sc.kept {
		if !strings.Contains(ex.upstreamSaw, kept) {
			t.Fatalf("%q must reach the upstream verbatim, upstream saw:\n%.500s", kept, ex.upstreamSaw)
		}
	}
	if sc.redact {
		if !strings.Contains(ex.upstreamSaw, "*****") {
			t.Fatalf("redaction marker missing: %.300s", ex.upstreamSaw)
		}
		return
	}
	if len(sc.masked) > 0 && !placeholderToken.MatchString(ex.upstreamSaw) {
		t.Fatalf("expected placeholders at the upstream: %.300s", ex.upstreamSaw)
	}
}

// checkClientSide asserts what the client received.
func checkClientSide(t *testing.T, sc e2eScenario, ex exchange, stream bool) {
	t.Helper()
	got := parseClientView(t, ex.clientRaw, stream)
	want := expectedClientView(ex.upstreamSaw, ex.metadata)
	if ok, why := got.equal(want); !ok {
		t.Fatalf("client view differs from the expected restored reply: %s\nraw client body:\n%.1500s", why, ex.clientRaw)
	}
	left := ex.clientRaw
	for _, allowed := range sc.allowedLeft {
		left = strings.ReplaceAll(left, allowed, "")
	}
	if loc := placeholderToken.FindString(left); loc != "" {
		t.Fatalf("a placeholder %q leaked to the client", loc)
	}
	if !sc.redact {
		var all strings.Builder
		for _, b := range got.blocks {
			all.WriteString(b.text)
		}
		joined := all.String()
		for _, original := range sc.masked {
			if len(sc.masked) <= 10 && !strings.Contains(joined, original) && !strings.Contains(joined, jsonEscaped(original)) {
				t.Fatalf("%q did not come back to the client", original)
			}
		}
	}
}

// containsStandalone reports whether v occurs in s outside a longer run of
// digits, which is where a number-shaped value is meant to be masked.
func containsStandalone(s, v string) bool {
	for from := 0; ; {
		i := strings.Index(s[from:], v)
		if i < 0 {
			return false
		}
		i += from
		if i == 0 || s[i-1] < '0' || s[i-1] > '9' {
			return true
		}
		from = i + 1
	}
}

func jsonEscaped(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// TestE2E_Matrix runs every scenario against every response shape, response
// tokenisation and network chunking.
func TestE2E_Matrix(t *testing.T) {
	up := newMockUpstream(t)
	for _, sc := range e2eScenarios(t) {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			g := newGateway(t, up, sc.chain)
			var firstUpstream string
			record := func(ex exchange) {
				if ex.gatewayError {
					return
				}
				if firstUpstream == "" {
					firstUpstream = ex.upstreamSaw
				} else if ex.upstreamSaw != firstUpstream {
					t.Fatalf("the masked request is not deterministic:\n%.300s\n%.300s", firstUpstream, ex.upstreamSaw)
				}
			}

			// Streamed answers: every tokenisation of the answer × every network chunking.
			for _, sp := range splitters {
				if sc.big && sp.name != "whole" && sp.name != "placeholder-tokens" {
					continue
				}
				for _, ck := range chunkers {
					if sc.big && (ck.name == "fixed-1" || ck.name == "fixed-3") {
						continue
					}
					name := "stream/" + sp.name + "/" + ck.name
					t.Run(name, func(t *testing.T) {
						up.configure(true, sp, 7)
						ex := g.do(sc.body, ck, "chunks", 11)
						checkRequestSide(t, sc, ex)
						record(ex)
						if !ex.gatewayError {
							checkClientSide(t, sc, ex, true)
						}
					})
				}
			}
			// Plain JSON answers, delivered in chunks and delivered whole.
			for _, ck := range chunkers {
				if sc.big && (ck.name == "fixed-1" || ck.name == "fixed-3") {
					continue
				}
				t.Run("json/"+ck.name, func(t *testing.T) {
					up.configure(false, splitters[0], 7)
					ex := g.do(sc.body, ck, "chunks", 13)
					checkRequestSide(t, sc, ex)
					record(ex)
					if !ex.gatewayError {
						checkClientSide(t, sc, ex, false)
					}
				})
			}
			t.Run("json/buffered", func(t *testing.T) {
				up.configure(false, splitters[0], 7)
				ex := g.do(sc.body, chunkers[0], "buffered", 17)
				checkRequestSide(t, sc, ex)
				record(ex)
				if !ex.gatewayError {
					checkClientSide(t, sc, ex, false)
				}
			})
		})
	}
}

// TestE2E_RepeatedRunsAreIdentical sends the same conversation many times, as an
// agent does turn after turn, and checks the upstream always sees the same bytes.
func TestE2E_RepeatedRunsAreIdentical(t *testing.T) {
	up := newMockUpstream(t)
	up.configure(true, splitters[0], 1)
	g := newGateway(t, up, []params{allBuiltins})
	body := `{"messages":[{"role":"user","content":"bob@example.org, (415) 555-0199, 123-45-6789, alice@example.com"}]}`
	seen := map[string]int{}
	for i := 0; i < 50; i++ {
		ex := g.do(body, chunkers[0], "chunks", int64(i))
		seen[ex.upstreamSaw]++
	}
	if len(seen) != 1 {
		t.Fatalf("expected one distinct upstream body over 50 runs, got %d", len(seen))
	}
}

// TestE2E_GrowingConversation replays an agent conversation turn by turn. Each
// turn must keep the masked bytes of the turns before it (prompt caching), and
// every turn's answer must come back restored.
func TestE2E_GrowingConversation(t *testing.T) {
	up := newMockUpstream(t)
	up.configure(true, splitters[3], 5)
	g := newGateway(t, up, []params{allBuiltins})

	var messages []string
	prevPrefix := ""
	for turn := 0; turn < 12; turn++ {
		messages = append(messages, jsonMsg(t, "user", fmt.Sprintf("turn %d: write to user%d@example.org or (415) 555-01%02d", turn, turn, turn)))
		body := `{"messages":[` + strings.Join(messages, ",") + `]}`
		ex := g.do(body, chunkers[4], "chunks", int64(turn))
		if ex.gatewayError {
			t.Fatalf("turn %d rejected: %s", turn, ex.errorBody)
		}
		if !strings.HasPrefix(ex.upstreamSaw, prevPrefix) {
			t.Fatalf("turn %d changed the masked prefix of earlier turns", turn)
		}
		prevPrefix = strings.TrimSuffix(ex.upstreamSaw, `"}]}`)
		checkClientSide(t, e2eScenario{}, ex, true)
		if strings.Contains(ex.upstreamSaw, fmt.Sprintf("user%d@example.org", turn)) {
			t.Fatalf("turn %d leaked its email", turn)
		}
	}
}

// TestE2E_ConcurrentRequests runs many requests at once through one set of
// policy instances; nothing may leak between them.
func TestE2E_ConcurrentRequests(t *testing.T) {
	const workers = 24
	// One set of policy instances serves every request, as in the gateway.
	p1 := mustGetPIIPolicy(t, emailWhole)
	p2 := mustGetPIIPolicy(t, phoneWhole)
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			up := newMockUpstream(t)
			up.configure(w%2 == 0, splitters[w%len(splitters)], int64(w))
			g := &gateway{t: t, up: up, chain: []*PIIMaskingRegexPolicy{p1, p2}}
			email := fmt.Sprintf("worker%d@example.org", w)
			body := `{"messages":[` + jsonMsg(t, "user", email+" (415) 555-0199") + `]}`
			for i := 0; i < 20; i++ {
				ex := g.do(body, chunkers[4], "chunks", int64(i))
				if strings.Contains(ex.upstreamSaw, email) {
					errs <- fmt.Errorf("worker %d leaked %s", w, email)
					return
				}
				if want := expectedClientView(ex.upstreamSaw, ex.metadata); !strings.Contains(ex.clientRaw, email) && len(want.blocks) > 0 {
					errs <- fmt.Errorf("worker %d: %s did not come back", w, email)
					return
				}
			}
			errs <- nil
		}(w)
	}
	for w := 0; w < workers; w++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// ─────────────────────────────── randomised round trips ───────────────────────────────

var (
	pools = struct{ emails, phones, ssns, words, awkward []string }{
		emails:  []string{"bob@example.org", "alice.smith@example.com", "carol+tag@sub.example.co.uk", "dave_1@example.io", "e.f@g.hk"},
		phones:  []string{"(415) 555-0199", "+1 650-555-0142", "212.555.0173", "303-555-0188"},
		ssns:    []string{"123-45-6789", "321-54-9876"},
		words:   []string{"hello", "the", "quick", "brown", "fox", "tool", "result", "id", "ref", "42", "ok"},
		awkward: []string{"\n", "\t", "\r", `"`, `\`, "<", ">", "&", "😀", "日本語", "é", " ", "[", "]", "[EMAIL_", "_", "1795104230191", "99123-45-6789"},
	}
)

func randomText(rng *rand.Rand, used *[]string) string {
	var parts []string
	n := 1 + rng.Intn(8)
	for i := 0; i < n; i++ {
		switch rng.Intn(6) {
		case 0:
			v := pools.emails[rng.Intn(len(pools.emails))]
			*used = append(*used, v)
			parts = append(parts, v)
		case 1:
			v := pools.phones[rng.Intn(len(pools.phones))]
			*used = append(*used, v)
			parts = append(parts, v)
		case 2:
			v := pools.ssns[rng.Intn(len(pools.ssns))]
			*used = append(*used, v)
			parts = append(parts, v)
		case 3:
			parts = append(parts, pools.awkward[rng.Intn(len(pools.awkward))])
		default:
			parts = append(parts, pools.words[rng.Intn(len(pools.words))])
		}
	}
	// Spaces keep digits and words from fusing into one another's matches.
	return strings.Join(parts, " ")
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

// TestE2E_RandomRoundTrip builds random Messages conversations full of awkward
// text, sends each through the policies in a random response shape, tokenisation
// and chunking, and checks the invariants that must always hold:
//   - the upstream never sees a PII value and always sees valid JSON,
//   - numbers and untouched strings arrive byte for byte,
//   - the client gets back every value, with no placeholder left.
//
// E2E_ITERATIONS (default 150) and E2E_SEED (default 1) control the run.
func TestE2E_RandomRoundTrip(t *testing.T) {
	iterations := envInt("E2E_ITERATIONS", 150)
	baseSeed := envInt("E2E_SEED", 1)
	up := newMockUpstream(t)
	g := newGateway(t, up, []params{emailWhole, phoneWhole, ssnWhole})

	for i := 0; i < iterations; i++ {
		seed := int64(baseSeed*100000 + i)
		rng := rand.New(rand.NewSource(seed))
		t.Run("seed-"+strconv.FormatInt(seed, 10), func(t *testing.T) {
			var used []string
			var msgs []string
			for m := 0; m < 1+rng.Intn(5); m++ {
				role := []string{"user", "assistant"}[rng.Intn(2)]
				if rng.Intn(3) == 0 {
					msgs = append(msgs, jsonMsg(t, role, []interface{}{map[string]interface{}{"type": "text", "text": randomText(rng, &used)}}))
				} else {
					msgs = append(msgs, jsonMsg(t, role, randomText(rng, &used)))
				}
			}
			body := `{"max":9007199254740991,"messages":[` + strings.Join(msgs, ",") + `],"tools":[{"description":"x ` + pools.emails[0] + `"}]}`
			used = append(used, pools.emails[0])

			stream := rng.Intn(3) != 0
			sp := splitters[rng.Intn(len(splitters))]
			ck := chunkers[rng.Intn(len(chunkers))]
			mode := "chunks"
			if !stream && rng.Intn(2) == 0 {
				mode = "buffered"
			}
			up.configure(stream, sp, seed)
			ex := g.do(body, ck, mode, seed)

			if ex.gatewayError {
				t.Fatalf("seed %d: unexpected gateway error %s\nbody %s", seed, ex.errorBody, body)
			}
			if !json.Valid([]byte(ex.upstreamSaw)) {
				t.Fatalf("seed %d: upstream saw invalid JSON\nbody %s\nsaw  %s", seed, body, ex.upstreamSaw)
			}
			for _, v := range used {
				if containsStandalone(ex.upstreamSaw, v) {
					t.Fatalf("seed %d: %q reached the upstream\nbody %s\nsaw  %s", seed, v, body, ex.upstreamSaw)
				}
			}
			if !strings.Contains(ex.upstreamSaw, `"max":9007199254740991`) {
				t.Fatalf("seed %d: a number was rewritten: %s", seed, ex.upstreamSaw)
			}
			for _, keep := range []string{"1795104230191", "99123-45-6789"} {
				if strings.Contains(body, keep) && strings.Count(ex.upstreamSaw, keep) != strings.Count(body, keep) {
					t.Fatalf("seed %d: %q was cut or masked inside a longer number", seed, keep)
				}
			}
			checkClientSide(t, e2eScenario{allowedLeft: []string{"[EMAIL_"}}, ex, stream)
			if stream {
				// Every value the user wrote in a scanned string must appear in the restored answer.
				var all strings.Builder
				for _, b := range parseClientView(t, ex.clientRaw, true).blocks {
					all.WriteString(b.text)
				}
				for _, v := range uniqueInOrder(used) {
					if !strings.Contains(all.String(), v) && !strings.Contains(all.String(), jsonEscaped(v)) {
						t.Fatalf("seed %d: %q did not come back\nclient %s", seed, v, ex.clientRaw)
					}
				}
			}
		})
	}
}
