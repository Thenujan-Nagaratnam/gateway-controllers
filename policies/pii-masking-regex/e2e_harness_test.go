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

// End-to-end harness.
//
// A request goes through a chain of real policy instances exactly as the gateway
// kernel drives them, over real HTTP to a mock Anthropic Messages upstream. The
// upstream records what it receives and answers using the placeholders it saw,
// as a model would. The answer comes back in arbitrary network chunks through
// the same policies, and what the client would receive is parsed and compared
// with what the upstream should have been told.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

var placeholderToken = regexp.MustCompile(`\[[A-Z_]+_[0-9a-f]{8}\]`)

// ─────────────────────────────── mock upstream ───────────────────────────────

// replySegment is one block of the model's answer.
type replySegment struct {
	typ  string // thinking | text | tool
	text string // for tool, the JSON text of the arguments
}

// buildReply is what the mock model says about the values it was given. It is a
// pure function of the values, so the test can compute the expected client view.
func buildReply(values []string) []replySegment {
	if len(values) == 0 {
		return []replySegment{{typ: "text", text: "nothing to report"}}
	}
	list := strings.Join(values, ", ")
	args, _ := json.Marshal(map[string]interface{}{"values": values})
	return []replySegment{
		{typ: "thinking", text: "I should look up " + list + " now."},
		{typ: "text", text: "Sent to " + list + "."},
		{typ: "text", text: "Also " + values[len(values)-1]},
		{typ: "tool", text: string(args)},
	}
}

func uniqueInOrder(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// splitter cuts a segment's text into the pieces a model would stream.
type splitter struct {
	name string
	fn   func(rng *rand.Rand, text string) []string
}

var splitters = []splitter{
	{"whole", func(_ *rand.Rand, s string) []string { return []string{s} }},
	{"per-rune", func(_ *rand.Rand, s string) []string {
		var out []string
		for _, r := range s {
			out = append(out, string(r))
		}
		return out
	}},
	{"random", func(rng *rand.Rand, s string) []string {
		runes := []rune(s)
		var out []string
		for len(runes) > 0 {
			n := 1 + rng.Intn(6)
			if n > len(runes) {
				n = len(runes)
			}
			out = append(out, string(runes[:n]))
			runes = runes[n:]
		}
		return out
	}},
	{"placeholder-tokens", func(_ *rand.Rand, s string) []string {
		var out []string
		last := 0
		for _, loc := range placeholderToken.FindAllStringIndex(s, -1) {
			if loc[0] > last {
				out = append(out, s[last:loc[0]])
			}
			ph := s[loc[0]:loc[1]]
			us := strings.LastIndex(ph, "_")
			out = append(out, "[", ph[1:us], "_", ph[us+1:us+5], ph[us+5:len(ph)-1], "]")
			last = loc[1]
		}
		if last < len(s) {
			out = append(out, s[last:])
		}
		if len(out) == 0 {
			out = []string{s}
		}
		return out
	}},
}

type mockUpstream struct {
	srv *httptest.Server

	mu     sync.Mutex
	seen   []string
	stream bool
	split  splitter
	rng    *rand.Rand
}

func newMockUpstream(t *testing.T) *mockUpstream {
	t.Helper()
	u := &mockUpstream{split: splitters[0], rng: rand.New(rand.NewSource(1))}
	u.srv = httptest.NewServer(http.HandlerFunc(u.handle))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *mockUpstream) configure(stream bool, split splitter, seed int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stream, u.split, u.rng = stream, split, rand.New(rand.NewSource(seed))
}

func (u *mockUpstream) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.seen = nil
}

func (u *mockUpstream) requests() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.seen...)
}

func sseEv(name string, payload map[string]interface{}) string {
	b, _ := json.Marshal(payload)
	return "event: " + name + "\ndata: " + string(b) + "\n\n"
}

func (u *mockUpstream) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.seen = append(u.seen, string(body))
	stream, split, rng := u.stream, u.split, u.rng
	u.mu.Unlock()

	segs := buildReply(uniqueInOrder(placeholderToken.FindAllString(string(body), -1)))

	if !stream {
		blocks := make([]interface{}, 0, len(segs))
		for _, s := range segs {
			switch s.typ {
			case "thinking":
				blocks = append(blocks, map[string]interface{}{"type": "thinking", "thinking": s.text, "signature": "c2ln"})
			case "text":
				blocks = append(blocks, map[string]interface{}{"type": "text", "text": s.text})
			case "tool":
				blocks = append(blocks, map[string]interface{}{"type": "tool_use", "id": "tu_1", "name": "lookup", "input": json.RawMessage(s.text)})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "msg_1", "type": "message", "role": "assistant", "content": blocks})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	var sb strings.Builder
	sb.WriteString(sseEv("message_start", map[string]interface{}{"type": "message_start", "message": map[string]interface{}{"id": "msg_1", "role": "assistant"}}))
	for i, s := range segs {
		start := map[string]interface{}{"type": "text", "text": ""}
		deltaType, key := "text_delta", "text"
		switch s.typ {
		case "thinking":
			start, deltaType, key = map[string]interface{}{"type": "thinking", "thinking": ""}, "thinking_delta", "thinking"
		case "tool":
			start, deltaType, key = map[string]interface{}{"type": "tool_use", "id": "tu_1", "name": "lookup", "input": map[string]interface{}{}}, "input_json_delta", "partial_json"
		}
		sb.WriteString(sseEv("content_block_start", map[string]interface{}{"type": "content_block_start", "index": i, "content_block": start}))
		for _, piece := range split.fn(rng, s.text) {
			sb.WriteString(sseEv("content_block_delta", map[string]interface{}{"type": "content_block_delta", "index": i, "delta": map[string]interface{}{"type": deltaType, key: piece}}))
		}
		if s.typ == "thinking" {
			sb.WriteString(sseEv("content_block_delta", map[string]interface{}{"type": "content_block_delta", "index": i, "delta": map[string]interface{}{"type": "signature_delta", "signature": "c2ln"}}))
		}
		sb.WriteString(sseEv("content_block_stop", map[string]interface{}{"type": "content_block_stop", "index": i}))
	}
	sb.WriteString(sseEv("message_delta", map[string]interface{}{"type": "message_delta", "delta": map[string]interface{}{"stop_reason": "end_turn"}}))
	sb.WriteString(sseEv("message_stop", map[string]interface{}{"type": "message_stop"}))
	_, _ = io.WriteString(w, sb.String())
}

// ─────────────────────────────── gateway simulation ───────────────────────────────

type chunker struct {
	name string
	fn   func(rng *rand.Rand, b []byte) [][]byte
}

func fixedChunker(n int) chunker {
	return chunker{fmt.Sprintf("fixed-%d", n), func(_ *rand.Rand, b []byte) [][]byte {
		var out [][]byte
		for len(b) > n {
			out = append(out, b[:n])
			b = b[n:]
		}
		return append(out, b)
	}}
}

var chunkers = []chunker{
	{"whole", func(_ *rand.Rand, b []byte) [][]byte { return [][]byte{b} }},
	fixedChunker(1),
	fixedChunker(3),
	fixedChunker(17),
	{"random", func(rng *rand.Rand, b []byte) [][]byte {
		var out [][]byte
		for len(b) > 0 {
			n := 1 + rng.Intn(40)
			if n > len(b) {
				n = len(b)
			}
			out = append(out, b[:n])
			b = b[n:]
		}
		return out
	}},
}

type exchange struct {
	sent          string
	upstreamSaw   string
	upstreamCalls int
	gatewayError  bool
	errorBody     string
	clientRaw     string
	metadata      map[string]interface{}
}

type gateway struct {
	t     *testing.T
	chain []*PIIMaskingRegexPolicy
	up    *mockUpstream
}

func newGateway(t *testing.T, up *mockUpstream, chain []map[string]interface{}) *gateway {
	t.Helper()
	g := &gateway{t: t, up: up}
	for _, params := range chain {
		g.chain = append(g.chain, mustGetPIIPolicy(t, params))
	}
	return g
}

// do sends body through the request chain, to the upstream, and back through the
// response chain. mode is "chunks" (the response is delivered in network chunks)
// or "buffered" (the whole response body is handed over at once).
func (g *gateway) do(body string, ck chunker, mode string, seed int64) exchange {
	g.t.Helper()
	g.up.reset()
	ex := exchange{sent: body}

	reqCtx := piiRequestContext(body)
	current := body
	for _, p := range g.chain {
		reqCtx.Body.Content = []byte(current)
		reqCtx.Body.Present = current != ""
		switch a := p.OnRequestBody(context.Background(), reqCtx, nil).(type) {
		case policy.UpstreamRequestModifications:
			if a.Body != nil {
				current = string(a.Body)
			}
		case policy.ImmediateResponse:
			ex.gatewayError, ex.errorBody = true, string(a.Body)
			ex.metadata = reqCtx.Metadata
			return ex
		default:
			g.t.Fatalf("unexpected request action %T", a)
		}
	}
	ex.metadata = reqCtx.Metadata

	resp, err := http.Post(g.up.srv.URL, "application/json", strings.NewReader(current))
	if err != nil {
		g.t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	reqs := g.up.requests()
	ex.upstreamCalls = len(reqs)
	if len(reqs) > 0 {
		ex.upstreamSaw = reqs[0]
	}

	shared := &policy.SharedContext{RequestID: "e2e", Metadata: reqCtx.Metadata}
	switch mode {
	case "buffered":
		out := raw
		for i := len(g.chain) - 1; i >= 0; i-- {
			rc := &policy.ResponseContext{SharedContext: shared, ResponseBody: &policy.Body{Content: out, Present: true}}
			if mods, ok := g.chain[i].OnResponseBody(context.Background(), rc, nil).(policy.DownstreamResponseModifications); ok && mods.Body != nil {
				out = mods.Body
			}
		}
		ex.clientRaw = string(out)
	default:
		ex.clientRaw = g.driveChunks(shared, ck.fn(rand.New(rand.NewSource(seed)), raw))
	}
	return ex
}

// driveChunks plays the kernel: chunks are accumulated while any policy asks for
// more data, then each flush goes through the policies in response order.
func (g *gateway) driveChunks(shared *policy.SharedContext, chunks [][]byte) string {
	var out strings.Builder
	var acc []byte
	flushes := 0
	for i, c := range chunks {
		eos := i == len(chunks)-1
		acc = append(acc, c...)
		if !eos {
			more := false
			for _, p := range g.chain {
				if p.NeedsMoreResponseData(acc) {
					more = true
					break
				}
			}
			if more {
				continue
			}
		}
		current := acc
		for j := len(g.chain) - 1; j >= 0; j-- {
			rc := &policy.ResponseStreamContext{SharedContext: shared}
			sb := &policy.StreamBody{Chunk: current, EndOfStream: eos, Index: uint64(flushes)}
			fwd, ok := g.chain[j].OnResponseBodyChunk(context.Background(), rc, sb, nil).(policy.ForwardResponseChunk)
			if !ok {
				g.t.Fatalf("expected ForwardResponseChunk")
			}
			if fwd.Body != nil {
				current = fwd.Body
			}
		}
		flushes++
		out.Write(current)
		acc = nil
	}
	return out.String()
}

// ─────────────────────────────── client view ───────────────────────────────

// clientView is what the client assembles from the answer, block by block.
type clientView struct {
	blocks []replySegment
}

func parseClientView(t *testing.T, raw string, stream bool) clientView {
	t.Helper()
	var v clientView
	if stream {
		blocks := assembleBlocks(t, raw)
		for i := 0; i < len(blocks); i++ {
			b, ok := blocks[i]
			if !ok {
				t.Fatalf("content block %d is missing from the stream:\n%s", i, raw)
			}
			switch {
			case b.args != "":
				v.blocks = append(v.blocks, replySegment{"tool", b.args})
			case b.thinking != "":
				v.blocks = append(v.blocks, replySegment{"thinking", b.thinking})
			default:
				v.blocks = append(v.blocks, replySegment{"text", b.text})
			}
		}
		return v
	}
	var doc struct {
		Content []struct {
			Type     string          `json:"type"`
			Text     string          `json:"text"`
			Thinking string          `json:"thinking"`
			Input    json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("client body is not valid JSON: %v\n%s", err, raw)
	}
	for _, b := range doc.Content {
		switch b.Type {
		case "thinking":
			v.blocks = append(v.blocks, replySegment{"thinking", b.Thinking})
		case "tool_use":
			v.blocks = append(v.blocks, replySegment{"tool", string(b.Input)})
		default:
			v.blocks = append(v.blocks, replySegment{"text", b.Text})
		}
	}
	return v
}

// expectedClientView is the answer the client should see: the model's reply with
// every placeholder it was shown replaced by the original value.
func expectedClientView(upstreamSaw string, metadata map[string]interface{}) clientView {
	mapping, _ := metadata[MetadataKeyPIIEntities].(map[string]string)
	inverse := map[string]string{}
	for original, ph := range mapping {
		inverse[ph] = original
	}
	var values []string
	for _, ph := range uniqueInOrder(placeholderToken.FindAllString(upstreamSaw, -1)) {
		if original, ok := inverse[ph]; ok {
			values = append(values, original)
		} else {
			values = append(values, ph)
		}
	}
	return clientView{blocks: buildReply(values)}
}

func (a clientView) equal(b clientView) (bool, string) {
	if len(a.blocks) != len(b.blocks) {
		return false, fmt.Sprintf("block count %d != %d", len(a.blocks), len(b.blocks))
	}
	for i := range a.blocks {
		x, y := a.blocks[i], b.blocks[i]
		if x.typ != y.typ {
			return false, fmt.Sprintf("block %d type %s != %s", i, x.typ, y.typ)
		}
		if x.typ == "tool" {
			var xa, ya interface{}
			if json.Unmarshal([]byte(x.text), &xa) != nil || json.Unmarshal([]byte(y.text), &ya) != nil {
				return false, fmt.Sprintf("block %d arguments are not valid JSON: %q vs %q", i, x.text, y.text)
			}
			xb, _ := json.Marshal(xa)
			yb, _ := json.Marshal(ya)
			if string(xb) != string(yb) {
				return false, fmt.Sprintf("block %d arguments %s != %s", i, xb, yb)
			}
			continue
		}
		if x.text != y.text {
			return false, fmt.Sprintf("block %d text %q != %q", i, x.text, y.text)
		}
	}
	return true, ""
}
