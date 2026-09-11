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

package tamperevidentauditlog

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func reqCtx(headers map[string][]string, body []byte) *policy.RequestContext {
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			Metadata: map[string]interface{}{}, RequestID: "req-1",
			APIName: "demo-api", APIVersion: "v1.0",
		},
		Headers: policy.NewHeaders(headers),
		Body:    &policy.Body{Content: body, Present: true, EndOfStream: true},
		Method:  "POST", Path: "/demo/chat/completions",
	}
}

func respCtx(shared *policy.SharedContext, respBody []byte, status int) *policy.ResponseContext {
	return &policy.ResponseContext{
		SharedContext:  shared,
		ResponseBody:   &policy.Body{Content: respBody, Present: true, EndOfStream: true},
		ResponseStatus: status,
		RequestMethod:  "POST", RequestPath: "/demo/chat/completions",
	}
}

func mustPolicy(t *testing.T, extra map[string]interface{}) *TamperEvidentAuditLogPolicy {
	t.Helper()
	params := map[string]interface{}{}
	for k, v := range extra {
		params[k] = v
	}
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*TamperEvidentAuditLogPolicy)
}

func chatBody(t *testing.T, content string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"model": "gpt-4o", "messages": []map[string]string{{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func fakeJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return "Bearer " + header + "." + body + ".sig"
}

// runOneCall executes a full request+response pair through the same shared
// context, the way the gateway would, and returns the response action.
func runOneCall(t *testing.T, p *TamperEvidentAuditLogPolicy, reqHeaders map[string][]string, reqBody, respBody []byte, status int) policy.ResponseAction {
	t.Helper()
	rc := reqCtx(reqHeaders, reqBody)
	ra := p.OnRequestBody(context.Background(), rc, nil)
	if _, ok := ra.(policy.ImmediateResponse); ok {
		t.Fatalf("request unexpectedly short-circuited: %#v", ra)
	}
	return p.OnResponseBody(context.Background(), respCtx(rc.SharedContext, respBody, status), nil)
}

func asDownstream(t *testing.T, a policy.ResponseAction) policy.DownstreamResponseModifications {
	t.Helper()
	m, ok := a.(policy.DownstreamResponseModifications)
	if !ok {
		t.Fatalf("expected DownstreamResponseModifications, got %#v", a)
	}
	return m
}

// ─── GetPolicy validation ────────────────────────────────────────────────────

func TestGetPolicy_Defaults(t *testing.T) {
	p := mustPolicy(t, nil)
	if len(p.head) != 64 {
		t.Fatalf("expected a 64-char hex genesis head, got %q", p.head)
	}
	if p.cfg.anchorEveryN != 50 {
		t.Fatalf("unexpected default anchorEveryN: %d", p.cfg.anchorEveryN)
	}
}

func TestGetPolicy_InvalidGenesisHash(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"genesisHash": "not-hex"}); err == nil {
		t.Fatal("expected error for a non-hex genesisHash")
	}
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"genesisHash": "abcd"}); err == nil {
		t.Fatal("expected error for a too-short genesisHash")
	}
}

func TestGetPolicy_PinnedGenesisHashUsed(t *testing.T) {
	g := strings.Repeat("ab", 32)
	p := mustPolicy(t, map[string]interface{}{"genesisHash": g})
	if p.head != g {
		t.Fatalf("expected pinned genesis %q, got %q", g, p.head)
	}
}

func TestGetPolicy_InvalidSinkUrl(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"sinkUrl": "not-a-url"}); err == nil {
		t.Fatal("expected error for an invalid sinkUrl")
	}
}

func TestGetPolicy_NegativeAnchorEveryN(t *testing.T) {
	if _, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"anchorEveryN": -1.0}); err == nil {
		t.Fatal("expected error for a negative anchorEveryN")
	}
}

// ─── never blocks traffic ────────────────────────────────────────────────────

func TestNeverBlocksTraffic(t *testing.T) {
	p := mustPolicy(t, nil)
	ra := asDownstream(t, runOneCall(t, p, nil, chatBody(t, "hi"), []byte(`{"choices":[]}`), 200))
	if ra.Body != nil {
		t.Fatalf("audit log must never rewrite the response body, got %v", ra.Body)
	}
}

// ─── chain linkage ────────────────────────────────────────────────────────────

func TestChain_SeqIncrementsAndLinksAcrossCalls(t *testing.T) {
	p := mustPolicy(t, nil)
	r1 := asDownstream(t, runOneCall(t, p, nil, chatBody(t, "one"), []byte(`{"a":1}`), 200))
	r2 := asDownstream(t, runOneCall(t, p, nil, chatBody(t, "two"), []byte(`{"a":2}`), 200))

	if r1.HeadersToSet["x-audit-seq"] != "1" || r2.HeadersToSet["x-audit-seq"] != "2" {
		t.Fatalf("expected seq 1 then 2, got %q then %q", r1.HeadersToSet["x-audit-seq"], r2.HeadersToSet["x-audit-seq"])
	}
	if r2.HeadersToSet["x-audit-prev-hash"] != r1.HeadersToSet["x-audit-hash"] {
		t.Fatalf("record 2's prevHash must equal record 1's hash: got prev=%q want=%q",
			r2.HeadersToSet["x-audit-prev-hash"], r1.HeadersToSet["x-audit-hash"])
	}
	if r1.HeadersToSet["x-audit-hash"] == r2.HeadersToSet["x-audit-hash"] {
		t.Fatal("distinct records must produce distinct hashes")
	}
}

func TestChain_RequestAndResponseHashesAreVerifiable(t *testing.T) {
	p := mustPolicy(t, nil)
	reqBody := chatBody(t, "verify me")
	respBody := []byte(`{"choices":[{"message":{"content":"ok"}}]}`)
	r := asDownstream(t, runOneCall(t, p, nil, reqBody, respBody, 200))

	wantReqHash := sha256Hex(reqBody)
	wantRespHash := sha256Hex(respBody)
	if r.HeadersToSet["x-audit-request-hash"] != wantReqHash {
		t.Fatalf("request hash mismatch: got %s want %s", r.HeadersToSet["x-audit-request-hash"], wantReqHash)
	}
	if r.HeadersToSet["x-audit-response-hash"] != wantRespHash {
		t.Fatalf("response hash mismatch: got %s want %s", r.HeadersToSet["x-audit-response-hash"], wantRespHash)
	}
}

func TestChain_DifferentGenesisProducesDifferentFirstHash(t *testing.T) {
	g1 := strings.Repeat("11", 32)
	g2 := strings.Repeat("22", 32)
	p1 := mustPolicy(t, map[string]interface{}{"genesisHash": g1})
	p2 := mustPolicy(t, map[string]interface{}{"genesisHash": g2})
	r1 := asDownstream(t, runOneCall(t, p1, nil, chatBody(t, "x"), []byte(`{}`), 200))
	r2 := asDownstream(t, runOneCall(t, p2, nil, chatBody(t, "x"), []byte(`{}`), 200))
	if r1.HeadersToSet["x-audit-hash"] == r2.HeadersToSet["x-audit-hash"] {
		t.Fatal("identical request/response with different genesis hashes must produce different record hashes")
	}
}

func TestChain_ResponseWithoutRequestPhase_NoOp(t *testing.T) {
	p := mustPolicy(t, nil)
	// A response phase invoked with no prior OnRequestBody call (e.g. a
	// request that was short-circuited before reaching this policy)
	// must not panic and must not extend the chain.
	rc := respCtx(&policy.SharedContext{Metadata: map[string]interface{}{}}, []byte(`{}`), 200)
	a := p.OnResponseBody(context.Background(), rc, nil)
	m := asDownstream(t, a)
	if len(m.HeadersToSet) != 0 {
		t.Fatalf("expected no audit headers when there was no request-phase record, got %#v", m.HeadersToSet)
	}
	p.mu.Lock()
	seq := p.seq
	p.mu.Unlock()
	if seq != 0 {
		t.Fatalf("chain must not advance without a request-phase record, seq=%d", seq)
	}
}

// ─── chain-status query ──────────────────────────────────────────────────────

func TestStatusQuery_DoesNotAdvanceChain(t *testing.T) {
	p := mustPolicy(t, nil)
	runOneCall(t, p, nil, chatBody(t, "real traffic"), []byte(`{}`), 200)

	statusBody, _ := json.Marshal(map[string]interface{}{"auditStatus": true})
	rc := reqCtx(nil, statusBody)
	ra := p.OnRequestBody(context.Background(), rc, nil)
	ir, ok := ra.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected a status query to short-circuit, got %#v", ra)
	}
	if ir.StatusCode != 200 {
		t.Fatalf("expected 200 for a status query, got %d", ir.StatusCode)
	}
	var parsed map[string]interface{}
	json.Unmarshal(ir.Body, &parsed)
	msg := parsed["message"].(map[string]interface{})
	if int(msg["seq"].(float64)) != 1 {
		t.Fatalf("status query should report the current seq without advancing it, got %v", msg["seq"])
	}

	p.mu.Lock()
	seq := p.seq
	p.mu.Unlock()
	if seq != 1 {
		t.Fatalf("a status query must not itself advance the chain, seq=%d", seq)
	}
}

// ─── principal recording ─────────────────────────────────────────────────────

func TestPrincipal_SubOnlyByDefault(t *testing.T) {
	p := mustPolicy(t, nil)
	auth := fakeJWT(t, map[string]interface{}{"sub": "alice@example.com", "role": "admin"})
	rc := reqCtx(map[string][]string{"authorization": {auth}}, chatBody(t, "hi"))
	p.OnRequestBody(context.Background(), rc, nil)
	principal := rc.Metadata[mdPrincipal]
	if principal != "alice@example.com" {
		t.Fatalf("expected sub-only principal, got %#v", principal)
	}
}

func TestPrincipal_FullClaimsWhenConfigured(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"includeClaims": true})
	auth := fakeJWT(t, map[string]interface{}{"sub": "alice@example.com", "role": "admin"})
	rc := reqCtx(map[string][]string{"authorization": {auth}}, chatBody(t, "hi"))
	p.OnRequestBody(context.Background(), rc, nil)
	claims, ok := rc.Metadata[mdPrincipal].(map[string]interface{})
	if !ok || claims["role"] != "admin" {
		t.Fatalf("expected full claims map with role, got %#v", rc.Metadata[mdPrincipal])
	}
}

func TestPrincipal_MalformedAuthHeaderIgnored(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx(map[string][]string{"authorization": {"Bearer not-a-jwt"}}, chatBody(t, "hi"))
	a := p.OnRequestBody(context.Background(), rc, nil)
	if _, ok := a.(policy.ImmediateResponse); ok {
		t.Fatal("a malformed Authorization header must not block the request")
	}
	if _, ok := rc.Metadata[mdPrincipal]; ok {
		t.Fatal("a malformed JWT should not produce a principal")
	}
}

// ─── tool call recording ─────────────────────────────────────────────────────

func toolBody(t *testing.T, name string, args map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call",
		"params": map[string]interface{}{"name": name, "arguments": args},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestToolCall_ArgsHashedNotEchoedByDefault(t *testing.T) {
	p := mustPolicy(t, nil)
	rc := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"amount": 500}))
	p.OnRequestBody(context.Background(), rc, nil)
	if _, ok := rc.Metadata[mdToolArgs]; ok {
		t.Fatal("raw tool arguments should not be recorded unless includeToolArguments is set")
	}
	if rc.Metadata[mdToolName] != "issue_refund" {
		t.Fatalf("expected tool name recorded, got %#v", rc.Metadata[mdToolName])
	}
	if rc.Metadata[mdToolArgHash] == "" {
		t.Fatal("expected a non-empty tool argument hash")
	}
}

func TestToolCall_ArgsIncludedWhenConfigured(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"includeToolArguments": true})
	rc := reqCtx(nil, toolBody(t, "issue_refund", map[string]interface{}{"amount": 500}))
	p.OnRequestBody(context.Background(), rc, nil)
	args, ok := rc.Metadata[mdToolArgs].(map[string]interface{})
	if !ok || args["amount"] != float64(500) {
		t.Fatalf("expected raw arguments to be recorded, got %#v", rc.Metadata[mdToolArgs])
	}
}

// ─── anchoring ────────────────────────────────────────────────────────────────

func TestAnchor_MarksEveryNthRecord(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"anchorEveryN": 3.0})
	var seenAnalytics []map[string]any
	for i := 0; i < 6; i++ {
		a := runOneCall(t, p, nil, chatBody(t, "x"), []byte(`{}`), 200)
		m := asDownstream(t, a)
		seenAnalytics = append(seenAnalytics, m.AnalyticsMetadata)
	}
	for i, am := range seenAnalytics {
		rec := am["auditRecord"].(map[string]interface{})
		wantAnchor := (i+1)%3 == 0
		if rec["isAnchor"] != wantAnchor {
			t.Fatalf("record %d: isAnchor=%v, want %v", i+1, rec["isAnchor"], wantAnchor)
		}
	}
}

func TestAnchor_ZeroDisablesAnchoring(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"anchorEveryN": 0.0})
	a := runOneCall(t, p, nil, chatBody(t, "x"), []byte(`{}`), 200)
	m := asDownstream(t, a)
	rec := m.AnalyticsMetadata["auditRecord"].(map[string]interface{})
	if rec["isAnchor"] != false {
		t.Fatalf("expected isAnchor=false when anchorEveryN=0, got %v", rec["isAnchor"])
	}
}

// ─── sink delivery (best-effort) ─────────────────────────────────────────────

func TestSink_PostsRecordAndDoesNotBlockOnFailure(t *testing.T) {
	var received int32
	var gotSeq float64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		gotSeq, _ = body["seq"].(float64)
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := mustPolicy(t, map[string]interface{}{"sinkUrl": srv.URL})
	runOneCall(t, p, nil, chatBody(t, "x"), []byte(`{}`), 200)

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&received) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&received) == 0 {
		t.Fatal("expected the sink to have been called")
	}
	if gotSeq != 1 {
		t.Fatalf("expected seq 1 delivered to the sink, got %v", gotSeq)
	}
}

func TestSink_UnreachableStillReturnsHeaders(t *testing.T) {
	p := mustPolicy(t, map[string]interface{}{"sinkUrl": "http://127.0.0.1:1/unreachable"})
	a := runOneCall(t, p, nil, chatBody(t, "x"), []byte(`{}`), 200)
	m := asDownstream(t, a)
	if m.HeadersToSet["x-audit-seq"] != "1" {
		t.Fatalf("an unreachable sink must not block audit headers from being attached, got %#v", m.HeadersToSet)
	}
}

// ─── concurrency ─────────────────────────────────────────────────────────────

func TestConcurrentCalls_ChainStaysConsistent(t *testing.T) {
	p := mustPolicy(t, nil)
	const n = 50
	var wg sync.WaitGroup
	results := make(chan policy.DownstreamResponseModifications, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := runOneCall(t, p, nil, chatBody(t, "x"), []byte(`{}`), 200)
			results <- asDownstream(t, a)
		}()
	}
	wg.Wait()
	close(results)

	seqs := map[string]bool{}
	for r := range results {
		seq := r.HeadersToSet["x-audit-seq"]
		if seqs[seq] {
			t.Fatalf("duplicate seq %s assigned under concurrency", seq)
		}
		seqs[seq] = true
	}
	if len(seqs) != n {
		t.Fatalf("expected %d unique sequence numbers, got %d", n, len(seqs))
	}
}

// ─── malformed body ───────────────────────────────────────────────────────────

func TestNonJSONBody_StillRecorded(t *testing.T) {
	p := mustPolicy(t, nil)
	a := runOneCall(t, p, nil, []byte("not json"), []byte("also not json"), 200)
	m := asDownstream(t, a)
	if m.HeadersToSet["x-audit-seq"] != "1" {
		t.Fatalf("a non-JSON body should still be hashed and recorded, got %#v", m.HeadersToSet)
	}
}

// ─── test helper ──────────────────────────────────────────────────────────────

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
