// Command mock-echo-llm is a minimal MCP-tools/call-shaped backend for the
// hitl-approval-gate e2e suite. It only matters whether it was reached at
// all - the gate's whole job is deciding whether a high-risk tool call ever
// gets this far - so it just echoes a canned tool result and exposes a
// debug endpoint proving what (and how many times) it was called.
//
//	GET /debug/last-request -> {"body": "...", "headers": {...}, "calls": N}
//	POST /debug/reset       -> clears the captured request and call counter.
//	GET /healthz            -> readiness probe.
//
// It also doubles as the approval-notification sink (the policy's
// `notifyUrl`): POST /notify captures the JSON payload, and
// GET /debug/last-notify returns the most recently captured one.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

var (
	mu          sync.Mutex
	callCount   int
	lastBody    string
	lastHeaders map[string]string
	lastNotify  json.RawMessage
)

func main() {
	addr := envOr("ADDR", ":9759")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /debug/last-request", handleLastRequest)
	mux.HandleFunc("POST /debug/reset", handleReset)
	mux.HandleFunc("POST /notify", handleNotify)
	mux.HandleFunc("GET /debug/last-notify", handleLastNotify)
	mux.HandleFunc("/", handleRequest)
	log.Printf("mock-echo-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleNotify(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	mu.Lock()
	lastNotify = json.RawMessage(body)
	mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func handleLastNotify(w http.ResponseWriter, _ *http.Request) {
	mu.Lock()
	n := lastNotify
	mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if n == nil {
		w.Write([]byte(`{}`))
		return
	}
	w.Write(n)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))

	hdr := map[string]string{}
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-hitl") || strings.EqualFold(k, "content-type") {
			hdr[strings.ToLower(k)] = r.Header.Get(k)
		}
	}

	mu.Lock()
	callCount++
	lastBody = string(body)
	lastHeaders = hdr
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]interface{}{
			"content": []map[string]string{{"type": "text", "text": "tool executed"}},
		},
	})
}

func handleLastRequest(w http.ResponseWriter, _ *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"body": lastBody, "headers": lastHeaders, "calls": callCount})
}

func handleReset(w http.ResponseWriter, _ *http.Request) {
	mu.Lock()
	callCount = 0
	lastBody = ""
	lastHeaders = map[string]string{}
	lastNotify = nil
	mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
