// Command mock-echo-llm is a minimal OpenAI-chat-completions-shaped AND
// MCP-tools/call-shaped backend for the agentic-loop-budget-governor e2e
// suite. The governor's behavior is entirely about what happens BEFORE the
// request reaches here (block vs forward, and what headers annotate adds to
// the upstream request), so this backend just echoes a canned reply and
// exposes a debug endpoint proving what actually arrived.
//
//	GET /debug/last-request -> {"body": "...", "headers": {...}, "calls": N}
//	                            so a test can assert the request that reached
//	                            the backend (annotate's x-loop-budget-* headers
//	                            are set on the UPSTREAM request, never visible
//	                            on the client response) and how many times
//	                            this backend was actually invoked.
//	POST /debug/reset       -> clears the captured request and call counter.
//	GET /healthz            -> readiness probe.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
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
)

func main() {
	addr := envOr("ADDR", ":9758")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /debug/last-request", handleLastRequest)
	mux.HandleFunc("POST /debug/reset", handleReset)
	mux.HandleFunc("/", handleRequest)
	log.Printf("mock-echo-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))

	hdr := map[string]string{}
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-loop-budget") || strings.EqualFold(k, "content-type") {
			hdr[strings.ToLower(k)] = r.Header.Get(k)
		}
	}

	mu.Lock()
	callCount++
	lastBody = string(body)
	lastHeaders = hdr
	mu.Unlock()

	var probe struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &probe)

	w.Header().Set("Content-Type", "application/json")
	if probe.Method == "tools/call" {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"content": []map[string]string{{"type": "text", "text": "tool ok"}},
			},
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id": "mock-chatcmpl-1", "object": "chat.completion", "model": "mock-model",
		"created": time.Now().Unix(),
		"choices": []map[string]interface{}{{
			"index": 0, "finish_reason": "stop",
			"message": map[string]string{"role": "assistant", "content": "ok"},
		}},
		"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
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
	mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
