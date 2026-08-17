// Command mock-model-backend is a minimal stand-in for an LLM backend, used
// to manually verify that the model-failover gateway policy actually rewrites
// the outbound request body's "model" field per attempt, and routes each
// attempt to the correct backend cluster — not just that the gateway returns
// a clean 2xx to the caller.
//
// Two instances of this same binary run side-by-side on different ports
// (ADDR), one per model-failover target, mirroring
// dev-policies/oauth2-generator/e2e/mocks/mock-ai-backend's exact
// structure/conventions.
//
// Every request (any method/path) returns an OpenAI chat-completions-shaped
// response so the gateway's "openai" LLM provider template can extract
// prompt/completion/total tokens without erroring. The assistant message
// content embeds the "model" field this server actually received in the
// request body, so a plain curl to /chat/completions through the gateway is
// enough to see which target and which rewritten model name actually landed
// here.
//
// GET /debug/last-request returns the full headers/body of the most recent
// request, for scripted assertions (e.g. `curl .../debug/last-request | jq
// -r .body | jq -r .model`).
//
// POST /debug/force-status?code=500 makes the NEXT request only (any
// method/path) return that status instead of the normal 200 - used to
// simulate this target failing, so a caller can observe the gateway's
// model-failover retry landing on a different target/model.
//
// POST /debug/reset clears the forced status and the last-request record,
// for a clean slate between test flows.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

var (
	mu           sync.Mutex
	lastRequest  lastRequestRecord
	forcedStatus int // 0 = normal 200 behavior; otherwise, the status to return once, then reset to 0
)

type lastRequestRecord struct {
	Time    time.Time           `json:"time"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("request: method=%s path=%s remote=%s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func main() {
	addr := envOr("ADDR", ":9711")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/last-request", handleLastRequest)
	mux.HandleFunc("POST /debug/force-status", handleForceStatus)
	mux.HandleFunc("POST /debug/reset", handleReset)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", handleAny) // catch-all: acts as the LLM backend for any path

	log.Printf("mock-model-backend listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, loggingMiddleware(mux)))
}

func handleAny(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	record := lastRequestRecord{
		Time:    time.Now().UTC(),
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: map[string][]string(r.Header),
		Body:    string(body),
	}

	mu.Lock()
	lastRequest = record
	status := forcedStatus
	forcedStatus = 0 // consumed - only the request that triggered this one is forced
	mu.Unlock()

	if status != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "forced_status_for_test"})
		return
	}

	var reqBody map[string]interface{}
	_ = json.Unmarshal(body, &reqBody)
	model, _ := reqBody["model"].(string)

	resp := map[string]interface{}{
		"id":      "mock-chatcmpl-1",
		"object":  "chat.completion",
		"model":   model,
		"created": time.Now().Unix(),
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": "received model: \"" + model + "\"",
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     1,
			"completion_tokens": 1,
			"total_tokens":      2,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func handleLastRequest(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(lastRequest)
}

func handleForceStatus(w http.ResponseWriter, r *http.Request) {
	code, err := strconv.Atoi(r.URL.Query().Get("code"))
	if err != nil || code < 100 || code > 599 {
		http.Error(w, "code query parameter must be a valid HTTP status code", http.StatusBadRequest)
		return
	}
	mu.Lock()
	forcedStatus = code
	mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	forcedStatus = 0
	lastRequest = lastRequestRecord{}
	mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
