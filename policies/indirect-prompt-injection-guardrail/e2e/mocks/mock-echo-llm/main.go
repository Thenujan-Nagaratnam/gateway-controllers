// Command mock-echo-llm is a minimal OpenAI-chat-completions-shaped backend for
// the indirect-prompt-injection-guardrail end-to-end suite.
//
// It echoes the last message's content back as the assistant reply. Two debug
// endpoints let the collection prove what the policy did:
//
//   GET /debug/last-request  -> {"body": "<raw request body>", "headers": {...}}
//                               so a test can assert the request that actually
//                               reached the backend (sanitize rewrote it, or
//                               annotate added x-indirect-injection-* headers).
//   POST /debug/reset        -> clears the captured request.
//   GET /healthz             -> readiness probe.
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

var (
	mu          sync.Mutex
	lastBody    string
	lastHeaders map[string]string
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type chatMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

func main() {
	addr := envOr("ADDR", ":9751")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/last-request", handleLastRequest)
	mux.HandleFunc("POST /debug/reset", handleReset)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", handleChatCompletions)

	log.Printf("mock-echo-llm listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	hdr := map[string]string{}
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-indirect-injection") || strings.EqualFold(k, "content-type") {
			hdr[strings.ToLower(k)] = r.Header.Get(k)
		}
	}

	mu.Lock()
	lastBody = string(body)
	lastHeaders = hdr
	mu.Unlock()

	var req chatRequest
	reply := ""
	if err := json.Unmarshal(body, &req); err == nil && len(req.Messages) > 0 {
		last := req.Messages[len(req.Messages)-1].Content
		var s string
		if json.Unmarshal(last, &s) == nil {
			reply = s
		} else {
			reply = string(last)
		}
	}

	resp := map[string]interface{}{
		"id":      "mock-chatcmpl-1",
		"object":  "chat.completion",
		"model":   "mock-model",
		"created": time.Now().Unix(),
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"message":       map[string]string{"role": "assistant", "content": reply},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleLastRequest(w http.ResponseWriter, _ *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"body": lastBody, "headers": lastHeaders})
}

func handleReset(w http.ResponseWriter, _ *http.Request) {
	mu.Lock()
	lastBody = ""
	lastHeaders = map[string]string{}
	mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
