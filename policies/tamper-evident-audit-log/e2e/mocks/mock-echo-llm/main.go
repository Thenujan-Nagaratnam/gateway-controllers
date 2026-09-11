// Command mock-echo-llm is a minimal OpenAI-chat-completions-shaped backend
// for the tamper-evident-audit-log e2e suite. The policy under test only
// ever reads the raw bytes of the request/response - it never depends on
// backend behavior - so this just echoes the last user message back as the
// assistant reply (giving each distinct test request a distinct, and
// therefore independently re-hashable, response body).
//
// It also doubles as the audit-log sink (the policy's `sinkUrl`):
// POST /sink captures the delivered record, and GET /debug/last-sink
// returns the most recently captured one.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
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
	mu       sync.Mutex
	lastSink json.RawMessage
)

func main() {
	addr := envOr("ADDR", ":9760")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("POST /sink", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		mu.Lock()
		lastSink = json.RawMessage(body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /debug/last-sink", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n := lastSink
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == nil {
			w.Write([]byte(`{}`))
			return
		}
		w.Write(n)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		reply := "ok"
		for _, m := range req.Messages {
			if m.Role == "user" {
				reply = m.Content
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "mock-chatcmpl-1", "object": "chat.completion", "model": "mock-model",
			"created": time.Now().Unix(),
			"choices": []map[string]interface{}{{
				"index": 0, "finish_reason": "stop",
				"message": map[string]string{"role": "assistant", "content": reply},
			}},
			"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	})
	log.Printf("mock-echo-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
