// Command mock-echo-llm is a minimal OpenAI-chat-completions-shaped backend
// used by the guardrails-ai (and byo-guardrail) end-to-end test suites.
//
// It echoes the last user message's content back as the assistant's reply,
// so a keyword placed in the request (e.g. "BLOCK_ME") also appears in the
// response, letting a single request exercise the response-phase guardrail
// without a separate reply-authoring mechanism.
//
// GET /debug/last-request returns the full request body most recently
// received, so the collection can assert exactly what reached the backend
// (e.g. to prove request-phase MODIFY rewrote the content before it arrived
// here). POST /debug/reset clears it. GET /healthz is a readiness probe.
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

var (
	mu          sync.Mutex
	lastRequest string
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

func main() {
	addr := envOr("ADDR", ":9731")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/last-request", handleLastRequest)
	mux.HandleFunc("POST /debug/reset", handleReset)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", handleChatCompletions)

	log.Printf("mock-echo-llm listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	lastRequest = string(body)
	mu.Unlock()

	var req chatRequest
	replyContent := ""
	if err := json.Unmarshal(body, &req); err == nil && len(req.Messages) > 0 {
		replyContent = req.Messages[len(req.Messages)-1].Content
	}

	resp := map[string]interface{}{
		"id":      "mock-chatcmpl-1",
		"object":  "chat.completion",
		"model":   "mock-model",
		"created": time.Now().Unix(),
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": replyContent,
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
	_ = json.NewEncoder(w).Encode(resp)
}

func handleLastRequest(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"body": lastRequest})
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	lastRequest = ""
	mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
