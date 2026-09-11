// Command mock-echo-llm is a minimal OpenAI-chat-completions-shaped backend
// for the ai-content-disclosure e2e suite. It echoes the last user message
// back as the assistant reply, so each test controls its own reply content.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	addr := envOr("ADDR", ":9761")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
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
