// Command mock-schema-llm is an OpenAI-chat-completions-shaped backend for the
// structured-output-schema-repair e2e suite. The reply content is chosen by a
// keyword in the last user message so the collection can drive malformed output
// through the gateway:
//
//   CLEAN          -> {"name":"Ada","age":36}
//   FENCED         -> ```json\n{...}\n```
//   TRAILING_COMMA -> {"name":"Ada","age":36,}
//   PROSE          -> Here is the JSON: {...} hope that helps!
//   MISSING_FIELD  -> {"name":"Ada"}
//   EXTRA_FIELD    -> {"name":"Ada","age":36,"x":1}
//   GARBAGE        -> Ada is thirty-six years old.
//
// POST /repair emulates a repair model: it always returns a clean object.
// GET /debug/last-request, POST /debug/reset, GET /healthz.
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

var (
	mu       sync.Mutex
	lastBody string
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

const cleanDoc = `{"name":"Ada","age":36}`

func replyFor(user string) string {
	switch {
	case strings.Contains(user, "FENCED"):
		return "```json\n" + cleanDoc + "\n```"
	case strings.Contains(user, "TRAILING_COMMA"):
		return `{"name":"Ada","age":36,}`
	case strings.Contains(user, "PROSE"):
		return "Here is the JSON you asked for:\n" + cleanDoc + "\nhope that helps!"
	case strings.Contains(user, "MISSING_FIELD"):
		return `{"name":"Ada"}`
	case strings.Contains(user, "EXTRA_FIELD"):
		return `{"name":"Ada","age":36,"x":1}`
	case strings.Contains(user, "GARBAGE"):
		return "Ada is thirty-six years old."
	default:
		return cleanDoc
	}
}

func main() {
	addr := envOr("ADDR", ":9754")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /debug/last-request", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"body": lastBody})
	})
	mux.HandleFunc("POST /debug/reset", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		lastBody = ""
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /repair", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chatResp(cleanDoc))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		mu.Lock()
		lastBody = string(body)
		mu.Unlock()
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		user := ""
		for _, m := range req.Messages {
			if m.Role == "user" {
				user = m.Content
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chatResp(replyFor(user)))
	})
	log.Printf("mock-schema-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func chatResp(content string) map[string]interface{} {
	return map[string]interface{}{
		"id": "mock-chatcmpl-1", "object": "chat.completion", "model": "mock-model",
		"choices": []map[string]interface{}{{
			"index": 0, "finish_reason": "stop",
			"message": map[string]string{"role": "assistant", "content": content},
		}},
		"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
	}
}
