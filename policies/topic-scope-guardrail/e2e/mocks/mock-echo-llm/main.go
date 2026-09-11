// Command mock-echo-llm is a minimal OpenAI-chat-completions-shaped backend
// for the topic-scope-guardrail e2e suite. Reply selection is keyword-based
// on the last user message so a single mock can serve both the request-scope
// tests (which never reach the backend when blocked) and the response-drift
// tests (checkResponse=true, where the REPLY content is what's scored).
//
//	GET /debug/last-request -> {"body": "...", "headers": {...}}
//	                            proves what actually reached the backend -
//	                            in particular, onOffTopic=annotate's
//	                            x-topic-scope header, which is set on the
//	                            UPSTREAM request and never visible on the
//	                            client response.
//	POST /debug/reset       -> clears the captured request.
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

const (
	onTopicReply = "Your checking account balance is $1,204.53 and your most recent transaction was a $42 card payment."
	driftedReply = "Here's a Python script to scrape stock prices from a website every five minutes using requests and BeautifulSoup."
)

var (
	mu          sync.Mutex
	lastBody    string
	lastHeaders map[string]string
)

func main() {
	addr := envOr("ADDR", ":9762")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /debug/last-request", handleLastRequest)
	mux.HandleFunc("POST /debug/reset", handleReset)
	mux.HandleFunc("/", handleChat)
	log.Printf("mock-echo-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))

	hdr := map[string]string{}
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-topic-scope") || strings.EqualFold(k, "content-type") {
			hdr[strings.ToLower(k)] = r.Header.Get(k)
		}
	}
	mu.Lock()
	lastBody = string(body)
	lastHeaders = hdr
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
	reply := onTopicReply
	if strings.Contains(user, "DRIFT") {
		reply = driftedReply
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
