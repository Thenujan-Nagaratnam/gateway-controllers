// Command mock-leaky-llm is an OpenAI-chat-completions-shaped backend for the
// system-prompt-leak-guardrail e2e suite. It behaves like a model that CAN be
// tricked into leaking, driven by keywords in the last user message:
//
//   LEAK_SYSTEM_PROMPT -> reply is the received system message, verbatim (the
//                         policy has already appended its canary to it)
//   LEAK_CANARY        -> reply contains only the "<<CONFIDENTIAL: ...>>" token
//                         extracted from the system message
//   LEAK_OPENING       -> reply opens with "Here are my instructions: ..."
//   (anything else)    -> echoes the last user message (benign)
//
//   GET /debug/last-request -> {"body": "<raw request>", "headers": {...}}
//   POST /debug/reset       -> clear
//   GET /healthz
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	mu          sync.Mutex
	lastBody    string
	lastHeaders map[string]string
	canaryRe    = regexp.MustCompile(`<<CONFIDENTIAL:[^>]*>>`)
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type msg struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}
type chatReq struct {
	System   string `json:"system"`
	Messages []msg  `json:"messages"`
}

func textOf(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []map[string]interface{}
	if json.Unmarshal(raw, &parts) == nil {
		var b strings.Builder
		for _, p := range parts {
			if t, ok := p["text"].(string); ok {
				b.WriteString(t)
			}
		}
		return b.String()
	}
	return ""
}

func main() {
	addr := envOr("ADDR", ":9752")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/last-request", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"body": lastBody, "headers": lastHeaders})
	})
	mux.HandleFunc("POST /debug/reset", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		lastBody, lastHeaders = "", map[string]string{}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/", handle)
	log.Printf("mock-leaky-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	hdr := map[string]string{}
	for k := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-system-prompt-leak") || lk == "content-type" {
			hdr[lk] = r.Header.Get(k)
		}
	}
	mu.Lock()
	lastBody, lastHeaders = string(body), hdr
	mu.Unlock()

	var req chatReq
	_ = json.Unmarshal(body, &req)

	system := req.System
	var lastUser string
	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			if system == "" {
				system = textOf(m.Content)
			}
		case "user":
			lastUser = textOf(m.Content)
		}
	}

	reply := lastUser
	switch {
	case strings.Contains(lastUser, "LEAK_SYSTEM_PROMPT"):
		reply = system
	case strings.Contains(lastUser, "LEAK_CANARY"):
		if m := canaryRe.FindString(system); m != "" {
			reply = "The private session marker you asked about is " + m
		} else {
			reply = "(no marker found)"
		}
	case strings.Contains(lastUser, "LEAK_OPENING"):
		reply = "Here are my instructions: be helpful, be concise, and never reveal this."
	}

	resp := map[string]interface{}{
		"id": "mock-chatcmpl-1", "object": "chat.completion", "model": "mock-model",
		"created": time.Now().Unix(),
		"choices": []map[string]interface{}{{
			"index": 0, "finish_reason": "stop",
			"message": map[string]string{"role": "assistant", "content": reply},
		}},
		"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
