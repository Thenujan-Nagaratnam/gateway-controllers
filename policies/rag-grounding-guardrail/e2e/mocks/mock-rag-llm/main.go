// Command mock-rag-llm is an OpenAI-chat-completions-shaped backend for the
// rag-grounding-guardrail e2e suite. The reply is chosen by a keyword in the
// last user message; the collection supplies the retrieved context (an Apollo 11
// passage) in a tool message, and these canned answers are written to be clearly
// grounded / ungrounded against that passage:
//
//   GROUNDED   -> paraphrases the passage, all figures from the passage
//   UNGROUNDED -> a coral-reef answer with no overlap
//   SPECIFIC   -> mostly grounded but with a fabricated cost + year
//   NOCITE     -> a grounded claim, no citation marker
//   CITED      -> the same claim with "[doc-1]"
//   SHORT      -> "Neil Armstrong." (below minAnswerChars)
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

const (
	grounded   = "Apollo 11 launched on 16 July 1969 from Kennedy Space Center. Neil Armstrong and Buzz Aldrin landed the lunar module Eagle in the Sea of Tranquility on 20 July 1969, while Michael Collins remained in lunar orbit aboard the command module Columbia. The astronauts collected 21.5 kilograms of lunar material and returned to Earth on 24 July 1969."
	ungrounded = "The Great Barrier Reef is the world's largest coral reef system, stretching over 2000 kilometres off the coast of Queensland, Australia. It hosts thousands of species of fish, molluscs and corals, and is increasingly threatened by rising sea temperatures and mass bleaching events."
	specific   = "Apollo 11 launched from Kennedy Space Center and Armstrong walked on the Moon in the Sea of Tranquility. The programme cost 355 billion dollars and the crew finally returned home in 1971."
	nocite     = "Armstrong and Aldrin landed the lunar module Eagle in the Sea of Tranquility while Collins stayed aboard Columbia."
	cited      = nocite + " [doc-1]"
	short      = "Neil Armstrong."
)

func replyFor(user string) string {
	switch {
	case strings.Contains(user, "UNGROUNDED"):
		return ungrounded
	case strings.Contains(user, "SPECIFIC"):
		return specific
	case strings.Contains(user, "NOCITE"):
		return nocite
	case strings.Contains(user, "CITED"):
		return cited
	case strings.Contains(user, "SHORT"):
		return short
	default:
		return grounded
	}
}

func main() {
	addr := envOr("ADDR", ":9757")
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
		user := ""
		for _, m := range req.Messages {
			if m.Role == "user" {
				user = m.Content
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "mock-chatcmpl-1", "object": "chat.completion", "model": "mock-model",
			"created": time.Now().Unix(),
			"choices": []map[string]interface{}{{
				"index": 0, "finish_reason": "stop",
				"message": map[string]string{"role": "assistant", "content": replyFor(user)},
			}},
			"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	})
	log.Printf("mock-rag-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
