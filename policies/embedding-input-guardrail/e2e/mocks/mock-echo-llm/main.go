// Command mock-echo-llm is a minimal OpenAI-embeddings-shaped backend for
// the embedding-input-guardrail e2e suite. It just returns a canned
// embedding vector - the guardrail's whole job is deciding whether the
// input ever reaches this far.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	addr := envOr("ADDR", ":9766")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(io.LimitReader(r.Body, 8<<20))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"object": "list",
			"data": []map[string]interface{}{
				{"object": "embedding", "index": 0, "embedding": []float64{0.001, -0.002, 0.003}},
			},
			"model": "text-embedding-3-small",
			"usage": map[string]int{"prompt_tokens": 8, "total_tokens": 8},
		})
	})
	log.Printf("mock-echo-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
