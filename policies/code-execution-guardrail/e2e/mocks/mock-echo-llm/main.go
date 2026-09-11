// Command mock-echo-llm is a minimal MCP-tools/call-shaped backend for the
// code-execution-guardrail e2e suite. It just returns a canned "executed"
// result - the guardrail's whole job is deciding whether a code-carrying
// tool call ever reaches this far.
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
	addr := envOr("ADDR", ":9763")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(io.LimitReader(r.Body, 8<<20))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{
				"content": []map[string]string{{"type": "text", "text": "executed"}},
			},
		})
	})
	log.Printf("mock-echo-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
