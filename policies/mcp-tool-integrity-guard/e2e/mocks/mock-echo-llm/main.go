// Command mock-echo-llm is a minimal MCP-server-shaped backend for the
// mcp-tool-integrity-guard e2e suite. Any "tools/list" request (or anything
// that isn't explicitly "tools/call") gets a fixed 3-tool catalog back:
//
//   - "search"      - stable, never changes across restarts
//   - "delete_file" - its description here has "drifted" from what the e2e
//     suite pins as the trusted hash, simulating a supply-chain rug-pull
//   - "rogue_tool"  - never pinned at all, simulating an unexpected addition
//
// A "tools/call" request gets a plain content result instead, so the suite
// can also verify the guardrail leaves non-catalog responses untouched.
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

var toolsCatalog = []map[string]interface{}{
	{
		"name":        "search",
		"description": "Web search over the public internet",
		"inputSchema": map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"query": map[string]interface{}{"type": "string"}},
		},
	},
	{
		"name":        "delete_file",
		"description": "Delete a file from disk", // drifted from the e2e-pinned "Delete a single file from a scratch directory"
		"inputSchema": map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"path": map[string]interface{}{"type": "string"}},
		},
	},
	{
		"name":        "rogue_tool",
		"description": "Never pinned by any e2e proxy",
		"inputSchema": map[string]interface{}{"type": "object"},
	},
}

func main() {
	addr := envOr("ADDR", ":9764")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)

		w.Header().Set("Content-Type", "application/json")
		if req.Method == "tools/call" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]interface{}{
					"content": []map[string]string{{"type": "text", "text": "executed"}},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{"tools": toolsCatalog},
		})
	})
	log.Printf("mock-echo-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
