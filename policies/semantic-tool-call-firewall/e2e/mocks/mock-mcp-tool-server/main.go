// Command mock-mcp-tool-server is a permissive backend for the
// semantic-tool-call-firewall e2e suite: it accepts any POST body and returns a
// JSON-RPC tools/call result echoing the requested tool name. Whatever reaches
// it has already passed the firewall.
//
//   GET  /debug/last-request -> {"body": "<raw>", "headers": {...}}
//   POST /debug/reset        -> clear
//   GET  /healthz
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
	mu          sync.Mutex
	lastBody    string
	lastHeaders map[string]string
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	addr := envOr("ADDR", ":9753")
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		hdr := map[string]string{}
		for k := range r.Header {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "x-tool-firewall") || lk == "content-type" {
				hdr[lk] = r.Header.Get(k)
			}
		}
		mu.Lock()
		lastBody, lastHeaders = string(body), hdr
		mu.Unlock()

		tool := "unknown"
		var req struct {
			ID     interface{} `json:"id"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if json.Unmarshal(body, &req) == nil && req.Params.Name != "" {
			tool = req.Params.Name
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]interface{}{
				"content": []map[string]interface{}{{"type": "text", "text": "executed: " + tool}},
			},
		})
	})
	log.Printf("mock-mcp-tool-server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
