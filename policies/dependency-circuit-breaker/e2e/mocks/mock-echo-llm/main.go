// Command mock-echo-llm is a controllable MCP-tools/call-shaped backend for
// the dependency-circuit-breaker e2e suite. Each tool name has an
// independently settable mode - "ok" (default), "fail" (HTTP 500), or
// "rpcerror" (HTTP 200 with a JSON-RPC error field) - set via
// POST /debug/set-mode {"tool":"...", "mode":"..."} and cleared via
// POST /debug/reset, so the suite can drive a tool through enough
// consecutive failures to trip the breaker and then back to healthy to
// exercise the half-open trial.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

var (
	mu    sync.Mutex
	modes = map[string]string{}
)

func modeFor(tool string) string {
	mu.Lock()
	defer mu.Unlock()
	if m, ok := modes[tool]; ok {
		return m
	}
	return "ok"
}

func main() {
	addr := envOr("ADDR", ":9765")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	mux.HandleFunc("POST /debug/set-mode", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Tool, Mode string }
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		_ = json.Unmarshal(body, &req)
		if req.Tool == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		modes[req.Tool] = req.Mode
		mu.Unlock()
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("POST /debug/reset", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		modes = map[string]string{}
		mu.Unlock()
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		var req struct {
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)

		w.Header().Set("Content-Type", "application/json")
		switch modeFor(req.Params.Name) {
		case "fail":
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "internal error"})
		case "rpcerror":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"error": map[string]interface{}{"code": -32000, "message": "tool execution failed"},
			})
		default: // "ok"
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]interface{}{
					"content": []map[string]string{{"type": "text", "text": "executed"}},
				},
			})
		}
	})
	log.Printf("mock-echo-llm on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
