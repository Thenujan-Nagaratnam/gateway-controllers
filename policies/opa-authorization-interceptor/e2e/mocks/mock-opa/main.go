// Command mock-opa doubles as (a) a fake Open Policy Agent decision endpoint and
// (b) the protected backend, for the opa-authorization-interceptor e2e suite.
//
//   POST /v1/data/agentgw/authz -> {"result": <decision>} derived from input:
//       tool issue_refund with arguments.amount > 500 -> {allow:false, reason:...}
//       tool lookup                                    -> {allow:true, redact:["$.params.arguments.ssn"]}
//       header x-tenant == "blocked"                   -> {allow:false, reason:"tenant blocked"}
//       otherwise                                      -> {allow:true}
//   POST /err500   -> HTTP 500 (drives the fail-closed-on-error case)
//   POST /garbage  -> non-JSON body
//   POST /mcp      -> the backend: echoes received x-opa-authz header + body via /debug/last
//   GET  /debug/last  -> {"body": "...", "headers": {...}}
//   POST /debug/reset ; GET /healthz
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
	lastHdr  map[string]string
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	addr := envOr("ADDR", ":9755")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /debug/last", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"body": lastBody, "headers": lastHdr})
	})
	mux.HandleFunc("POST /debug/reset", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		lastBody, lastHdr = "", map[string]string{}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /err500", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	mux.HandleFunc("POST /garbage", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("<<not json")) })
	mux.HandleFunc("POST /v1/data/agentgw/authz", decide)
	mux.HandleFunc("/", backend)
	log.Printf("mock-opa on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func decide(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var wrap struct {
		Input map[string]interface{} `json:"input"`
	}
	_ = json.Unmarshal(body, &wrap)
	in := wrap.Input

	result := map[string]interface{}{"allow": true}

	if hdr, ok := in["headers"].(map[string]interface{}); ok {
		if hdr["x-tenant"] == "blocked" {
			result = map[string]interface{}{"allow": false, "reason": "tenant blocked"}
		}
	}
	if tool, ok := in["tool"].(map[string]interface{}); ok {
		switch tool["name"] {
		case "issue_refund":
			if args, ok := tool["arguments"].(map[string]interface{}); ok {
				if amt, ok := args["amount"].(float64); ok && amt > 500 {
					result = map[string]interface{}{"allow": false, "reason": "refund amount exceeds the 500 ceiling"}
				}
			}
		case "lookup":
			result = map[string]interface{}{"allow": true, "redact": []string{"$.params.arguments.ssn"}}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"result": result})
}

func backend(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	hdr := map[string]string{}
	for k := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-opa-authz") || lk == "content-type" {
			hdr[lk] = r.Header.Get(k)
		}
	}
	mu.Lock()
	lastBody, lastHdr = string(body), hdr
	mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "echo": json.RawMessage(orNull(body))})
}

func orNull(b []byte) []byte {
	if len(b) == 0 || !json.Valid(b) {
		return []byte("null")
	}
	return b
}
