// Command mock-tool-backend is a permissive "third-party tool" backend for the
// tool-argument-egress-dlp e2e suite. Whatever reaches it has passed the DLP
// policy. It records the last request so the collection can assert what was (or
// was not) forwarded.
//
//   GET  /debug/last-request -> {"body": "<raw>", "headers": {...}}
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
	mu   sync.Mutex
	body string
	hdr  map[string]string
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	addr := envOr("ADDR", ":9756")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /debug/last-request", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"body": body, "headers": hdr})
	})
	mux.HandleFunc("POST /debug/reset", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		body, hdr = "", map[string]string{}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		h := map[string]string{}
		for k := range r.Header {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "x-egress-dlp") || lk == "content-type" {
				h[lk] = r.Header.Get(k)
			}
		}
		mu.Lock()
		body, hdr = string(b), h
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	log.Printf("mock-tool-backend on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
