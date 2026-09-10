// Command mock-byo-guardrail-server is a minimal stand-in for an operator-hosted
// "bring your own guardrail" service, used for the byo-guardrail policy's
// end-to-end test suite.
//
// It implements the byo-guardrail wire contract: POST / (any path - the
// policy dials the full configured endpoint) accepts
// {"content": "...", "direction": "REQUEST"|"RESPONSE", "requestId": "..."}
// and returns a deterministic, keyword-driven verdict so the Postman
// collection can trigger every code path predictably:
//
//   - content contains "BLOCK_ME"       -> verdict BLOCK, with a reason and assessment
//   - content contains "MODIFY_ME"      -> verdict MODIFY, modifiedContent="[REDACTED]"
//   - content contains "UNKNOWN_VERDICT"-> verdict "MAYBE" (not ALLOW/BLOCK/MODIFY)
//   - content contains "EMPTY_MODIFY"   -> verdict MODIFY with an empty modifiedContent
//   - content contains "SLOW_RESPONSE"  -> sleeps 3s before responding
//   - content contains "SERVER_ERROR"   -> HTTP 500
//   - anything else                      -> verdict ALLOW
//
// If started with EXPECT_API_KEY and EXPECT_AUTH_HEADER set, every call must
// present that header with value "<EXPECT_AUTH_VALUE_PREFIX><EXPECT_API_KEY>"
// or the server responds 401 - used to prove the policy actually sends the
// configured credential under the configured header/prefix.
//
// GET /debug/last-request returns the most recently received content, so the
// collection can assert the policy extracted the right text via jsonPath.
// POST /debug/reset clears it. GET /healthz is a plain readiness probe.
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

var (
	mu                sync.Mutex
	lastContent       string
	lastAuthorization string
	lastXAPIKey       string
	expectAPIKey      string
	expectAuthHeader  string
	expectValueFull   string
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type evaluateRequest struct {
	Content   string `json:"content"`
	Direction string `json:"direction"`
	RequestID string `json:"requestId"`
}

type decision struct {
	Verdict              string            `json:"verdict"`
	Reason               string            `json:"reason,omitempty"`
	ModifiedContent      string            `json:"modifiedContent,omitempty"`
	Assessment           map[string]string `json:"assessment,omitempty"`
	InterveningGuardrail string            `json:"interveningGuardrail,omitempty"`
}

func main() {
	addr := envOr("ADDR", ":9740")
	expectAPIKey = os.Getenv("EXPECT_API_KEY")
	expectAuthHeader = envOr("EXPECT_AUTH_HEADER", "Authorization")
	expectValueFull = envOr("EXPECT_AUTH_VALUE_PREFIX", "Bearer ") + expectAPIKey

	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/last-request", handleLastRequest)
	mux.HandleFunc("POST /debug/reset", handleReset)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/evaluate", handleEvaluate)

	log.Printf("mock-byo-guardrail-server listening on %s (auth required: %v)", addr, expectAPIKey != "")
	log.Fatal(http.ListenAndServe(addr, loggingMiddleware(mux)))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("request: method=%s path=%s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if expectAPIKey != "" {
		if r.Header.Get(expectAuthHeader) != expectValueFull {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_credential"})
			return
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	var req evaluateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	lastContent = req.Content
	lastAuthorization = r.Header.Get("Authorization")
	lastXAPIKey = r.Header.Get("x-api-key")
	mu.Unlock()

	switch {
	case strings.Contains(req.Content, "SERVER_ERROR"):
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
		return

	case strings.Contains(req.Content, "SLOW_RESPONSE"):
		time.Sleep(3 * time.Second)
	}

	w.Header().Set("Content-Type", "application/json")

	switch {
	case strings.Contains(req.Content, "BLOCK_ME"):
		_ = json.NewEncoder(w).Encode(decision{
			Verdict:    "BLOCK",
			Reason:     "content violates policy XYZ",
			Assessment: map[string]string{"category": "toxicity", "score": "0.97"},
		})

	case strings.Contains(req.Content, "EMPTY_MODIFY"):
		_ = json.NewEncoder(w).Encode(decision{Verdict: "MODIFY", ModifiedContent: ""})

	case strings.Contains(req.Content, "MODIFY_ME"):
		_ = json.NewEncoder(w).Encode(decision{Verdict: "MODIFY", ModifiedContent: "[REDACTED]"})

	case strings.Contains(req.Content, "UNKNOWN_VERDICT"):
		_ = json.NewEncoder(w).Encode(decision{Verdict: "MAYBE"})

	default:
		_ = json.NewEncoder(w).Encode(decision{Verdict: "ALLOW"})
	}
}

func handleLastRequest(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"content":       lastContent,
		"authorization": lastAuthorization,
		"xApiKey":       lastXAPIKey,
	})
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	lastContent = ""
	lastAuthorization = ""
	lastXAPIKey = ""
	mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
