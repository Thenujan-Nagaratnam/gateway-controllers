// Command mock-guardrails-server is a minimal stand-in for a Guardrails AI
// server, used for the guardrails-ai policy's end-to-end test suite.
//
// POST /guards/{guardName}/validate accepts {"llmOutput": "...", "numReasks": N}
// and returns a deterministic, keyword-driven verdict so the Postman collection
// can trigger every code path predictably:
//
//   - llmOutput contains "BLOCK_ME"      -> status "fail", with failedValidators
//   - llmOutput contains "HUGE_RESPONSE" -> status "pass", but the response body
//     is padded past a couple KB, to exercise the policy's maxResponseBytes limit
//   - llmOutput contains "SLOW_RESPONSE" -> sleeps 3s before responding, to
//     exercise the policy's requestTimeout
//   - llmOutput contains "SERVER_ERROR"  -> HTTP 500
//   - anything else                      -> status "pass"
//
// If started with EXPECT_API_KEY set, every /validate call must present
// "Authorization: Bearer <EXPECT_API_KEY>" or the server responds 401 - used to
// prove the policy actually sends the configured apiKey.
//
// GET /debug/last-request returns the most recently received llmOutput, so the
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
	mu             sync.Mutex
	lastLLMOutput  string
	expectedAPIKey string
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type validateRequest struct {
	LLMOutput string `json:"llmOutput"`
	NumReasks int    `json:"numReasks"`
}

func main() {
	addr := envOr("ADDR", ":9730")
	expectedAPIKey = os.Getenv("EXPECT_API_KEY")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /guards/", handleValidate)
	mux.HandleFunc("GET /debug/last-request", handleLastRequest)
	mux.HandleFunc("POST /debug/reset", handleReset)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("mock-guardrails-server listening on %s (auth required: %v)", addr, expectedAPIKey != "")
	log.Fatal(http.ListenAndServe(addr, loggingMiddleware(mux)))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("request: method=%s path=%s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/validate") {
		http.NotFound(w, r)
		return
	}

	if expectedAPIKey != "" {
		want := "Bearer " + expectedAPIKey
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_api_key"})
			return
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	var req validateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	lastLLMOutput = req.LLMOutput
	mu.Unlock()

	switch {
	case strings.Contains(req.LLMOutput, "SERVER_ERROR"):
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
		return

	case strings.Contains(req.LLMOutput, "SLOW_RESPONSE"):
		time.Sleep(3 * time.Second)
	}

	w.Header().Set("Content-Type", "application/json")

	switch {
	case strings.Contains(req.LLMOutput, "BLOCK_ME"):
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"callId":           "mock-call-block",
			"rawLlmOutput":     req.LLMOutput,
			"status":           "fail",
			"failedValidators": []string{"ToxicLanguage"},
		})

	case strings.Contains(req.LLMOutput, "HUGE_RESPONSE"):
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"callId":       "mock-call-huge",
			"rawLlmOutput": req.LLMOutput,
			"status":       "pass",
			"padding":      strings.Repeat("x", 4096),
		})

	default:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"callId":       "mock-call-pass",
			"rawLlmOutput": req.LLMOutput,
			"status":       "pass",
		})
	}
}

func handleLastRequest(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"llmOutput": lastLLMOutput})
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	lastLLMOutput = ""
	mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
