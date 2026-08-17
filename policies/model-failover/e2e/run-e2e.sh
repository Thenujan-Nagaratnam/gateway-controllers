#!/usr/bin/env bash
#
# One-command runner for the model-failover policy's end-to-end test suite
# (postman/model-failover.postman_collection.json) against a gateway stack
# that is ALREADY running (see gateway/dev-policies/oauth2-generator/e2e/
# TESTING.md Parts B/C for the general build+run pattern - this script does
# not build or start gateway-controller/gateway-runtime itself).
#
# Covers both LlmProvider (multi-target-group dispatch, cross-cluster
# failover, suspend skip-ahead, unmatched-model passthrough, zero-fallback
# groups, registration-time validation rejections, model-failover +
# resilience.retry composing on one operation) and LlmProxy (model-keyed
# dispatch across additionalProviders aliases, registration-time rejection of
# an unsafe loopback+fallback config).
#
# What it does:
#   1. Sanity-checks the gateway stack is reachable.
#   2. Starts four instances of mock-model-backend natively (go run), on
#      different ports, unless they're already up - one per LlmProvider
#      target (primary/fallback-1/anthropic-primary/anthropic-fallback-1),
#      reused as-is for the LlmProxy provider aliases.
#   3. Registers each API config as its OWN folder, waits for gateway-runtime
#      to actually pick up the new route via xDS (the same
#      registration-returns-201-before-the-route-is-live gap documented in
#      oauth2-generator's own run-e2e.sh) before running any folder that
#      invokes it, then runs the flow/verification folders.
#   4. Retries the whole run if xDS propagation didn't land in time - a
#      transient infrastructure-timing condition, not a policy bug.
#   5. Tears down only the mock processes THIS script started, deletes every
#      resource it registered, and reports a single pass/fail exit code.
#
# Usage:
#   ./run-e2e.sh
#
# Env overrides:
#   CONTROLLER_ADMIN_URL   http://localhost:9094
#   CONTROLLER_BASE_URL    http://localhost:9090
#   GATEWAY_URL            https://localhost:8443
#   BACKEND_A_ADDR         :9711  (LlmProvider primary / LlmProxy openai-alias)
#   BACKEND_B_ADDR         :9712  (LlmProvider fallback-1)
#   BACKEND_C_ADDR         :9713  (LlmProvider anthropic-primary / LlmProxy anthropic-alias)
#   BACKEND_D_ADDR         :9714  (LlmProvider anthropic-fallback-1)
#   NEWMAN_REPORTERS       cli,junit
#   MAX_ATTEMPTS           3
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTION="$ROOT/postman/model-failover.postman_collection.json"
REPORT_DIR="$ROOT/postman/reports"

CONTROLLER_ADMIN_URL="${CONTROLLER_ADMIN_URL:-http://localhost:9094}"
CONTROLLER_BASE_URL="${CONTROLLER_BASE_URL:-http://localhost:9090}"
GATEWAY_URL="${GATEWAY_URL:-https://localhost:8443}"
BACKEND_A_ADDR="${BACKEND_A_ADDR:-:9711}"
BACKEND_B_ADDR="${BACKEND_B_ADDR:-:9712}"
BACKEND_C_ADDR="${BACKEND_C_ADDR:-:9713}"
BACKEND_D_ADDR="${BACKEND_D_ADDR:-:9714}"
NEWMAN_REPORTERS="${NEWMAN_REPORTERS:-cli,junit}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"

BACKEND_A_PORT="${BACKEND_A_ADDR#:}"
BACKEND_B_PORT="${BACKEND_B_ADDR#:}"
BACKEND_C_PORT="${BACKEND_C_ADDR#:}"
BACKEND_D_PORT="${BACKEND_D_ADDR#:}"

log() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# ─── prerequisites ───────────────────────────────────────────────────────────

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v go >/dev/null 2>&1 || die "go is required to run the mock servers"

NEWMAN=(newman)
if ! command -v newman >/dev/null 2>&1; then
  command -v npx >/dev/null 2>&1 || die "neither 'newman' nor 'npx' found on PATH - install newman: npm install -g newman"
  NEWMAN=(npx --yes newman)
fi

# ─── verify the gateway stack is already up (this script never starts it) ───

log "Checking gateway-controller admin API at $CONTROLLER_ADMIN_URL ..."
curl -sf --max-time 5 "$CONTROLLER_ADMIN_URL/api/admin/v1/health" >/dev/null \
  || die "gateway-controller not reachable at $CONTROLLER_ADMIN_URL - start the stack first: cd gateway && make build && docker compose up -d gateway-controller gateway-runtime sample-backend redis"

log "Checking gateway-runtime (Envoy) at $GATEWAY_URL ..."
curl -sk --max-time 5 "$GATEWAY_URL/" -o /dev/null \
  || die "gateway-runtime not reachable at $GATEWAY_URL - start the stack first"

echo "Gateway stack looks up."

# ─── start the mocks (skip any that's already running) ─────────────────────

declare -a STARTED_PIDS=()

cleanup() {
  local ec=$?
  if [ "${#STARTED_PIDS[@]}" -gt 0 ]; then
    log "Stopping mocks this script started (pids: ${STARTED_PIDS[*]}) ..."
    for pid in "${STARTED_PIDS[@]}"; do
      kill "$pid" >/dev/null 2>&1 || true
    done
    wait "${STARTED_PIDS[@]}" 2>/dev/null || true
  fi
  exit $ec
}
trap cleanup EXIT INT TERM

wait_healthy() {
  local url="$1" name="$2" tries=30
  until curl -sf --max-time 1 "$url" >/dev/null 2>&1; do
    tries=$((tries - 1))
    if [ "$tries" -le 0 ]; then
      die "$name never became healthy at $url"
    fi
    sleep 0.5
  done
}

start_mock_if_needed() {
  local healthz_url="$1" addr_env_val="$2" label="$3"
  if curl -sf --max-time 1 "$healthz_url" >/dev/null 2>&1; then
    echo "$label already running at $healthz_url - reusing it."
    return
  fi
  log "Starting $label ..."
  (cd "$ROOT/mocks/mock-model-backend" && GOWORK=off ADDR="$addr_env_val" exec go run .) \
    >"$REPORT_DIR/mock-model-backend-$(echo "$addr_env_val" | tr -d ':').log" 2>&1 &
  STARTED_PIDS+=("$!")
  wait_healthy "$healthz_url" "$label"
  echo "$label is up (pid $!)."
}

mkdir -p "$REPORT_DIR"

start_mock_if_needed "http://localhost:${BACKEND_A_PORT}/healthz" "$BACKEND_A_ADDR" "mock-model-backend (A / primary / openai-alias)"
start_mock_if_needed "http://localhost:${BACKEND_B_PORT}/healthz" "$BACKEND_B_ADDR" "mock-model-backend (B / fallback-1)"
start_mock_if_needed "http://localhost:${BACKEND_C_PORT}/healthz" "$BACKEND_C_ADDR" "mock-model-backend (C / anthropic-primary / anthropic-alias)"
start_mock_if_needed "http://localhost:${BACKEND_D_PORT}/healthz" "$BACKEND_D_ADDR" "mock-model-backend (D / anthropic-fallback-1)"

# ─── shared state ────────────────────────────────────────────────────────────

# route_is_up posts an empty body at the given context path and treats
# anything other than a 404/000 (curl's "no HTTP response at all" code) as
# "the route exists" - a 400/422/500 from an intentionally-malformed probe
# body still proves the route itself is live, which is all this checks.
route_is_up() {
  local path="$1"
  local code
  code=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' \
    -X POST "$GATEWAY_URL/$path" \
    -H "Content-Type: application/json" -d '{}')
  [ "$code" != "404" ] && [ "$code" != "000" ]
}

wait_for_route() {
  local path="$1" tries="${2:-40}"
  until route_is_up "$path"; do
    tries=$((tries - 1))
    [ "$tries" -le 0 ] && return 1
    sleep 0.5
  done
  return 0
}

delete_llm_provider() {
  curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-providers/$1" \
    -H "Authorization: Basic YWRtaW46YWRtaW4="
}

delete_llm_proxy() {
  curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-proxies/$1" \
    -H "Authorization: Basic YWRtaW46YWRtaW4="
}

cleanup_all_registered_resources() {
  delete_llm_proxy mf-proxy-zerofb-test
  delete_llm_proxy mf-proxy-default-test
  delete_llm_provider mf-proxy-primary-provider
  delete_llm_provider mf-proxy-anthropic-provider
  delete_llm_provider mf-zero-fallback-test
  delete_llm_provider model-failover-test
  delete_llm_provider mf-plain-single-upstream
  delete_llm_provider mf-shared-upstream-test
  delete_llm_provider mf-multi-op-test
  delete_llm_provider mf-3level-test
  delete_llm_provider mf-suspend-expiry-test
  delete_llm_provider mf-minimal-default
}

run_newman() {
  # $1 = human label, remaining args = newman flags/folders
  local label="$1"; shift
  log "$label"
  "${NEWMAN[@]}" run "$COLLECTION" --insecure "$@" || return 1
}

# ─── one full attempt: register -> wait -> test -> cleanup, per API ────────

run_attempt() {
  run_newman "Health checks ..." \
    --folder "00 - Health Checks" \
    --reporters cli --color on || return 1

  # --- LlmProvider: 2 independent target groups ---
  run_newman "Registering model-failover-test ..." \
    --folder "01 - LlmProvider: Register (2 independent target groups)" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up model-failover-test via xDS ..."
  wait_for_route "model-failover-test/latest/chat/completions" || { echo "route for 'model-failover-test' never came up" >&2; return 1; }
  # Route table showing up doesn't guarantee the policy engine's own policy
  # chain for that route has landed yet (separate, async xDS channel - see
  # oauth2-generator's run-e2e.sh for the same observed gap). Fixed grace
  # sleep, since there's no cheap readiness signal for that second channel.
  sleep 3
  echo "model-failover-test route is live."

  run_newman "Running LlmProvider flows (baseline, cross-cluster failover, suspend skip-ahead, passthrough) ..." \
    --folder "02 - LlmProvider: Baseline routing (no failure)" \
    --folder "03 - LlmProvider: Cross-cluster failover with per-attempt model rewrite" \
    --folder "04 - LlmProvider: Suspend skip-ahead" \
    --folder "05 - LlmProvider: Unmatched model passes through untouched" \
    --folder "06 - LlmProvider: Unmatched model passthrough is unaffected by an unrelated suspend" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-llmprovider-flows.xml" \
    --color on || return 1

  # --- LlmProvider: zero-fallback group (separate registration/route) ---
  run_newman "Registering mf-zero-fallback-test ..." \
    --folder "07 - LlmProvider: Register zero-fallback provider" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up mf-zero-fallback-test via xDS ..."
  wait_for_route "mf-zero-fallback-test/latest/chat/completions" || { echo "route for 'mf-zero-fallback-test' never came up" >&2; return 1; }
  sleep 3
  echo "mf-zero-fallback-test route is live."

  run_newman "Running zero-fallback target group flow ..." \
    --folder "08 - LlmProvider: Zero-fallback target group" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-zero-fallback.xml" \
    --color on || return 1

  # --- Registration-time validation rejections (no route wait needed - these never register) ---
  run_newman "Running registration-time validation rejections ..." \
    --folder "09 - LlmProvider: Registration-time validation rejections" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-validation-rejections.xml" \
    --color on || return 1

  # --- LlmProvider: model-failover + resilience.retry composing on one operation ---
  run_newman "Registering mf-resilience-retry-compose-test ..." \
    --folder "09b - LlmProvider: Register model-failover + resilience.retry composing on the same operation" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up mf-resilience-retry-compose-test via xDS ..."
  wait_for_route "mf-resilience-retry-compose-test/latest/chat/completions" || { echo "route for 'mf-resilience-retry-compose-test' never came up" >&2; return 1; }
  sleep 3
  echo "mf-resilience-retry-compose-test route is live."

  run_newman "Running composed retry (resilience.retry status code triggers model-failover cross-cluster failover) ..." \
    --folder "09c - LlmProvider: Composed retry - operator's resilience.retry status code also triggers model-failover's cross-cluster failover" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-resilience-retry-compose.xml" \
    --color on || return 1

  run_newman "Cleaning up model-failover-test ..." \
    --folder "10 - LlmProvider: Cleanup" \
    --reporters cli --color on || return 1

  # --- LlmProvider: single-upstream sanity check (exactly one cluster, common/default case) ---
  run_newman "Registering mf-plain-single-upstream ..." \
    --folder "11 - LlmProvider: Register single-upstream sanity check" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up mf-plain-single-upstream via xDS ..."
  wait_for_route "mf-plain-single-upstream/latest/chat/completions" || { echo "route for 'mf-plain-single-upstream' never came up" >&2; return 1; }
  sleep 3
  echo "mf-plain-single-upstream route is live."

  run_newman "Verifying single-upstream sanity check (exactly one Envoy cluster) ..." \
    --folder "12 - LlmProvider: Single-upstream sanity check (exactly one cluster)" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-single-upstream.xml" \
    --color on || return 1

  # --- LlmProvider: shared upstreamDefinition across two groups dedupes to one cluster ---
  run_newman "Registering mf-shared-upstream-test ..." \
    --folder "13 - LlmProvider: Register shared-upstream test" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up mf-shared-upstream-test via xDS ..."
  wait_for_route "mf-shared-upstream-test/latest/chat/completions" || { echo "route for 'mf-shared-upstream-test' never came up" >&2; return 1; }
  sleep 3
  echo "mf-shared-upstream-test route is live."

  run_newman "Verifying shared-upstream cluster dedup ..." \
    --folder "14 - LlmProvider: Shared upstreamDefinition across two groups dedupes to one cluster" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-shared-upstream.xml" \
    --color on || return 1

  # --- LlmProvider: multi-operation route-scoping (no cluster-name collision, no cross-op suspend leak) ---
  run_newman "Registering mf-multi-op-test ..." \
    --folder "15 - LlmProvider: Register multi-operation test" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up mf-multi-op-test via xDS (both operations) ..."
  wait_for_route "mf-multi-op-test/latest/chat/completions" || { echo "route for 'mf-multi-op-test' (op1) never came up" >&2; return 1; }
  wait_for_route "mf-multi-op-test/latest/other-chat/completions" || { echo "route for 'mf-multi-op-test' (op2) never came up" >&2; return 1; }
  sleep 3
  echo "mf-multi-op-test routes are live."

  run_newman "Verifying multi-operation route-scoping ..." \
    --folder "16 - LlmProvider: Multi-operation route-scoping (no collision, no cross-op suspend leak)" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-multi-op.xml" \
    --color on || return 1

  # --- LlmProvider: 3-level fallback chain (cascading failover + full exhaustion) ---
  run_newman "Registering mf-3level-test ..." \
    --folder "17 - LlmProvider: Register 3-level chain test" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up mf-3level-test via xDS ..."
  wait_for_route "mf-3level-test/latest/chat/completions" || { echo "route for 'mf-3level-test' never came up" >&2; return 1; }
  sleep 3
  echo "mf-3level-test route is live."

  run_newman "Verifying 3-level cascading failover ..." \
    --folder "18 - LlmProvider: 3-level fallback chain cascades through every member" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-3level-cascade.xml" \
    --color on || return 1

  run_newman "Verifying full chain exhaustion ..." \
    --folder "19 - LlmProvider: Fully exhausted chain surfaces the final attempt's error" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-3level-exhaustion.xml" \
    --color on || return 1

  # --- LlmProvider: suspend expiry (requires waiting out a real 3s window - shell-orchestrated) ---
  run_newman "Registering mf-suspend-expiry-test ..." \
    --folder "20 - LlmProvider: Register suspend-expiry test" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up mf-suspend-expiry-test via xDS ..."
  wait_for_route "mf-suspend-expiry-test/latest/chat/completions" || { echo "route for 'mf-suspend-expiry-test' never came up" >&2; return 1; }
  sleep 3
  echo "mf-suspend-expiry-test route is live."

  run_newman "Triggering suspend ..." \
    --folder "21 - LlmProvider: Suspend expiry - trigger suspend" \
    --reporters cli --color on || return 1

  run_newman "Verifying skip-ahead within the suspend window ..." \
    --folder "22 - LlmProvider: Suspend expiry - verify skip-ahead within the window" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-suspend-expiry-within-window.xml" \
    --color on || return 1

  log "Waiting out the 3s suspendDuration window (+1s margin) before checking expiry ..."
  sleep 4

  run_newman "Verifying primary is eligible again after the window elapses ..." \
    --folder "23 - LlmProvider: Suspend expiry - verify primary is eligible again after the window elapses" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-suspend-expiry-after-window.xml" \
    --color on || return 1

  # --- LlmProvider: minimal config - no upstreamDefinitions, no explicit upstreamDefinition anywhere ---
  run_newman "Registering mf-minimal-default ..." \
    --folder "24 - LlmProvider: Register minimal default-to-main config" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up mf-minimal-default via xDS ..."
  wait_for_route "mf-minimal-default/latest/chat/completions" || { echo "route for 'mf-minimal-default' never came up" >&2; return 1; }
  sleep 3
  echo "mf-minimal-default route is live."

  run_newman "Verifying minimal default-to-main config ..." \
    --folder "25 - LlmProvider: Minimal default-to-main config - baseline + failover" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-minimal-default.xml" \
    --color on || return 1

  # --- LlmProxy: model-keyed dispatch across additionalProviders aliases ---
  run_newman "Registering LlmProxy providers + mf-proxy-zerofb-test ..." \
    --folder "26 - LlmProxy: Register providers + zero-fallback dispatch proxy" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up mf-proxy-zerofb-test via xDS ..."
  wait_for_route "mf-proxy-zerofb-test/chat/completions" || { echo "route for 'mf-proxy-zerofb-test' never came up" >&2; return 1; }
  sleep 3
  echo "mf-proxy-zerofb-test route is live."

  run_newman "Running LlmProxy dispatch flow ..." \
    --folder "27 - LlmProxy: Model-keyed dispatch across provider aliases" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-llmproxy-dispatch.xml" \
    --color on || return 1

  # --- LlmProxy: zero-fallback default-to-main, no additionalProviders self-aliasing needed ---
  run_newman "Registering mf-proxy-default-test ..." \
    --folder "28 - LlmProxy: Zero-fallback default-to-main needs no additionalProviders" \
    --reporters cli --color on || return 1

  log "Waiting for gateway-runtime to pick up mf-proxy-default-test via xDS ..."
  wait_for_route "mf-proxy-default-test/chat/completions" || { echo "route for 'mf-proxy-default-test' never came up" >&2; return 1; }
  sleep 3
  echo "mf-proxy-default-test route is live."

  run_newman "Verifying default-to-main dispatch with no additionalProviders ..." \
    --folder "29 - LlmProxy: Verify default-to-main dispatch works with no additionalProviders" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-llmproxy-default-to-main.xml" \
    --color on || return 1

  run_newman "Running LlmProxy unsafe-config rejection ..." \
    --folder "30 - LlmProxy: Registration-time rejection of an unsafe loopback+fallback config" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-llmproxy-rejection.xml" \
    --color on || return 1

  run_newman "Running LlmProxy no-additionalProviders rejection ..." \
    --folder "31 - LlmProxy: Registration-time rejection when additionalProviders is absent entirely" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-llmproxy-no-additional-rejection.xml" \
    --color on || return 1

  run_newman "Running LlmProxy unsafe-default-to-main rejection ..." \
    --folder "32 - LlmProxy: Registration-time rejection when a fallback-having group defaults to main" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-llmproxy-unsafe-default-rejection.xml" \
    --color on || return 1

  run_newman "Cleaning up LlmProxy resources ..." \
    --folder "33 - LlmProxy: Cleanup" \
    --reporters cli --color on || return 1

  return 0
}

# ─── retry loop ──────────────────────────────────────────────────────────────

attempt=1
success=0
while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
  log "Attempt $attempt/$MAX_ATTEMPTS"
  if run_attempt; then
    success=1
    break
  fi
  echo "Attempt $attempt failed - cleaning up and retrying." >&2
  cleanup_all_registered_resources
  attempt=$((attempt + 1))
  sleep 2
done

if [ "$success" -ne 1 ]; then
  cleanup_all_registered_resources
  die "all $MAX_ATTEMPTS attempts failed - see output above for the actual assertion failures (this is likely a real regression, not just propagation timing, if it fails consistently)"
fi

log "All model-failover end-to-end flows passed (LlmProvider + LlmProxy)."
