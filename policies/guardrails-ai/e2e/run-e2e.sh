#!/usr/bin/env bash
#
# One-command runner for the guardrails-ai policy's end-to-end test suite
# (postman/guardrails-ai.postman_collection.json) against a gateway stack
# that is ALREADY running with the guardrails-ai policy built in.
#
# This script does NOT build or start gateway-controller/gateway-runtime
# itself. Since guardrails-ai is registered in gateway/build.yaml via
# `filePath: ./dev-policies/guardrails-ai` (no published module tag yet), the
# gateway-runtime image must be rebuilt at least once to pick it up:
#
#   cd gateway && docker compose build gateway-runtime && docker compose up -d
#
# What it does:
#   1. Sanity-checks the gateway stack is reachable.
#   2. Starts mock-guardrails-server and mock-echo-llm natively (go run) on
#      fixed ports, unless they're already up.
#   3. Registers the LlmProvider + six LlmProxy variants the collection needs
#      (see postman/guardrails-ai.postman_collection.json, folder "01 -
#      Register"), waits for xDS propagation.
#   4. Runs `newman run` against the collection (cli+junit reporters).
#   5. Deletes every resource it registered and stops only the mock
#      processes THIS script started, reporting a single pass/fail exit code.
#
# Usage:
#   ./run-e2e.sh
#
# Env overrides:
#   CONTROLLER_ADMIN_URL   http://localhost:9094
#   CONTROLLER_BASE_URL    http://localhost:9090
#   GATEWAY_URL            https://localhost:8443
#   GUARDRAILS_MOCK_ADDR   :9730
#   ECHO_LLM_MOCK_ADDR     :9731
#   NEWMAN_REPORTERS       cli,junit
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTION="$ROOT/postman/guardrails-ai.postman_collection.json"
REPORT_DIR="$ROOT/postman/reports"
mkdir -p "$REPORT_DIR"

CONTROLLER_ADMIN_URL="${CONTROLLER_ADMIN_URL:-http://localhost:9094}"
CONTROLLER_BASE_URL="${CONTROLLER_BASE_URL:-http://localhost:9090}"
GATEWAY_URL="${GATEWAY_URL:-https://localhost:8443}"
GUARDRAILS_MOCK_ADDR="${GUARDRAILS_MOCK_ADDR:-:9730}"
ECHO_LLM_MOCK_ADDR="${ECHO_LLM_MOCK_ADDR:-:9731}"
NEWMAN_REPORTERS="${NEWMAN_REPORTERS:-cli,junit}"

GUARDRAILS_MOCK_PORT="${GUARDRAILS_MOCK_ADDR#:}"
ECHO_LLM_MOCK_PORT="${ECHO_LLM_MOCK_ADDR#:}"

log() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# --- prerequisites -----------------------------------------------------------

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v go >/dev/null 2>&1 || die "go is required to run the mock servers"

NEWMAN=(newman)
if ! command -v newman >/dev/null 2>&1; then
  command -v npx >/dev/null 2>&1 || die "neither 'newman' nor 'npx' found on PATH - install newman: npm install -g newman"
  NEWMAN=(npx --yes newman)
fi

# --- verify the gateway stack is already up (this script never starts it) ---

log "Checking gateway-controller admin API at $CONTROLLER_ADMIN_URL ..."
curl -sf --max-time 5 "$CONTROLLER_ADMIN_URL/api/admin/v1/health" >/dev/null \
  || die "gateway-controller not reachable at $CONTROLLER_ADMIN_URL - start the stack first: cd gateway && docker compose build gateway-runtime && docker compose up -d"

log "Checking gateway-runtime (Envoy) at $GATEWAY_URL ..."
curl -sk --max-time 5 "$GATEWAY_URL/" -o /dev/null \
  || die "gateway-runtime not reachable at $GATEWAY_URL - start the stack first"

echo "Gateway stack looks up. NOTE: if gateway-runtime hasn't been rebuilt since"
echo "guardrails-ai was added to build.yaml, LlmProxy registration below will"
echo "succeed but every request will 404/502 - rebuild first if that happens:"
echo "  cd gateway && docker compose build gateway-runtime && docker compose up -d"

# --- start the mocks (skip any that's already running) -----------------------

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
  cleanup_registered_resources
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
  local dir="$1" addr="$2" port="$3" name="$4"
  if curl -sf --max-time 1 "http://localhost:$port/healthz" >/dev/null 2>&1; then
    echo "$name already running on :$port, reusing it."
    return
  fi
  log "Starting $name on :$port ..."
  (cd "$dir" && ADDR="$addr" go run . ) >"/tmp/${name}.log" 2>&1 &
  STARTED_PIDS+=("$!")
  wait_healthy "http://localhost:$port/healthz" "$name"
}

start_mock_if_needed "$ROOT/mocks/mock-guardrails-server" "$GUARDRAILS_MOCK_ADDR" "$GUARDRAILS_MOCK_PORT" "mock-guardrails-server"
start_mock_if_needed "$ROOT/mocks/mock-echo-llm" "$ECHO_LLM_MOCK_ADDR" "$ECHO_LLM_MOCK_PORT" "mock-echo-llm"

# --- run newman ----------------------------------------------------------

REGISTERED_PROXIES=(gr2-main gr2-response-only gr2-size-block gr2-size-passthrough gr2-timeout-block gr2-timeout-passthrough gr2-custom-jsonpath gr2-invalid-missing-guardname gr2-invalid-missing-endpoint)

cleanup_registered_resources() {
  for name in "${REGISTERED_PROXIES[@]}"; do
    curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-proxies/$name" \
      -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
  done
  curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-providers/guardrails-ai-e2e-provider" \
    -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
}

# Best-effort pre-clean in case a previous run left resources behind.
cleanup_registered_resources

# A successful registration (HTTP 2xx from gateway-controller) does not mean the
# route is live on gateway-runtime yet - that propagates asynchronously via xDS.
# Hitting the route immediately after registering is the classic "registration
# returns 201 before the route is live" gap (see model-failover/e2e's run-e2e.sh
# for the same pattern) - a request in that window gets an immediate 500/404 from
# Envoy, not a real policy-chain response. Poll until the route answers with
# anything other than 404/000 before running the folders that exercise it.
route_is_up() {
  local path="$1"
  local code
  code=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' \
    -X POST "$GATEWAY_URL/$path" \
    -H "Content-Type: application/json" -d '{}')
  # 503 is Envoy's "cluster not warm yet" response in the same brief window right
  # after registration - a route that answers 503 is not actually ready either,
  # even though it's no longer 404. Treating 503 as "up" here was the root cause
  # of intermittent early-test failures in the real automated run.
  [ "$code" != "404" ] && [ "$code" != "000" ] && [ "$code" != "500" ] && [ "$code" != "503" ]
}

wait_for_route() {
  local path="$1" tries=120
  until route_is_up "$path"; do
    tries=$((tries - 1))
    [ "$tries" -le 0 ] && return 1
    sleep 0.5
  done
  return 0
}

# --insecure alone doesn't cover every TLS code path newman/Node exercises against
# the gateway's self-signed dev cert (some requests fail with "self-signed
# certificate ... try running Node.js with --use-system-ca" even with --insecure
# set) - NODE_TLS_REJECT_UNAUTHORIZED=0 is the blunt but reliable fix for local
# e2e runs against a self-signed cert.
run_newman() {
  local label="$1"; shift
  log "$label"
  NODE_TLS_REJECT_UNAUTHORIZED=0 "${NEWMAN[@]}" run "$COLLECTION" \
    --env-var "controllerBaseUrl=${CONTROLLER_BASE_URL#http://}" \
    --env-var "controllerAdminUrl=${CONTROLLER_ADMIN_URL#http://}" \
    --env-var "gatewayBaseUrl=${GATEWAY_URL#https://}" \
    --env-var "guardrailsMockUrl=localhost:$GUARDRAILS_MOCK_PORT" \
    --env-var "echoLlmMockUrl=localhost:$ECHO_LLM_MOCK_PORT" \
    --insecure \
    --delay-request 200 \
    --timeout-request 30000 \
    --reporters "$NEWMAN_REPORTERS" \
    "$@"
}

OVERALL_EXIT=0
MAX_REGISTER_ATTEMPTS="${MAX_REGISTER_ATTEMPTS:-3}"

# Registering several LlmProxies against gateway-controller in quick succession
# has been observed to occasionally race the xDS snapshot pipeline, leaving one
# or more routes permanently answering "Policy chain not found for route,
# returning 500" even though the registration itself (HTTP 2xx) succeeded and a
# single isolated registration comes up instantly. This has been seen to
# self-heal on a clean re-registration, so retry the whole register+wait cycle
# a bounded number of times rather than treating one bad attempt as a real
# failure (the same shape of environment flake model-failover/e2e's run-e2e.sh
# retries for, not a policy bug).
ALL_PROXY_CONTEXTS=(gr2-main gr2-response-only gr2-size-block gr2-size-passthrough gr2-timeout-block gr2-timeout-passthrough gr2-custom-jsonpath)

register_attempt=0
routes_ready=false
until $routes_ready || [ "$register_attempt" -ge "$MAX_REGISTER_ATTEMPTS" ]; do
  register_attempt=$((register_attempt + 1))
  if [ "$register_attempt" -gt 1 ]; then
    log "Registration attempt $register_attempt/$MAX_REGISTER_ATTEMPTS - cleaning up and retrying ..."
    cleanup_registered_resources
    sleep 2
  fi

  run_newman "Register (attempt $register_attempt)" --folder "00 - Health Checks" --folder "01 - Register" \
    --reporter-junit-export "$REPORT_DIR/junit-register.xml"

  log "Waiting for gateway-runtime to pick up the registered proxies via xDS ..."
  attempt_ok=true
  for ctx in "${ALL_PROXY_CONTEXTS[@]}"; do
    wait_for_route "$ctx/chat/completions" || { echo "route for '$ctx' never came up (attempt $register_attempt)" >&2; attempt_ok=false; }
  done
  if $attempt_ok; then
    routes_ready=true
  fi
done

if ! $routes_ready; then
  echo "routes never came up cleanly after $MAX_REGISTER_ATTEMPTS attempts" >&2
  OVERALL_EXIT=1
fi

# Policy-chain build is a separate, slightly-lagging xDS channel from route
# existence itself - a short fixed wait covers the gap (no cheap readiness
# signal for that second channel, same as model-failover's run-e2e.sh).
sleep 3

run_newman "Functional tests" \
  --folder "02 - Request phase: pass-through" \
  --folder "03 - Request phase: block + showAssessment" \
  --folder "04 - Response phase: pass-through and block" \
  --folder "05 - Guardrails response exceeds maxResponseBytes" \
  --folder "06 - Guardrail service slow or erroring" \
  --folder "07 - Custom jsonPath extraction" \
  --folder "08 - Invalid config is accepted at registration but the route never comes up" \
  --folder "09 - Cleanup" \
  --reporter-junit-export "$REPORT_DIR/junit.xml" || OVERALL_EXIT=1

NEWMAN_EXIT=$OVERALL_EXIT

if [ "$NEWMAN_EXIT" -eq 0 ]; then
  log "guardrails-ai e2e suite PASSED"
else
  log "guardrails-ai e2e suite FAILED (exit $NEWMAN_EXIT)"
fi

exit "$NEWMAN_EXIT"
