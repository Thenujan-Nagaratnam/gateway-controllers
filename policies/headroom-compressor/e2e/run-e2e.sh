#!/usr/bin/env bash
#
# One-command runner for the headroom-compressor policy's end-to-end test suite
# (postman/headroom-compressor.postman_collection.json) against a gateway stack
# that is ALREADY running with the headroom-compressor policy built in.
#
# This script does NOT build or start gateway-controller/gateway-runtime
# itself. Since headroom-compressor is registered in gateway/build.yaml via
# `filePath: ./dev-policies/headroom-compressor` (no published module tag
# yet), the gateway-runtime image must be rebuilt at least once to pick it
# up - and because it depends on the real `headroom-ai` PyPI package (a large
# dependency tree including litellm/boto3/tokenizers), that rebuild takes
# noticeably longer than a typical policy:
#
#   cd gateway && docker compose build gateway-runtime && docker compose up -d
#
# What it does:
#   1. Sanity-checks the gateway stack is reachable.
#   2. Starts mock-echo-llm natively (go run) on a fixed port, unless it's
#      already up.
#   3. Registers an LlmProvider (pointing at the mock) + two LlmProxy variants
#      (hc-main: compressUserMessages=false, hc-compress-user: true), waits
#      for xDS propagation.
#   4. Runs `newman run` against the collection (cli+junit reporters).
#   5. Deletes every resource it registered and stops only the mock process
#      THIS script started, reporting a single pass/fail exit code.
#
# Usage:
#   ./run-e2e.sh
#
# Env overrides:
#   CONTROLLER_ADMIN_URL   http://localhost:9094
#   CONTROLLER_BASE_URL    http://localhost:9090
#   GATEWAY_URL            https://localhost:8443
#   ECHO_LLM_MOCK_ADDR     :9741
#   NEWMAN_REPORTERS       cli,junit
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTION="$ROOT/postman/headroom-compressor.postman_collection.json"
REPORT_DIR="$ROOT/postman/reports"
mkdir -p "$REPORT_DIR"

CONTROLLER_ADMIN_URL="${CONTROLLER_ADMIN_URL:-http://localhost:9094}"
CONTROLLER_BASE_URL="${CONTROLLER_BASE_URL:-http://localhost:9090}"
GATEWAY_URL="${GATEWAY_URL:-https://localhost:8443}"
ECHO_LLM_MOCK_ADDR="${ECHO_LLM_MOCK_ADDR:-:9741}"
NEWMAN_REPORTERS="${NEWMAN_REPORTERS:-cli,junit}"

ECHO_LLM_MOCK_PORT="${ECHO_LLM_MOCK_ADDR#:}"

log() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# --- prerequisites -----------------------------------------------------------

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v go >/dev/null 2>&1 || die "go is required to run the mock server"

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
echo "headroom-compressor was added to build.yaml, LlmProxy registration below"
echo "will succeed but every request will 404/502 - rebuild first if that happens:"
echo "  cd gateway && docker compose build gateway-runtime && docker compose up -d"

# --- start the mock (skip if already running) --------------------------------

declare -a STARTED_PIDS=()

cleanup() {
  local ec=$?
  if [ "${#STARTED_PIDS[@]}" -gt 0 ]; then
    log "Stopping mock this script started (pids: ${STARTED_PIDS[*]}) ..."
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

start_mock_if_needed "$ROOT/mocks/mock-echo-llm" "$ECHO_LLM_MOCK_ADDR" "$ECHO_LLM_MOCK_PORT" "mock-echo-llm"

# --- run newman ----------------------------------------------------------

REGISTERED_PROXIES=(hc-main hc-compress-user)

cleanup_registered_resources() {
  for name in "${REGISTERED_PROXIES[@]}"; do
    curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-proxies/$name" \
      -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
  done
  curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-providers/headroom-compressor-e2e-provider" \
    -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
}

# Best-effort pre-clean in case a previous run left resources behind.
cleanup_registered_resources

log "Running newman against $COLLECTION ..."
# --insecure alone doesn't cover every TLS code path newman/Node exercises against
# the gateway's self-signed dev cert (some requests fail with "self-signed
# certificate ... try running Node.js with --use-system-ca" even with --insecure
# set) - NODE_TLS_REJECT_UNAUTHORIZED=0 is the blunt but reliable fix for local
# e2e runs against a self-signed cert.
NODE_TLS_REJECT_UNAUTHORIZED=0 "${NEWMAN[@]}" run "$COLLECTION" \
  --env-var "controllerBaseUrl=${CONTROLLER_BASE_URL#http://}" \
  --env-var "controllerAdminUrl=${CONTROLLER_ADMIN_URL#http://}" \
  --env-var "gatewayBaseUrl=${GATEWAY_URL#https://}" \
  --env-var "echoLlmMockUrl=localhost:$ECHO_LLM_MOCK_PORT" \
  --env-var "echoLlmMockPort=$ECHO_LLM_MOCK_PORT" \
  --insecure \
  --delay-request 200 \
  --timeout-request 30000 \
  --reporters "$NEWMAN_REPORTERS" \
  --reporter-junit-export "$REPORT_DIR/junit.xml"
NEWMAN_EXIT=$?

if [ "$NEWMAN_EXIT" -eq 0 ]; then
  log "headroom-compressor e2e suite PASSED"
else
  log "headroom-compressor e2e suite FAILED (exit $NEWMAN_EXIT)"
fi

exit "$NEWMAN_EXIT"
