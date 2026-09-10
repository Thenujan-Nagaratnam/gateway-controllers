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

# A successful registration (HTTP 2xx from gateway-controller) does not mean the
# route is live on gateway-runtime yet - that propagates asynchronously via xDS,
# and even after the route itself answers, the upstream cluster can still return
# 503 for a brief warm-up window. Poll until the route answers with anything
# other than 404/000/500/503 before running the folders that exercise it (see
# guardrails-ai/byo-guardrail's run-e2e.sh for the same pattern).
route_is_up() {
  local path="$1"
  local code
  code=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' \
    -X POST "$GATEWAY_URL/$path" \
    -H "Content-Type: application/json" -d '{}')
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
    --env-var "echoLlmMockUrl=localhost:$ECHO_LLM_MOCK_PORT" \
    --env-var "echoLlmMockPort=$ECHO_LLM_MOCK_PORT" \
    --insecure \
    --delay-request 200 \
    --timeout-request 30000 \
    --reporters "$NEWMAN_REPORTERS" \
    "$@"
}

OVERALL_EXIT=0
MAX_REGISTER_ATTEMPTS="${MAX_REGISTER_ATTEMPTS:-3}"
ALL_PROXY_CONTEXTS=(hc-main hc-compress-user)

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

sleep 3

# Prime each Python policy instance with a few small real requests before the
# functional folders run. The first request through a freshly-created
# headroom-compressor instance pays a one-time cost - loading the tiktoken vocab
# (which can hit its ~10s load timeout in an offline environment and fall back to
# token estimation) and completing Headroom's ContentRouter first-call init -
# during which the router is measurably more conservative. Without this, folder
# 02/05's first request lands on a cold instance and its "was compressed"
# assertion can flake. The wait_for_route probes above don't prime it: they send
# an empty body, so the policy returns before Headroom is ever invoked. These
# priming requests are deliberately small and NOT the compressible payload the
# folders check - just enough to get the instance past first-call init.
prime_route() {  # $1 = gateway context
  local ctx="$1" i
  for i in 1 2 3 4; do
    curl -sk --max-time 30 -o /dev/null -X POST "$GATEWAY_URL/$ctx/chat/completions" \
      -H "Content-Type: application/json" \
      -d '{"model":"gpt-4o","messages":[{"role":"user","content":"warming the tokenizer with a normal-length sentence"},{"role":"assistant","content":"ready"},{"role":"user","content":"go ahead"}]}' || true
  done
}
for ctx in "${ALL_PROXY_CONTEXTS[@]}"; do
  log "Priming Headroom policy instance for '$ctx' ..."
  prime_route "$ctx"
done
sleep 5

run_newman "Functional tests" \
  --folder "02 - Old repetitive message gets compressed, recent ones untouched" \
  --folder "03 - Short ordinary message is left unchanged" \
  --folder "04 - No model available anywhere skips compression entirely" \
  --folder "05 - compressUserMessages true vs false" \
  --folder "06 - Malformed JSON body still passes through" \
  --folder "07 - Response body is never modified (request-only policy)" \
  --folder "08 - Cleanup" \
  --reporter-junit-export "$REPORT_DIR/junit.xml" || OVERALL_EXIT=1

NEWMAN_EXIT=$OVERALL_EXIT

if [ "$NEWMAN_EXIT" -eq 0 ]; then
  log "headroom-compressor e2e suite PASSED"
else
  log "headroom-compressor e2e suite FAILED (exit $NEWMAN_EXIT)"
fi

exit "$NEWMAN_EXIT"
