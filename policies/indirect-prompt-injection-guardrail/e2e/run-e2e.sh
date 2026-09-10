#!/usr/bin/env bash
#
# One-command runner for the indirect-prompt-injection-guardrail policy's
# end-to-end suite (postman/indirect-prompt-injection-guardrail.postman_collection.json)
# against a gateway stack that is ALREADY running with the policy built in.
#
# This script does NOT build or start the gateway. If the policy is registered
# via `filePath:` / a fork gomodule that the running image predates, rebuild
# first:
#
#   cd gateway && (cd gateway-runtime && make build) && docker compose up -d
#
# What it does:
#   1. Sanity-checks the gateway stack is reachable.
#   2. Starts mock-echo-llm natively (go run) on a fixed port unless it's up.
#   3. Registers an LlmProvider + the LlmProxy variants the collection needs,
#      waits for xDS propagation.
#   4. Runs `newman run` against the collection.
#   5. Deletes every resource it registered and stops only the mock it started,
#      reporting a single pass/fail exit code.
#
# Env overrides:
#   CONTROLLER_ADMIN_URL   http://localhost:9094
#   CONTROLLER_BASE_URL    http://localhost:9090
#   GATEWAY_URL            https://localhost:8443
#   ECHO_LLM_MOCK_ADDR     :9751
#   NEWMAN_REPORTERS       cli,junit
#   MAX_REGISTER_ATTEMPTS  3
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTION="$ROOT/postman/indirect-prompt-injection-guardrail.postman_collection.json"
REPORT_DIR="$ROOT/postman/reports"
mkdir -p "$REPORT_DIR"

CONTROLLER_ADMIN_URL="${CONTROLLER_ADMIN_URL:-http://localhost:9094}"
CONTROLLER_BASE_URL="${CONTROLLER_BASE_URL:-http://localhost:9090}"
GATEWAY_URL="${GATEWAY_URL:-https://localhost:8443}"
ECHO_LLM_MOCK_ADDR="${ECHO_LLM_MOCK_ADDR:-:9751}"
NEWMAN_REPORTERS="${NEWMAN_REPORTERS:-cli,junit}"

ECHO_LLM_MOCK_PORT="${ECHO_LLM_MOCK_ADDR#:}"

log() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v go >/dev/null 2>&1 || die "go is required to run the mock server"

NEWMAN=(newman)
if ! command -v newman >/dev/null 2>&1; then
  command -v npx >/dev/null 2>&1 || die "neither 'newman' nor 'npx' found on PATH - install: npm i -g newman"
  NEWMAN=(npx --yes newman)
fi

log "Checking gateway-controller admin API at $CONTROLLER_ADMIN_URL ..."
curl -sf --max-time 5 "$CONTROLLER_ADMIN_URL/api/admin/v1/health" >/dev/null \
  || die "gateway-controller not reachable - start the stack first"
log "Checking gateway-runtime (Envoy) at $GATEWAY_URL ..."
curl -sk --max-time 5 "$GATEWAY_URL/" -o /dev/null \
  || die "gateway-runtime not reachable - start the stack first"

declare -a STARTED_PIDS=()
cleanup() {
  local ec=$?
  if [ "${#STARTED_PIDS[@]}" -gt 0 ]; then
    log "Stopping mock this script started (pids: ${STARTED_PIDS[*]}) ..."
    for pid in "${STARTED_PIDS[@]}"; do kill "$pid" >/dev/null 2>&1 || true; done
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
    [ "$tries" -le 0 ] && die "$name never became healthy at $url"
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
  (cd "$dir" && ADDR="$addr" go run . ) >"/tmp/${name}-ipi.log" 2>&1 &
  STARTED_PIDS+=("$!")
  wait_healthy "http://localhost:$port/healthz" "$name"
}

start_mock_if_needed "$ROOT/mocks/mock-echo-llm" "$ECHO_LLM_MOCK_ADDR" "$ECHO_LLM_MOCK_PORT" "mock-echo-llm"

REGISTERED_PROXIES=(ipi-block ipi-sanitize ipi-annotate ipi-response ipi-custom-paths ipi-threshold ipi-invalid)

cleanup_registered_resources() {
  for name in "${REGISTERED_PROXIES[@]}"; do
    curl -s --max-time 20 -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-proxies/$name" \
      -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
  done
  curl -s --max-time 25 -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-providers/ipi-e2e-provider" \
    -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
}
cleanup_registered_resources

# A 2xx from gateway-controller does not mean the route is live on
# gateway-runtime yet - xDS propagates asynchronously. Poll until the route
# answers with anything other than 404/000/500/503 (503 = "cluster not warm").
route_is_up() {
  local path="$1" code
  code=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' \
    -X POST "$GATEWAY_URL/$path" -H "Content-Type: application/json" -d '{}')
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

run_newman() {
  local label="$1"; shift
  log "$label"
  NODE_TLS_REJECT_UNAUTHORIZED=0 "${NEWMAN[@]}" run "$COLLECTION" \
    --env-var "controllerBaseUrl=${CONTROLLER_BASE_URL#http://}" \
    --env-var "controllerAdminUrl=${CONTROLLER_ADMIN_URL#http://}" \
    --env-var "gatewayBaseUrl=${GATEWAY_URL#https://}" \
    --env-var "echoLlmMockUrl=localhost:$ECHO_LLM_MOCK_PORT" \
    --env-var "echoLlmMockPort=$ECHO_LLM_MOCK_PORT" \
    --insecure --delay-request 200 --timeout-request 30000 \
    --reporters "$NEWMAN_REPORTERS" "$@"
}

OVERALL_EXIT=0
MAX_REGISTER_ATTEMPTS="${MAX_REGISTER_ATTEMPTS:-3}"
ALL_PROXY_CONTEXTS=(ipi-block ipi-sanitize ipi-annotate ipi-response ipi-custom-paths ipi-threshold)

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
  $attempt_ok && routes_ready=true
done
if ! $routes_ready; then
  echo "routes never came up cleanly after $MAX_REGISTER_ATTEMPTS attempts" >&2
  OVERALL_EXIT=1
fi
sleep 3

run_newman "Functional tests" \
  --folder "02 - Benign tool output passes through" \
  --folder "03 - Injection in tool message is blocked" \
  --folder "04 - User/system messages are not inspected" \
  --folder "05 - Sanitize rewrites the tool content" \
  --folder "06 - Annotate adds headers and forwards" \
  --folder "07 - Invisible unicode / exfil markup / delimiter detection" \
  --folder "08 - Custom RAG jsonPath is inspected" \
  --folder "09 - Response-phase inspection" \
  --folder "10 - severityThreshold requires two findings" \
  --folder "11 - Invalid config is accepted at registration but the route never comes up" \
  --folder "12 - Cleanup" \
  --reporter-junit-export "$REPORT_DIR/junit.xml" || OVERALL_EXIT=1

if [ "$OVERALL_EXIT" -eq 0 ]; then
  log "indirect-prompt-injection-guardrail e2e suite PASSED"
else
  log "indirect-prompt-injection-guardrail e2e suite FAILED (exit $OVERALL_EXIT)"
fi
exit "$OVERALL_EXIT"
