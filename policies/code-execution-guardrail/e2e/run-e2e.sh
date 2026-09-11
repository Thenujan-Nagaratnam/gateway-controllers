#!/usr/bin/env bash
#
# One-command runner for the code-execution-guardrail e2e suite against a
# gateway stack ALREADY running with the policy built in (both gateway-runtime
# AND gateway-controller must have been rebuilt to pick up a new policy).
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTION="$ROOT/postman/code-execution-guardrail.postman_collection.json"
REPORT_DIR="$ROOT/postman/reports"
mkdir -p "$REPORT_DIR"

CONTROLLER_ADMIN_URL="${CONTROLLER_ADMIN_URL:-http://localhost:9094}"
CONTROLLER_BASE_URL="${CONTROLLER_BASE_URL:-http://localhost:9090}"
GATEWAY_URL="${GATEWAY_URL:-https://localhost:8443}"
MOCK_ADDR="${MOCK_ADDR:-:9763}"
NEWMAN_REPORTERS="${NEWMAN_REPORTERS:-cli,junit}"
MOCK_PORT="${MOCK_ADDR#:}"

log() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v go >/dev/null 2>&1 || die "go is required to run the mock"
NEWMAN=(newman)
command -v newman >/dev/null 2>&1 || { command -v npx >/dev/null 2>&1 || die "need newman or npx"; NEWMAN=(npx --yes newman); }

log "Checking gateway-controller at $CONTROLLER_ADMIN_URL ..."
curl -sf --max-time 5 "$CONTROLLER_ADMIN_URL/api/admin/v1/health" >/dev/null || die "gateway-controller not reachable"
log "Checking gateway-runtime at $GATEWAY_URL ..."
curl -sk --max-time 5 "$GATEWAY_URL/" -o /dev/null || die "gateway-runtime not reachable"

declare -a STARTED_PIDS=()
cleanup() {
  local ec=$?
  for pid in "${STARTED_PIDS[@]:-}"; do kill "$pid" >/dev/null 2>&1 || true; done
  [ "${#STARTED_PIDS[@]}" -gt 0 ] && wait "${STARTED_PIDS[@]}" 2>/dev/null || true
  cleanup_registered_resources
  exit $ec
}
trap cleanup EXIT INT TERM

wait_healthy() {
  local url="$1" name="$2" tries=30
  until curl -sf --max-time 1 "$url" >/dev/null 2>&1; do
    tries=$((tries-1)); [ "$tries" -le 0 ] && die "$name never healthy"; sleep 0.5
  done
}
if curl -sf --max-time 1 "http://localhost:$MOCK_PORT/healthz" >/dev/null 2>&1; then
  echo "mock-echo-llm already on :$MOCK_PORT, reusing."
else
  log "Starting mock-echo-llm on :$MOCK_PORT ..."
  (cd "$ROOT/mocks/mock-echo-llm" && ADDR="$MOCK_ADDR" go run . ) >/tmp/mock-echo-llm-codeexec.log 2>&1 &
  STARTED_PIDS+=("$!")
  wait_healthy "http://localhost:$MOCK_PORT/healthz" "mock-echo-llm"
fi

REGISTERED_PROXIES=(code-exec-block code-exec-annotate code-exec-invalid)
cleanup_registered_resources() {
  for n in "${REGISTERED_PROXIES[@]}"; do
    curl -s --max-time 20 -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-proxies/$n" -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
  done
  curl -s --max-time 25 -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-providers/codeexec-e2e-provider" -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
}
cleanup_registered_resources

route_is_up() {
  local code; code=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/$1" -H "Content-Type: application/json" -d '{}')
  [ "$code" != "404" ] && [ "$code" != "000" ] && [ "$code" != "500" ] && [ "$code" != "503" ]
}
wait_for_route() { local tries=120; until route_is_up "$1"; do tries=$((tries-1)); [ "$tries" -le 0 ] && return 1; sleep 0.5; done; }

run_newman() {
  local label="$1"; shift; log "$label"
  NODE_TLS_REJECT_UNAUTHORIZED=0 "${NEWMAN[@]}" run "$COLLECTION" \
    --env-var "controllerBaseUrl=${CONTROLLER_BASE_URL#http://}" \
    --env-var "controllerAdminUrl=${CONTROLLER_ADMIN_URL#http://}" \
    --env-var "gatewayBaseUrl=${GATEWAY_URL#https://}" \
    --env-var "mockUrl=localhost:$MOCK_PORT" --env-var "mockPort=$MOCK_PORT" \
    --insecure --delay-request 200 --timeout-request 30000 --reporters "$NEWMAN_REPORTERS" "$@"
}

OVERALL_EXIT=0
MAX_REGISTER_ATTEMPTS="${MAX_REGISTER_ATTEMPTS:-3}"
CTXS=(code-exec-block code-exec-annotate)
attempt=0; ready=false
until $ready || [ "$attempt" -ge "$MAX_REGISTER_ATTEMPTS" ]; do
  attempt=$((attempt+1))
  [ "$attempt" -gt 1 ] && { log "retry $attempt"; cleanup_registered_resources; sleep 2; }
  run_newman "Register (attempt $attempt)" --folder "00 - Health Checks" --folder "01 - Register" \
    --reporter-junit-export "$REPORT_DIR/junit-register.xml"
  ok=true
  for c in "${CTXS[@]}"; do wait_for_route "$c/mcp" || { echo "route $c never came up" >&2; ok=false; }; done
  $ok && ready=true
done
$ready || { echo "routes never came up" >&2; OVERALL_EXIT=1; }
sleep 3

run_newman "Functional tests" \
  --folder "02 - Benign code and non-matching tools pass" \
  --folder "03 - Dangerous code is blocked" \
  --folder "04 - onViolation annotate forwards to the backend with a header" \
  --folder "05 - Invalid config accepted at registration but the route never enforces" \
  --folder "06 - Cleanup" \
  --reporter-junit-export "$REPORT_DIR/junit.xml" || OVERALL_EXIT=1

if [ "$OVERALL_EXIT" -eq 0 ]; then log "code-execution-guardrail e2e suite PASSED"; else log "code-execution-guardrail e2e suite FAILED (exit $OVERALL_EXIT)"; fi
exit "$OVERALL_EXIT"
