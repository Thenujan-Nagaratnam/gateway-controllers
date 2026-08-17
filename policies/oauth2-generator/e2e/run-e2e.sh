#!/usr/bin/env bash
#
# One-command runner for the oauth2 policy's end-to-end test suite
# (TESTING.md / postman/oauth2.postman_collection.json) against a gateway
# stack that is ALREADY running (see TESTING.md Parts B/C - this script does
# not build or start gateway-controller/gateway-runtime itself).
#
# What it does:
#   1. Sanity-checks the gateway stack is reachable.
#   2. Starts mock-oauth2-idp and mock-ai-backend natively (go run), unless
#      they're already up - matching TESTING.md Part A.
#   3. Registers the test LlmProviders, waits for gateway-runtime to actually
#      pick up the new routes via xDS (registering returns 201 as soon as
#      gateway-controller persists it, but the route only becomes reachable
#      once an async xDS push lands - observed to take anywhere from well
#      under a second up to several seconds under load), then runs the E.1-
#      E.9b flows, recreates the one provider whose test needs a guaranteed-
#      empty cache, and runs E.11 onward plus the Redis cache check and
#      cleanup. See run_attempt() below for exactly why it's split this way.
#   4. Retries the whole register-through-cleanup cycle (with a full
#      teardown in between) a few times if xDS propagation didn't land in
#      time anywhere in the pipeline - a transient-infrastructure-timing
#      condition, not a policy bug, so retrying is the honest response
#      rather than papering over it with an ever-larger fixed sleep.
#   5. Tears down only the mock processes THIS script started, and reports
#      a single pass/fail exit code for the whole suite.
#
# Usage:
#   ./run-e2e.sh                       # everything: oauth2 + model-failover + advanced-ratelimit
#   ./run-e2e.sh --oauth2              # only this policy's own E.1-E.34 suite (+ E.33 if opted in)
#   ./run-e2e.sh --model-failover      # only dev-policies/model-failover/e2e/run-e2e.sh, chained
#   ./run-e2e.sh --oauth2 --model-failover   # both of the above, skipping advanced-ratelimit
#
# Passing ANY selector flag switches this script from "run everything" to
# "run only what was explicitly selected" - advanced-ratelimit's chained
# suite (which isn't its own flag, see the bottom of this script) only runs
# in the no-flags "everything" mode, matching how it was silently chained in
# before these flags existed.
#
# Env overrides (defaults match TESTING.md / the Postman collection):
#   CONTROLLER_ADMIN_URL   http://localhost:9094
#   CONTROLLER_BASE_URL    http://localhost:9090
#   GATEWAY_URL            https://localhost:8443
#   IDP_ADDR               :9601
#   BACKEND_ADDR           :9602
#   PROXY_ADDR             :9603       (mock-forward-proxy, used only by E.26)
#   COMBINED_PRIMARY_ADDR  :9604       (dedicated mock-ai-backend instance for E.35's
#                                       model-failover primary target - never shared
#                                       with BACKEND_ADDR)
#   COMBINED_FALLBACK_ADDR :9605       (dedicated mock-ai-backend instance for E.35's
#                                       model-failover fallback target)
#   TLS_IDP_ADDR           :9611       (mock-oauth2-idp's TLS instance, used only by E.27 -
#                                       requires the /etc/gateway/certs bind mount in
#                                       docker-compose.yaml; recreate gateway-runtime if it
#                                       predates that mount)
#   NEWMAN_REPORTERS       cli,junit
#   MAX_ATTEMPTS           3
#   RUN_REALWORLD_TEST     0           (set to 1 to also run E.33 - hits a
#                                        real external IdP over the internet
#                                        using a real shared credential, so
#                                        it's off by default; see E.33's own
#                                        section near the end of this script)
#   REDIS_HOST             localhost   (used only to flush stale cached
#   REDIS_PORT             6379         tokens between runs/attempts - see
#   REDIS_KEY_PREFIX       oauth2-generator:token:v1:   flush_redis_cache(); skipped
#                          entirely, with a warning, if redis-cli isn't on
#                          PATH)
#
set -uo pipefail

# ─── suite selection ─────────────────────────────────────────────────────────
#
# No selector flag at all = "everything" (RUN_OAUTH2, RUN_MODEL_FAILOVER, and
# RUN_ADVANCED_RATELIMIT all on) - the historical default behavior, unchanged.
# Passing --oauth2 and/or --model-failover switches to "only what was named" -
# advanced-ratelimit has no flag of its own (it was always just chained on
# for convenience, not a suite this script owns), so it's excluded the moment
# any selector is given.
RUN_OAUTH2=1
RUN_MODEL_FAILOVER=1
RUN_ADVANCED_RATELIMIT=1
any_selector_given=0
for arg in "$@"; do
  case "$arg" in
    --oauth2)
      if [ "$any_selector_given" -eq 0 ]; then RUN_OAUTH2=0; RUN_MODEL_FAILOVER=0; RUN_ADVANCED_RATELIMIT=0; any_selector_given=1; fi
      RUN_OAUTH2=1
      ;;
    --model-failover)
      if [ "$any_selector_given" -eq 0 ]; then RUN_OAUTH2=0; RUN_MODEL_FAILOVER=0; RUN_ADVANCED_RATELIMIT=0; any_selector_given=1; fi
      RUN_MODEL_FAILOVER=1
      ;;
    -h|--help)
      grep '^#' "${BASH_SOURCE[0]}" | sed '1d'
      exit 0
      ;;
    *)
      echo "ERROR: unrecognized argument '$arg' (expected --oauth2 and/or --model-failover)" >&2
      exit 1
      ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTION="$ROOT/postman/oauth2.postman_collection.json"
REPORT_DIR="$ROOT/postman/reports"

CONTROLLER_ADMIN_URL="${CONTROLLER_ADMIN_URL:-http://localhost:9094}"
CONTROLLER_BASE_URL="${CONTROLLER_BASE_URL:-http://localhost:9090}"
GATEWAY_URL="${GATEWAY_URL:-https://localhost:8443}"
# gateway-runtime's Envoy admin API (config_dump) - used only to check route
# existence without sending real traffic through it. See
# route_exists_in_admin() for why a functional probe can't be used for
# LlmProxy resources with valid oauth2 credentials.
RUNTIME_ADMIN_URL="${RUNTIME_ADMIN_URL:-http://localhost:9901}"
IDP_ADDR="${IDP_ADDR:-:9601}"
BACKEND_ADDR="${BACKEND_ADDR:-:9602}"
PROXY_ADDR="${PROXY_ADDR:-:9603}"
COMBINED_PRIMARY_ADDR="${COMBINED_PRIMARY_ADDR:-:9604}"
COMBINED_FALLBACK_ADDR="${COMBINED_FALLBACK_ADDR:-:9605}"
# TLS_IDP_ADDR is a second, TLS-enabled mock-oauth2-idp instance for E.27
# (tlsCaCertPath/tlsInsecureSkipVerify) - a separate process/port from
# IDP_ADDR rather than switching that one to HTTPS, so every other flow
# keeps using plain HTTP unaffected. See generate_tls_idp_cert().
TLS_IDP_ADDR="${TLS_IDP_ADDR:-:9611}"
NEWMAN_REPORTERS="${NEWMAN_REPORTERS:-cli,junit}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"

IDP_PORT="${IDP_ADDR#:}"
BACKEND_PORT="${BACKEND_ADDR#:}"
PROXY_PORT="${PROXY_ADDR#:}"
TLS_IDP_PORT="${TLS_IDP_ADDR#:}"
COMBINED_PRIMARY_PORT="${COMBINED_PRIMARY_ADDR#:}"
COMBINED_FALLBACK_PORT="${COMBINED_FALLBACK_ADDR#:}"

log() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

if [ "$RUN_OAUTH2" -eq 1 ]; then

# ─── prerequisites ───────────────────────────────────────────────────────────

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v go >/dev/null 2>&1 || die "go is required to run the mock servers"
command -v python3 >/dev/null 2>&1 || die "python3 is required (used to read request bodies out of the Postman collection)"
command -v lsof >/dev/null 2>&1 || die "lsof is required (used to find and restart a stale TLS mock instance - see stop_process_on_port())"

NEWMAN=(newman)
if ! command -v newman >/dev/null 2>&1; then
  command -v npx >/dev/null 2>&1 || die "neither 'newman' nor 'npx' found on PATH - install newman: npm install -g newman"
  NEWMAN=(npx --yes newman)
fi

# ─── verify the gateway stack is already up (this script never starts it) ───

log "Checking gateway-controller admin API at $CONTROLLER_ADMIN_URL ..."
curl -sf --max-time 5 "$CONTROLLER_ADMIN_URL/api/admin/v1/health" >/dev/null \
  || die "gateway-controller not reachable at $CONTROLLER_ADMIN_URL - start the stack first (TESTING.md Part C: docker compose up -d gateway-controller gateway-runtime sample-backend redis)"

log "Checking gateway-runtime (Envoy) at $GATEWAY_URL ..."
curl -sk --max-time 5 "$GATEWAY_URL/" -o /dev/null \
  || die "gateway-runtime not reachable at $GATEWAY_URL - start the stack first (TESTING.md Part C)"

echo "Gateway stack looks up."

# ─── start the mocks (skip any that are already running) ───────────────────

declare -a STARTED_PIDS=()

# Registered before either mock is started (not after): if the first mock
# starts but the second then fails wait_healthy's die() below, the first
# mock's PID is already in STARTED_PIDS and must still be cleaned up on this
# exit - which only happens if the trap is already armed by that point.
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
  # -k: harmless no-op for plain HTTP, and required for the TLS mock's
  # self-signed cert (verification is exactly what E.27 tests, not what
  # this readiness probe needs to enforce).
  until curl -sfk --max-time 1 "$url" >/dev/null 2>&1; do
    tries=$((tries - 1))
    if [ "$tries" -le 0 ]; then
      die "$name never became healthy at $url"
    fi
    sleep 0.5
  done
}

# start_mock_if_needed's 5th arg (extra_env, optional) is space-separated
# VAR=value pairs prepended to the `go run .` invocation - used to switch
# mock-oauth2-idp's second instance to HTTPS via TLS_CERT_FILE/TLS_KEY_FILE.
start_mock_if_needed() {
  local healthz_url="$1" dir="$2" addr_env_val="$3" label="$4" extra_env="${5:-}"
  if curl -sfk --max-time 1 "$healthz_url" >/dev/null 2>&1; then
    echo "$label already running at $healthz_url - reusing it."
    return
  fi
  log "Starting $label ..."
  (cd "$dir" && eval "GOWORK=off ADDR=\"$addr_env_val\" $extra_env exec go run .") \
    >"$REPORT_DIR/$(basename "$dir")-$(echo "$addr_env_val" | tr -d ':').log" 2>&1 &
  STARTED_PIDS+=("$!")
  wait_healthy "$healthz_url" "$label"
  echo "$label is up (pid $!)."
}

# generate_tls_idp_cert (re)creates a short-lived self-signed cert for
# mock-oauth2-idp's TLS instance, directly in its own directory - which
# gateway-runtime has bind-mounted read-only at /etc/gateway/certs (see
# docker-compose.yaml), so the cert becomes visible there immediately, live,
# with no container restart needed regardless of generation order.
# SAN covers host.docker.internal since that's the hostname gateway-runtime
# (inside its container) uses to reach this mock. The FILE is regenerated on
# every run - but the PROCESS serving it is not restarted just by writing a
# new file (a live Go process keeps whatever cert it loaded at its own
# startup, in memory, indefinitely). If a TLS mock instance from an earlier
# run is still alive and healthy, start_mock_if_needed's generic reuse check
# would happily leave it running with its OLD cert while this function
# overwrites the file out from under it - gateway-runtime (reading the fresh
# file) and the mock (serving the stale in-memory one) then disagree, and
# E.27 fails with a confusing "certificate signed by unknown authority"
# every time this happens. See stop_process_on_port() - the TLS instance is
# always force-restarted, never reused, specifically because of this.
generate_tls_idp_cert() {
  local dir="$ROOT/mocks/mock-oauth2-idp"
  log "Generating mock-oauth2-idp's TLS cert (E.27) ..."
  # basicConstraints=CA:TRUE + keyUsage=keyCertSign are required because this
  # same file is used BOTH as mock-oauth2-idp's TLS server cert AND as the CA
  # oauth2-test-tlscacert's tlsCaCertPath trusts - without them, modern
  # openssl (3.x) omits the CA basic constraint by default on a plain -x509
  # self-signed cert, and Go's x509 verifier then rejects it with "parent
  # certificate cannot sign this kind of certificate" even though it IS the
  # exact cert being presented (confirmed live: this was silently broken
  # before adding these two extensions).
  openssl req -x509 -newkey rsa:2048 -keyout "$dir/mock-idp-ca.key" -out "$dir/mock-idp-ca.crt" \
    -days 1 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:host.docker.internal" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,digitalSignature" \
    >"$REPORT_DIR/tls-cert-gen.log" 2>&1 \
    || die "failed to generate mock-oauth2-idp's TLS cert - is openssl installed? see $REPORT_DIR/tls-cert-gen.log"
}

mkdir -p "$REPORT_DIR"

# stop_process_on_port kills whatever is listening on $1, if anything - used
# only for the TLS mock instance (see generate_tls_idp_cert's comment): that
# one process must never be silently reused across runs, because the cert
# file underneath it is unconditionally rewritten every run. Not started via
# STARTED_PIDS/cleanup() - this targets a leftover from a PRIOR invocation of
# this script, not something this run itself is responsible for tearing down.
stop_process_on_port() {
  local port="$1" pid
  pid=$(lsof -ti "tcp:${port}" 2>/dev/null || true)
  if [ -n "$pid" ]; then
    log "Stopping stale process on port ${port} (pid ${pid}) so it can't serve an outdated TLS cert ..."
    kill -9 $pid 2>/dev/null || true
    sleep 0.5
  fi
}

start_mock_if_needed "http://localhost:${IDP_PORT}/healthz" \
  "$ROOT/mocks/mock-oauth2-idp" "$IDP_ADDR" "mock-oauth2-idp"

start_mock_if_needed "http://localhost:${BACKEND_PORT}/healthz" \
  "$ROOT/mocks/mock-ai-backend" "$BACKEND_ADDR" "mock-ai-backend"

start_mock_if_needed "http://localhost:${PROXY_PORT}/healthz" \
  "$ROOT/mocks/mock-forward-proxy" "$PROXY_ADDR" "mock-forward-proxy"

# Two more instances of mock-ai-backend, dedicated to E.35's model-failover
# primary/fallback targets - never shared with BACKEND_ADDR (:9602, used by
# every other flow), so E.35's force-status/revoke-token/last-request calls
# can never cross-contaminate any other flow's backend state.
start_mock_if_needed "http://localhost:${COMBINED_PRIMARY_PORT}/healthz" \
  "$ROOT/mocks/mock-ai-backend" "$COMBINED_PRIMARY_ADDR" "mock-ai-backend (E.35 primary)"

start_mock_if_needed "http://localhost:${COMBINED_FALLBACK_PORT}/healthz" \
  "$ROOT/mocks/mock-ai-backend" "$COMBINED_FALLBACK_ADDR" "mock-ai-backend (E.35 fallback)"

# The TLS instance's own healthz check must go over HTTPS too (-k: it's a
# self-signed cert, verification is exactly what E.27 tests, not what this
# readiness probe needs to enforce) - a plain http:// probe would always 404
# à la wrong scheme, never reporting healthy.
stop_process_on_port "$TLS_IDP_PORT"
generate_tls_idp_cert
start_mock_if_needed "https://localhost:${TLS_IDP_PORT}/healthz" \
  "$ROOT/mocks/mock-oauth2-idp" "$TLS_IDP_ADDR" "mock-oauth2-idp (TLS)" \
  "TLS_CERT_FILE=./mock-idp-ca.crt TLS_KEY_FILE=./mock-idp-ca.key"

fi # RUN_OAUTH2 (prerequisites, stack check, mock startup)

# ─── shared state ────────────────────────────────────────────────────────────

PROVIDER_NAMES=(
  # oauth2-test-basic-clone no longer exists as a registration - repurposed
  # into oauth2-test-rediscache-clone below (see that entry's comment).
  oauth2-test-basic oauth2-test-shortttl oauth2-test-badsecret
  oauth2-test-unreachable oauth2-test-malformed oauth2-test-password
  oauth2-test-password-wrong oauth2-test-clientauthpost oauth2-test-timeout
  oauth2-test-defaultttl oauth2-test-purge oauth2-test-purge-disabled
  oauth2-test-password-scope oauth2-test-proxy-backend oauth2-test-proxy-backend-ownauth
  oauth2-test-proxy-backend-ownauth2
  # oauth2-test-rediscache-clone (E.14) - byte-identical policyParams to
  # oauth2-test-rediscache (including cacheStrategy: redis), different API.
  # E.14 needs this, not oauth2-test-basic/-clone: cross-API cache sharing
  # only ever works through the Redis tier, never the in-process one (each
  # GetPolicy() call gets its own fresh in-process cache, regardless of how
  # identical the config is) - oauth2-test-basic/-clone deliberately stay on
  # the memory default (E.1/E.2 test that default), so they can never
  # demonstrate cross-API sharing no matter how identical their config is.
  oauth2-test-rediscache oauth2-test-rediscache-clone oauth2-test-bearertoken oauth2-test-customheader
  oauth2-test-tokenreqheaders oauth2-test-retries oauth2-test-proxyurl
  # oauth2-test-badgrant (E.8) DOES get created (201) despite its invalid
  # grantType - gateway-controller never validates policyParams' contents,
  # only oauth2-generator's own GetPolicy rejects it, asynchronously, when
  # policy-engine tries to build this route's policy chain. Must be cleaned
  # up like any other provider, or a retry hits "configuration already
  # exists" instead of re-registering cleanly.
  oauth2-test-badgrant
  # E.27-E.31 additions.
  oauth2-test-purge-custom oauth2-test-redis-failopen oauth2-test-redis-failclosed
  oauth2-test-customheader-prefix oauth2-test-tlscacert oauth2-test-tlsinsecure
  oauth2-test-tlsuntrusted
  # E.32 addition.
  oauth2-test-expirybuffer
  # E.34 addition.
  oauth2-test-retry-refresh
  # E.35 addition.
  oauth2-test-mf-combined
)

# LlmProxy resources use a separate REST path (/llm-proxies, not
# /llm-providers) so they need their own delete helper - see
# delete_registered_proxies().
PROXY_NAMES=(
  oauth2-test-proxy oauth2-test-proxy-hop2only oauth2-test-proxy-bothauth
)

# Mcp resources use their own REST path (/mcp-proxies, not /llm-providers or
# /llm-proxies) so they need their own delete helper - see
# delete_registered_mcps().
MCP_NAMES=(
  mcp-test-oauth2
)

# Probing a route is the only way to tell "not live yet" apart from "live,
# but access-control denies this request" - both 404 identically, by design
# (the deny-all policy must not reveal route existence any more to a prober
# than to an attacker). For most of the 10 providers that's harmless: their
# configured credentials are deliberately wrong, or their token endpoint is
# unreachable/hung, so the oauth2 policy's fetch fails before anything gets
# cached (only a *successful* fetch is ever written to the cache - see
# token_cache.go's Token()). The other 5 (basic/shortttl/password/
# clientauthpost/defaultttl) have valid credentials, so probing them directly
# would cache a real token before any test flow runs - harmless for flows
# that just count IdP calls after their own reset (0 or 1 calls both prove
# caching works), but E.11 specifically needs a guaranteed-fresh IdP call for
# its own request, which a probe-warmed cache would silently skip. So: only
# probe the 5 where that's inherently safe, and separately force a clean
# cache for the one provider (clientauthpost) whose test actually depends on
# it - see the E.11 handling in run_attempt().
SAFE_TO_PROBE_NAMES=(
  oauth2-test-badsecret oauth2-test-unreachable oauth2-test-malformed
  oauth2-test-password-wrong oauth2-test-timeout
)

delete_registered_providers() {
  for name in "${PROVIDER_NAMES[@]}"; do
    curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-providers/$name" \
      -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
  done
}

# Proxies are deleted before delete_registered_providers runs (see callers) -
# oauth2-test-proxy references oauth2-test-proxy-backend by id, so deleting
# the provider first would leave a dangling reference if that's enforced.
delete_registered_proxies() {
  for name in "${PROXY_NAMES[@]}"; do
    curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-proxies/$name" \
      -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
  done
}

delete_registered_mcps() {
  for name in "${MCP_NAMES[@]}"; do
    curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/mcp-proxies/$name" \
      -H "Authorization: Basic YWRtaW46YWRtaW4=" || true
  done
}

# Prints the request body of a named Postman collection item to stdout. Used
# to recreate oauth2-test-clientauthpost from the collection's own "Register:
# ..." body (see run_attempt()) instead of a second, hand-maintained copy of
# that YAML that could silently drift from the real one.
collection_request_body() {
  local request_name="$1"
  python3 -c "
import json, sys
d = json.load(open('$COLLECTION'))
def find(items, name):
    for it in items:
        if it.get('name') == name:
            return it
        if 'item' in it:
            r = find(it['item'], name)
            if r:
                return r
    return None
it = find(d['item'], sys.argv[1])
if it is None:
    sys.exit('request not found in collection: ' + sys.argv[1])
sys.stdout.write(it['request']['body']['raw'])
" "$request_name"
}

flush_redis_cache() {
  local host="${REDIS_HOST:-localhost}" port="${REDIS_PORT:-6379}" prefix="${REDIS_KEY_PREFIX:-oauth2-generator:token:v1:}"
  if ! command -v redis-cli >/dev/null 2>&1; then
    echo "WARNING: redis-cli not found - skipping the cache flush. If the Redis profile is in use, a stale token from a previous run/attempt may cause a flow that expects a fresh IdP call to see a cache hit instead." >&2
    return 0
  fi
  local keys
  keys=$(redis-cli -h "$host" -p "$port" --scan --pattern "${prefix}*" 2>/dev/null || true)
  [ -n "$keys" ] && echo "$keys" | xargs -I{} redis-cli -h "$host" -p "$port" DEL "{}" >/dev/null
  return 0
}

route_is_up() {
  local name="$1" code
  code=$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' \
    -X POST "$GATEWAY_URL/$name/latest/chat/completions" \
    -H "Content-Type: application/json" -d '{}')
  # "000" is curl's %{http_code} for "no HTTP response at all" (connection
  # refused/reset/timed out) - e.g. if gateway-runtime became unreachable
  # after the earlier startup check. That must NOT be treated the same as a
  # real, live non-404 response - only "not 404" was checked here before,
  # which would have falsely reported the route as up in exactly that case.
  [ "$code" != "404" ] && [ "$code" != "000" ]
}

wait_for_route() {
  local name="$1"
  local tries="$2"
  until route_is_up "$name"; do
    tries=$((tries - 1))
    [ "$tries" -le 0 ] && return 1
    sleep 0.5
  done
  return 0
}

# route_exists_in_admin checks gateway-runtime's actual live route table (via
# Envoy's admin config_dump, not a real traffic request) for a route whose
# path regex contains the given path fragment. Unlike route_is_up, this never
# sends a request through the route - required for LlmProxy/Mcp resources
# with VALID oauth2 credentials (route_is_up's probe would fetch and cache a
# real token, silently invalidating any later "exactly N token requests"
# assertion). path_fragment is context-shaped, e.g. "<name>/latest" for
# LlmProxy or "<name>/mcp" for Mcp (Mcp contexts have no "/latest" version
# segment convention). Requires python3 (already a hard dependency of this
# script - see collection_request_body()).
route_exists_in_admin() {
  local path_fragment="$1"
  curl -s --max-time 5 "$RUNTIME_ADMIN_URL/config_dump?resource=dynamic_route_configs" 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
pattern = '/' + sys.argv[1]
for cfg in d.get('configs', []):
    for vh in cfg.get('route_config', {}).get('virtual_hosts', []):
        for r in vh.get('routes', []):
            regex = r.get('match', {}).get('safe_regex', {}).get('regex', '')
            if pattern in regex:
                sys.exit(0)
sys.exit(1)
" "$path_fragment"
}

# wait_for_proxy_routes_via_admin waits for every name in PROXY_NAMES to show
# up in gateway-runtime's live route table (see route_exists_in_admin), and
# recovers from a real, observed gateway-controller bug: when multiple
# LlmProxy resources are created in rapid succession (the same newman folder
# posting all of PROXY_NAMES back to back), only the first one's route
# reliably reaches gateway-runtime - the rest can be dropped from whatever
# xDS snapshot actually gets applied and never come up on their own, even
# after 90+ seconds of waiting (confirmed live, not theorized). Deleting and
# re-POSTing any ONE stuck proxy forces a fresh full snapshot rebuild that
# has reliably picked up every other previously-stuck proxy too - so recovery
# only needs to recreate the first missing one, then re-check all of them.
wait_for_proxy_routes_via_admin() {
  local tries="$1" name missing recreate_body
  for ((round = 0; round < 3; round++)); do
    missing=()
    for name in "${PROXY_NAMES[@]}"; do
      local remaining=$tries
      until route_exists_in_admin "$name/latest"; do
        remaining=$((remaining - 1))
        [ "$remaining" -le 0 ] && { missing+=("$name"); break; }
        sleep 0.5
      done
    done
    [ "${#missing[@]}" -eq 0 ] && return 0

    echo "WARNING: ${#missing[@]} LlmProxy route(s) never reached gateway-runtime after registration (${missing[*]}) - this is a known gateway-controller xDS batching issue when multiple LlmProxies are created back to back, not a policy bug. Recreating '${missing[0]}' to force a fresh snapshot (recovery round $((round + 1))/3) ..." >&2
    recreate_body="$(collection_request_body "Register: ${missing[0]}")" \
      || { echo "failed to read ${missing[0]}'s body from the collection: $recreate_body" >&2; return 1; }
    curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-proxies/${missing[0]}" \
      -H "Authorization: Basic YWRtaW46YWRtaW4="
    sleep 1
    curl -s -o /dev/null -X POST "$CONTROLLER_BASE_URL/api/management/v1/llm-proxies" \
      -H "Content-Type: application/yaml" -H "Authorization: Basic YWRtaW46YWRtaW4=" \
      --data-binary "$recreate_body"
  done
  echo "route(s) never reached gateway-runtime even after recovery: ${missing[*]}" >&2
  return 1
}

# wait_for_mcp_routes_via_admin is wait_for_proxy_routes_via_admin's Mcp
# counterpart. Mcp contexts have no "/latest" version-segment convention (the
# route path is "<context>/mcp", not "<context>/latest/..."), so this checks
# for that shape instead, and recreates via /mcp-proxies rather than
# /llm-proxies. Whether Mcp resources are prone to the same rapid-succession
# route-drop bug as LlmProxy has not been separately confirmed - MCP_NAMES
# currently has only one entry, so nothing has exercised the "multiple
# created back to back" scenario for this resource kind yet. This still
# guards against the single-resource case (route never reaching
# gateway-runtime at all) either way.
wait_for_mcp_routes_via_admin() {
  local tries="$1" name missing recreate_body
  for ((round = 0; round < 3; round++)); do
    missing=()
    for name in "${MCP_NAMES[@]}"; do
      local remaining=$tries
      until route_exists_in_admin "$name/mcp"; do
        remaining=$((remaining - 1))
        [ "$remaining" -le 0 ] && { missing+=("$name"); break; }
        sleep 0.5
      done
    done
    [ "${#missing[@]}" -eq 0 ] && return 0

    echo "WARNING: ${#missing[@]} Mcp route(s) never reached gateway-runtime after registration (${missing[*]}). Recreating '${missing[0]}' to force a fresh snapshot (recovery round $((round + 1))/3) ..." >&2
    recreate_body="$(collection_request_body "Register: ${missing[0]}")" \
      || { echo "failed to read ${missing[0]}'s body from the collection: $recreate_body" >&2; return 1; }
    curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/mcp-proxies/${missing[0]}" \
      -H "Authorization: Basic YWRtaW46YWRtaW4="
    sleep 1
    curl -s -o /dev/null -X POST "$CONTROLLER_BASE_URL/api/management/v1/mcp-proxies" \
      -H "Content-Type: application/yaml" -H "Authorization: Basic YWRtaW46YWRtaW4=" \
      --data-binary "$recreate_body"
  done
  echo "route(s) never reached gateway-runtime even after recovery: ${missing[*]}" >&2
  return 1
}

# ─── one full attempt: register -> wait -> test -> cleanup ─────────────────
#
# Split into two newman invocations at the E.9b/E.11 boundary specifically to
# recreate oauth2-test-clientauthpost (guaranteeing an empty in-process AND
# Redis cache for it - a plain re-POST doesn't redeploy, it 400s with
# "already exists"; delete-then-create is what actually tears down and
# rebuilds its policy chain) between them, without that recreation being
# racing against - or masked by - anything else in the collection. E.11 is
# the only flow that asserts on the freshly-recorded IdP history entry for
# its own request; every other flow tolerates whatever cache state precedes
# it (see SAFE_TO_PROBE_NAMES above).
run_attempt() {
  # Mcp servers are registered FIRST, ahead of the 16 LlmProviders and 3
  # LlmProxies below - mcp-test-oauth2 has no dependency on any of them
  # (unlike the LlmProxies, which reference a provider by id and must come
  # after "01"). gateway-controller processes replica-sync events one at a
  # time on a single goroutine (pkg/eventlistener's processEvents), so
  # registering ~20 other resources first would queue mcp-test-oauth2's own
  # event behind all of them - and its POLICY CHAIN push (synchronous,
  # inside that same per-event processing) would only fire once its turn
  # comes up, well after Envoy's route table (a separate, async push - see
  # pkg/xds/snapshot.go) already reflects the route. That gap is exactly
  # what produced a live, reproducible "Policy chain not found for route"
  # 500 for mcp-test-oauth2 specifically (confirmed: registering it ALONE,
  # or ahead of the other ~20 resources, never reproduces this; registering
  # it LAST behind them does, consistently). Registering it first sidesteps
  # the queue-depth entirely rather than trying to out-wait it.
  log "Registering test Mcp servers ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --folder "01c - Register MCP Servers (Mcp)" \
    --reporters cli --color on || return 1

  log "Registering test LlmProviders ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --folder "01 - Register AI APIs (LLM Providers)" \
    --reporters cli --color on || return 1

  log "Registering test LlmProxies ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --folder "01b - Register AI Proxies (LLM Proxies)" \
    --reporters cli --color on || return 1

  log "Verifying every registered LlmProxy route actually reached gateway-runtime ..."
  wait_for_proxy_routes_via_admin 20 \
    || { echo "one or more LlmProxy routes never reached gateway-runtime, even after recovery" >&2; return 1; }

  log "Verifying every registered Mcp route actually reached gateway-runtime ..."
  wait_for_mcp_routes_via_admin 20 \
    || { echo "one or more Mcp routes never reached gateway-runtime, even after recovery" >&2; return 1; }
  # route_exists_in_admin (used by both waits above) only confirms Envoy's
  # OWN route table - the policy engine's policy chain for that same route is
  # a separate xDS channel to a different process (ext_proc), observed live
  # to lag behind the route table by a few seconds independently. A request
  # that lands in that gap gets a real 500 ("Policy chain not found for
  # route") from the policy engine, not a 404 from Envoy - confirmed by
  # reading gateway-runtime's own logs, and confirmed transient by a manual
  # retry succeeding seconds later with no other change. There is no cheap
  # readiness signal for this second channel (unlike the route table, the
  # policy engine exposes no admin dump of loaded policy chains), so this is
  # a fixed grace sleep, sized from that same live observation, rather than a
  # polled check.
  sleep 3

  log "Waiting for gateway-runtime to pick up the new routes via xDS ..."
  for name in "${SAFE_TO_PROBE_NAMES[@]}"; do
    wait_for_route "$name" 40 || { echo "route for '$name' never came up" >&2; return 1; }
  done
  # The 5 valid-credential providers were registered in the exact same batch
  # as the 5 just confirmed live and are deliberately never probed directly
  # (see SAFE_TO_PROBE_NAMES) - this grace pause is their only insurance.
  sleep 1
  echo "Routes are live."

  log "Running oauth2 flows E.1-E.9b ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "00 - Health Checks" \
    --folder "02 - Mock Debug Endpoints" \
    --folder "03 - Test Flows (E.1-E.9b)" \
    --reporters cli --color on || return 1

  log "Recreating oauth2-test-clientauthpost for a guaranteed-clean cache ahead of E.11 ..."
  curl -s -o /dev/null -X DELETE "$CONTROLLER_BASE_URL/api/management/v1/llm-providers/oauth2-test-clientauthpost" \
    -H "Authorization: Basic YWRtaW46YWRtaW4="
  # Captured into a variable (not piped straight into curl) so a failure
  # extracting the body from the collection - e.g. the request got renamed -
  # is caught here as a hard error instead of silently POSTing an empty body
  # and only surfacing as a confusing E.11 failure downstream.
  clientauthpost_body="$(collection_request_body "Register: oauth2-test-clientauthpost")" \
    || { echo "failed to read oauth2-test-clientauthpost's body from the collection: $clientauthpost_body" >&2; return 1; }
  curl -s -o /dev/null -X POST "$CONTROLLER_BASE_URL/api/management/v1/llm-providers" \
    -H "Content-Type: application/yaml" \
    -H "Authorization: Basic YWRtaW46YWRtaW4=" \
    --data-binary "$clientauthpost_body"
  # Deliberately NOT verified with a real probe - that would immediately
  # re-warm the very cache this step exists to keep empty. In practice this
  # single-route recreate is the most common source of a retried attempt
  # (see the retry loop below) - erring generous here trades a bit of wall
  # clock for meaningfully fewer full-cycle retries.
  #
  # Measured live against this same stack: a delete+recreate cycle's route
  # can take ~3s to go live on its own, on top of the old route still
  # answering for ~1-2s after the delete call returns - a 5s budget leaves
  # ~0 margin once xDS propagation is running slower than usual (e.g. under
  # the extra load of repeated local rebuilds/restarts), which is what
  # turned an occasional single retry into every attempt in a run failing
  # at E.11. Doubling it trades a few more seconds of wall clock for that
  # margin back.
  sleep 10

  # The clientauthpost delete+recreate immediately above is itself a config
  # change, and gateway-controller's xDS snapshot rebuild on ANY config
  # change has been observed (live, not theorized) to occasionally drop an
  # unrelated LlmProxy route that was already confirmed live earlier in this
  # same attempt - not just when multiple LlmProxies are created back to
  # back. Re-verifying (and self-healing, see wait_for_proxy_routes_via_admin)
  # here catches that regression before E.18/E.19/E.20 rely on those routes.
  log "Re-verifying LlmProxy routes are still live after the clientauthpost recreate ..."
  wait_for_proxy_routes_via_admin 20 \
    || { echo "one or more LlmProxy routes were dropped by a later config change and never recovered" >&2; return 1; }
  wait_for_mcp_routes_via_admin 20 \
    || { echo "one or more Mcp routes were dropped by a later config change and never recovered" >&2; return 1; }

  log "Running oauth2 flows E.11-E.17 ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "03 - Test Flows (E.11-E.13)" \
    --folder "E.14 - Shared cache across two APIs with identical oauth2 config (requires --profile redis)" \
    --folder "E.15 - Password grant custom scope reaches the token endpoint" \
    --folder "E.16 - Purge cached token on upstream 401 (default tokenPurgeStatusCodes)" \
    --folder "E.17 - Purge disabled (tokenPurgeStatusCodes: []) leaves the cache alone" \
    --reporters cli --color on || return 1

  log "Running oauth2 flows E.22-E.26 (bearerToken, header/proxy customization, retries) ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.22-E.26 - New oauth2-generator capabilities" \
    --reporters cli --color on || return 1

  # One more check, as close as possible to the point of use: the same
  # unexplained drop has been observed to recur between the check above and
  # this point (a handful of newman requests / a few seconds later), with no
  # explicit config mutation in between that would obviously explain it - so
  # this isn't provably tied to any single fixed checkpoint. Re-verifying
  # immediately before the LlmProxy-dependent flows minimizes that window.
  log "Re-verifying LlmProxy/Mcp routes immediately before the dependent flows ..."
  wait_for_proxy_routes_via_admin 20 \
    || { echo "one or more LlmProxy routes were dropped again and never recovered" >&2; return 1; }
  wait_for_mcp_routes_via_admin 20 \
    || { echo "one or more Mcp routes were dropped again and never recovered" >&2; return 1; }
  # Same policy-chain-lags-route-table gap as the first checkpoint above -
  # this is the checkpoint that actually matters, since E.18-E.20 run
  # immediately after it.
  sleep 10

  log "Running LlmProxy flows E.18-E.20 ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.18 - LlmProxy with oauth2 upstream auth (provider.auth)" \
    --folder "E.19 - LlmProvider's own upstream.auth fires via LlmProxy loopback (hop2-only)" \
    --folder "E.20 - LlmProxy provider.auth + LlmProvider's own upstream.auth (both hops, precedence)" \
    --reporters cli --color on || return 1

  # E.27-E.31 happen to already sit in this exact relative order in the
  # collection (indices 18-22), so one combined invocation would technically
  # be safe per the ordering rule above - but giving each its own invocation
  # costs nothing and removes any need to re-verify that ordering invariant
  # if a folder is ever inserted between them later.
  log "Running oauth2 flows E.27-E.31 (TLS, custom purge codes, redis failure modes, header+prefix) ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.27 - tlsCaCertPath / tlsInsecureSkipVerify" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit-e27-e31.xml" \
    --color on || return 1
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.28 - Custom tokenPurgeStatusCodes ([403] instead of the default [401])" \
    --reporters cli --color on || return 1
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.29 - redis.failureMode open (Redis unreachable falls back to the token endpoint)" \
    --reporters cli --color on || return 1
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.30 - redis.failureMode closed (Redis unreachable fails the request)" \
    --reporters cli --color on || return 1
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.31 - headerName + a non-empty custom valuePrefix together" \
    --reporters cli --color on || return 1

  log "Running oauth2 flow E.32a (expiryBuffer priming) ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.32a - expiryBuffer priming (before the buffer window)" \
    --reporters cli --color on || return 1

  # expiryBuffer's whole point is refreshing a cached token before it's
  # actually expired - proving that needs a real wall-clock gap between the
  # priming request and the next one, not just newman's own inter-request
  # overhead (unlike E.3, which only needs to prove ordinary post-expiry
  # refresh, so it tolerates that ambiguity). oauth2-test-expirybuffer uses
  # ttl=12s/expiryBuffer=8s, a 4s fresh window; sleeping 6s here lands
  # comfortably past that boundary (early refresh should already have fired)
  # while staying well under the token's real 12s expiry - proving this
  # isn't just E.3's "waited past actual expiry" case.
  sleep 6

  log "Running oauth2 flow E.32b (expiryBuffer forces an early refresh) ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.32b - expiryBuffer forces an early refresh (well before actual TTL expiry)" \
    --reporters cli --color on || return 1

  log "Running oauth2 flow E.34 (no resilience.retry, no x-wso2-retry-trigger; revoke a live token at the IdP; oauth2-generator's own self-retry gets a genuinely fresh, non-revoked one) ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.34 - Self-retry with a fresh token (no resilience.retry, no x-wso2-retry-trigger)" \
    --reporters cli --color on || return 1

  log "Running oauth2 flow E.35a (combined: model-failover retry-source + resilience.retry compose into one merged RetryPolicy, alongside oauth2-generator's independent self-retry) ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.35a - Combined: merged RetryPolicy (model-failover + resilience.retry) + oauth2-generator's self-retry leg" \
    --reporters cli --color on || return 1

  # E.35a's own retry (401, oauth2-generator's self-retry token-purge) is dispatched through
  # model-failover's aggregate-cluster priority mechanism and can suspend
  # whichever target received the failed attempt - even though 401 isn't one
  # of model-failover's own configured statusCodes. E.35b's force-500 check
  # needs primary NOT suspended, so this waits out that same suspendDuration
  # (10s) the combined provider is registered with - same pattern as E.32a/b.
  sleep 11

  log "Running oauth2 flow E.35b (combined: model-failover's own retry-source leg) ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.35b - Combined: model-failover's own retry-source leg (run after E.35a's suspend window expires)" \
    --reporters cli --color on || return 1

  # E.21 (Mcp) is DELIBERATELY run as its own newman invocation, not folded
  # into the E.18-E.20 one above, or combined with "04 - Redis Token Cache
  # Verification"/"05 - Cleanup" in a single invocation with --folder flags
  # in that order. Confirmed root cause of a previously-mysterious,
  # consistent 500 ("Policy chain not found for route") for mcp-test-oauth2:
  # `newman run --folder A --folder B --folder C` does NOT run A, B, C in
  # the order the flags are given - it runs whichever of them were selected
  # in the COLLECTION's own top-level order, silently ignoring command-line
  # order entirely (confirmed against a synthetic collection: flags given as
  # C, A, B still ran as A, B, C). In this collection, "04 - Redis Token
  # Cache Verification" and "05 - Cleanup" both sit well before E.21's own
  # folder - so a single invocation listing them as `--folder "E.21..."
  # --folder "04..." --folder "05..."` actually ran Cleanup (which deletes
  # mcp-test-oauth2, among ~20 other resources) BEFORE E.21 ever sent its
  # request. The route briefly lingering in Envoy's table past the delete
  # (stale until the next xDS push) while its policy chain was already torn
  # down is exactly what produces "Policy chain not found for route" - this
  # was never a timing race in gateway-controller at all, and is 100%
  # deterministic once you know to look for it. Each folder must run in its
  # own invocation to force the intended order.
  log "Running Mcp flow E.21 ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "E.21 - Mcp server with oauth2 upstream auth (MCPProxyConfigData.upstream.auth)" \
    --reporters "$NEWMAN_REPORTERS" \
    --reporter-junit-export "$REPORT_DIR/junit.xml" \
    --color on || return 1

  log "Running the Redis cache check ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "04 - Redis Token Cache Verification" \
    --reporters cli --color on || return 1

  log "Running cleanup ..."
  "${NEWMAN[@]}" run "$COLLECTION" \
    --insecure \
    --folder "05 - Cleanup" \
    --reporters cli --color on || return 1

  return 0
}

# A leftover Redis-cached token from a PREVIOUS invocation of this script
# (Redis is a long-lived external service, not reset by anything here) can
# silently satisfy what a flow expects to be a fresh IdP call, since the
# cache key is a pure function of the oauth2 config - the exact same
# LlmProvider body registered by a prior run produces the exact same cache
# entry. Flushing it here makes every run start from the same deterministic
# state regardless of what an earlier run left behind.
if [ "$RUN_OAUTH2" -eq 1 ]; then

log "Flushing any leftover cached tokens from a previous run ..."
flush_redis_cache

# ─── retry loop ──────────────────────────────────────────────────────────────
#
# A propagation lag that outlasts the waits above is a transient
# infrastructure-timing condition (observed directly: identical registration
# batches taking anywhere from well under a second to several seconds to
# fully land), not a policy defect - retrying the whole cycle from a clean
# slate is the honest way to absorb that, rather than chasing an
# ever-larger fixed sleep that would still just be a guess.
attempt=1
success=0
while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
  log "Attempt $attempt/$MAX_ATTEMPTS"
  if run_attempt; then
    success=1
    break
  fi
  echo "Attempt $attempt failed - cleaning up and retrying." >&2
  # oauth2-test-clientauthpost is already in PROVIDER_NAMES, so
  # delete_registered_providers alone covers it - no separate delete needed
  # even though run_attempt() may have recreated it mid-run. Proxies first,
  # since oauth2-test-proxy references a provider by id.
  delete_registered_mcps
  delete_registered_proxies
  delete_registered_providers
  flush_redis_cache
  attempt=$((attempt + 1))
  sleep 2
done

if [ "$success" -ne 1 ]; then
  delete_registered_mcps
  delete_registered_proxies
  delete_registered_providers
  die "all $MAX_ATTEMPTS attempts failed - see output above for the actual assertion failures (this is likely a real regression, not just propagation timing, if it fails consistently)"
fi

log "All oauth2 end-to-end flows passed."

# ─── E.33: real-world IdP verification (opt-in) ──────────────────────────────
#
# Unlike every flow above, E.33 depends on real internet access to a live,
# external IdP (Asgardeo) and reuses one real credential baked into the
# collection - not something every environment running this script should
# hit by default (offline/CI runners, rate limits, multiple people sharing
# one tenant). Opt in with RUN_REALWORLD_TEST=1 ./run-e2e.sh.
#
# A single newman invocation runs Register/Send/Delete back-to-back with no
# gap, but Send needs the same xDS propagation window as everything else in
# this script (see the "attempt" retry loop's own comment above) - and here
# there's no second invocation to insert a bash `sleep` between. newman's
# --delay-request pauses before EVERY request in the run, so it doubles as
# that gap between Register and Send. Retrying escalates the delay rather
# than assuming one fixed value always covers the observed several-second
# variance.
if [ "${RUN_REALWORLD_TEST:-0}" = "1" ]; then
  log "Running E.33 (real-world IdP verification, opt-in) ..."
  realworld_attempt=1
  realworld_success=0
  realworld_delay_ms=6000
  while [ "$realworld_attempt" -le 3 ]; do
    log "E.33 attempt $realworld_attempt/3 (--delay-request ${realworld_delay_ms}ms) ..."
    if "${NEWMAN[@]}" run "$COLLECTION" \
        --insecure \
        --delay-request "$realworld_delay_ms" \
        --folder "E.33 - Real-world OAuth2 verification against YOUR OWN IdP (opt-in: RUN_REALWORLD_TEST=1 ./run-e2e.sh, or standalone newman/Postman)" \
        --reporters cli --color on; then
      realworld_success=1
      break
    fi
    echo "E.33 attempt $realworld_attempt failed - retrying with a longer delay." >&2
    realworld_attempt=$((realworld_attempt + 1))
    realworld_delay_ms=$((realworld_delay_ms + 3000))
  done
  if [ "$realworld_success" -ne 1 ]; then
    die "E.33 (real-world IdP verification) failed after 3 attempts"
  fi
  log "E.33 passed."
else
  log "Skipping E.33 (real-world IdP verification, opt-in) - set RUN_REALWORLD_TEST=1 to include it."
fi

fi # RUN_OAUTH2 (flush, retry loop, E.33)

# ─── model-failover: chained end-to-end (--model-failover or "everything") ──
#
# Unrelated policy, same gateway stack - chained here (rather than requiring
# a second manual invocation) the same way advanced-ratelimit already was,
# now gated by its own selector flag instead of always running. Its own
# run-e2e.sh starts/tears down its own mocks and registers/deletes its own
# LlmProvider; it does not touch anything this script does above.
if [ "$RUN_MODEL_FAILOVER" -eq 1 ]; then
  MODEL_FAILOVER_E2E="$ROOT/../../model-failover/e2e/run-e2e.sh"
  if [ -x "$MODEL_FAILOVER_E2E" ]; then
    log "Running model-failover's e2e suite ..."
    "$MODEL_FAILOVER_E2E" || die "model-failover e2e suite failed"
    log "model-failover e2e suite passed."
  else
    log "Skipping model-failover e2e suite - $MODEL_FAILOVER_E2E not found or not executable."
  fi
fi

# ─── advanced-ratelimit: Redis-precedence end-to-end (chained) ──────────────
#
# Unrelated policy, same gateway stack - chained here because this is the
# one e2e script most people already run for the whole gateway, not because
# it belongs to the oauth2 policy. Its own run-e2e.sh restarts gateway-runtime
# with different env states per phase (see that script's header for why) and
# always restores api-platform.env/gateway-runtime on exit, success or
# failure - it does not touch anything this script already did above. Runs
# only in the no-flags "everything" mode - it has no selector flag of its own.
if [ "$RUN_ADVANCED_RATELIMIT" -eq 1 ]; then
ADVANCED_RATELIMIT_E2E="$ROOT/../../advanced-ratelimit/e2e/run-e2e.sh"
if [ -x "$ADVANCED_RATELIMIT_E2E" ]; then
  log "Running advanced-ratelimit's Redis-precedence e2e suite ..."
  "$ADVANCED_RATELIMIT_E2E" || die "advanced-ratelimit e2e suite failed"
  log "advanced-ratelimit e2e suite passed."
else
  log "Skipping advanced-ratelimit e2e suite - $ADVANCED_RATELIMIT_E2E not found or not executable."
fi
fi # RUN_ADVANCED_RATELIMIT
