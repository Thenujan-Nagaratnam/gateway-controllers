#!/usr/bin/env bash
# Repeatable regression and end-to-end run for the pii-masking-regex policy.
#
#   TestE2E_*          real policy instances over HTTP against a mock Anthropic upstream:
#                      edge-case scenarios x answer shapes x tokenisations x chunkings,
#                      seeded random round trips, a growing conversation, concurrency
#   TestDifferential_* the frozen v1.1.0 policy (internal/legacy) next to this one: every
#                      value it masked validly must still be masked, and every response
#                      shape it restored must reach the client byte for byte
#   TestGolden_*       pinned outputs for a fixed corpus (refresh with UPDATE_GOLDEN=1)
#   TestProperties_*   invariants for any input: valid JSON stays valid, only string text
#                      changes, masking twice changes nothing, restore(mask(x)) == x
#   TestEdge_*         individual edge cases (structure, patterns, size, response shapes)
#
#   ./run-e2e.sh                           # 3 passes with the race detector (about 3 min)
#   RUNS=20 RACE=0 ./run-e2e.sh            # many fast passes
#   E2E_ITERATIONS=5000 DIFF_ITERATIONS=50000 PROP_ITERATIONS=20000 ./run-e2e.sh
#   E2E_SEED=7 DIFF_SEED=7 PROP_SEED=7 ./run-e2e.sh      # different random streams
#   FUZZ=60s ./run-e2e.sh                  # also fuzz both targets for 60s each
#   UPDATE_GOLDEN=1 go test -run TestGolden .   # after an intended behaviour change
set -euo pipefail
cd "$(dirname "$0")"

RUNS="${RUNS:-3}"
RACE_FLAG="-race"
[ "${RACE:-1}" = "0" ] && RACE_FLAG=""
PATTERN='TestE2E|TestDifferential|TestGolden|TestProperties|TestEdge'

echo "pii-masking-regex regression run: runs=${RUNS} race=${RACE:-1} seeds e2e=${E2E_SEED:-1} diff=${DIFF_SEED:-1} prop=${PROP_SEED:-1}"
start=$(date +%s)
# -count reruns every test, so each pass is a fresh gateway, upstream and random stream.
go test ${RACE_FLAG} -count="${RUNS}" -run "${PATTERN}" -timeout 40m .
echo "all ${RUNS} passes green in $(( $(date +%s) - start ))s"

if [ -n "${FUZZ:-}" ]; then
  for target in FuzzMaskRequest FuzzRestoreStream; do
    echo "fuzzing ${target} for ${FUZZ}"
    go test -run xxx -fuzz "^${target}\$" -fuzztime "${FUZZ}" .
  done
fi
