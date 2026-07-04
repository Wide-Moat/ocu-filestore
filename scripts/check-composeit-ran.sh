# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Single source of the component-it liveness assertion: confirm the full-stack
# component round-trip case TestComponentRoundTripOverTLSToMinIO emitted a real
# PASS event against the composed broker+MinIO stack.
#
# The composeit cases t.Skip when OCU_COMPOSE_IT != 1 or docker is absent, and a
# skip counts as a green test — so a missing env var or a docker-less runner
# could otherwise report green while standing up nothing. That silent skip is
# EXACTLY the gap this job closes (no CI job set OCU_COMPOSE_IT before), so the
# gate must fail closed when the round-trip did not really run. The round-trip
# case runs ONLY against the live stack, so its real pass is the unique liveness
# signal.
#
# Input is a go-test-json stream: newline-delimited JSON objects, one event per
# line. Each test's pass is its own object carrying both Action=="pass" and the
# Test name. We select on that single object with jq, robust to JSON field order
# and line buffering — unlike a two-stage grep pipe, which is brittle to both and
# false-reds a real green run.
#
# Usage: check-composeit-ran.sh <path-to-go-test-json>
# Exit 0  iff at least one object matches Action=="pass" AND Test==target.
# Exit 1  if the target test was skipped, absent, or otherwise never passed.
set -euo pipefail

readonly TARGET='TestComponentRoundTripOverTLSToMinIO'

json="${1:?usage: check-composeit-ran.sh <path-to-go-test-json>}"

if [ ! -f "$json" ]; then
  echo "::error::go-test-json stream not found: $json" >&2
  exit 1
fi

# jq -e reads each newline-delimited object and exits 0 iff the filter produced
# a truthy/non-empty result for at least one input. select() emits the matching
# object only when both fields hold; no match => empty output => jq -e exits 1.
if ! jq -e --arg t "$TARGET" \
    'select(.Action=="pass" and .Test==$t)' "$json" >/dev/null; then
  echo "::error::the component-it case ${TARGET} did not pass against the live composed stack — the full-stack REST->MinIO round-trip was not exercised" >&2
  exit 1
fi

echo "component-it leg ran: ${TARGET} passed against the live composed stack"
