# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Single source of the e2e-s3 liveness assertion: confirm each live-s3 leg case
# emitted a real PASS event against the MinIO rig.
#
# The s3 live cases t.Skip when the rig env (OCU_S3_TEST_ENDPOINT et al.) never
# reaches the suite, and a skip counts as a green test — so a var typo could
# otherwise report green while exercising no live S3. Each target below runs
# ONLY against the rig, so its real pass is a unique liveness signal:
#   - TestComposeS3RealEngineServes  (cmd composed-daemon south round-trip)
#   - TestFilesAPIRealS3EngineRoundTrip  (filesapi north create/content/archive
#     against the REAL s3 engine — the engine-leg above the composed daemon)
#
# Input is a go-test-json stream: newline-delimited JSON objects, one event per
# line. Each test's pass is its own object carrying both Action=="pass" and the
# Test name. We select on that single object with jq, which is robust to JSON
# field order and to line buffering — unlike a two-stage grep pipe, which is
# brittle to both and false-reds on a real green run.
#
# Usage: check-s3-leg-ran.sh <path-to-go-test-json>
# Exit 0  iff EVERY target has at least one object matching Action=="pass".
# Exit 1  if any target test was skipped, absent, or otherwise never passed.
set -euo pipefail

# Every live-s3 leg that must have really run against the rig. A skip counts as
# green, so each is asserted independently — one silently skipping fails closed.
readonly TARGETS=(
  'TestComposeS3RealEngineServes'
  'TestFilesAPIRealS3EngineRoundTrip'
)

json="${1:?usage: check-s3-leg-ran.sh <path-to-go-test-json>}"

if [ ! -f "$json" ]; then
  echo "::error::go-test-json stream not found: $json" >&2
  exit 1
fi

# jq -e reads each newline-delimited object and exits 0 iff the filter produced
# a truthy/non-empty result for at least one input. select() emits the matching
# object only when both fields hold; no match => empty output => jq -e exits 1.
for target in "${TARGETS[@]}"; do
  if ! jq -e --arg t "$target" \
      'select(.Action=="pass" and .Test==$t)' "$json" >/dev/null; then
    echo "::error::the s3 live-leg case ${target} did not pass against the real MinIO rig — the live s3 slice was not exercised" >&2
    exit 1
  fi
  echo "s3 e2e leg ran: ${target} passed against real MinIO"
done
