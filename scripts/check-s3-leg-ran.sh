# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Single source of the e2e-s3 liveness assertion: confirm the live-s3 leg case
# TestComposeS3RealEngineServes emitted a real PASS event against the MinIO rig.
#
# The s3 live cases t.Skip when the rig env (OCU_S3_TEST_ENDPOINT et al.) never
# reaches the suite, and a skip counts as a green test — so a var typo could
# otherwise report green while exercising no live S3. TestComposeS3RealEngineServes
# runs ONLY against the rig, so its real pass is the unique liveness signal.
#
# Input is a go-test-json stream: newline-delimited JSON objects, one event per
# line. Each test's pass is its own object carrying both Action=="pass" and the
# Test name. We select on that single object with jq, which is robust to JSON
# field order and to line buffering — unlike a two-stage grep pipe, which is
# brittle to both and false-reds on a real green run.
#
# Usage: check-s3-leg-ran.sh <path-to-go-test-json>
# Exit 0  iff at least one object matches Action=="pass" AND Test==target.
# Exit 1  if the target test was skipped, absent, or otherwise never passed.
set -euo pipefail

readonly TARGET='TestComposeS3RealEngineServes'

json="${1:?usage: check-s3-leg-ran.sh <path-to-go-test-json>}"

if [ ! -f "$json" ]; then
  echo "::error::go-test-json stream not found: $json" >&2
  exit 1
fi

# jq -e reads each newline-delimited object and exits 0 iff the filter produced
# a truthy/non-empty result for at least one input. select() emits the matching
# object only when both fields hold; no match => empty output => jq -e exits 1.
if ! jq -e --arg t "$TARGET" \
    'select(.Action=="pass" and .Test==$t)' "$json" >/dev/null; then
  echo "::error::the s3 live-leg case ${TARGET} did not pass against the real MinIO rig — the live s3 slice was not exercised" >&2
  exit 1
fi

echo "s3 e2e leg ran: ${TARGET} passed against real MinIO"
