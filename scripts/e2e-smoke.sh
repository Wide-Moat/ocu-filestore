# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Real-binary smoke: assert the composed daemon refuses bad invocations
# BEFORE binding any socket. One committed source of truth so the e2e and
# release workflows assert the SAME load-bearing invariants against the SAME
# binary instead of hand-rolling drifting copies in YAML.
#
# Usage:  bash scripts/e2e-smoke.sh /path/to/ocu-filestored
#
# The three checks (each must exit 1 with a stable substring of the typed
# error main.go emits, and never bind a socket):
#   1. a missing required flag is named in the refusal text;
#   2. an unknown engine is refused, never silently defaulted;
#   3. -engine s3 with NO storage-lane posture refuses pre-bind naming
#      ADR-0011 (the bypass dial does not exist — NFR-SEC-16/85).
set -uo pipefail

BIN="${1:-}"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "::error::usage: e2e-smoke.sh <path-to-ocu-filestored> (executable)"
  exit 2
fi

fail=0

# 1. missing required flag — exit 1, typed error, the first missing flag named.
code=0
out=$("$BIN" -engine local-volume 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on a missing required flag, got $code"
  fail=1
fi
echo "$out" | grep -q "required flag missing or invalid" || {
  echo "::error::missing-required-flag error text missing from output"
  fail=1
}
echo "$out" | grep -q "engine-root" || {
  echo "::error::expected the first missing required flag (-engine-root) to be named"
  fail=1
}

# 2. unknown engine — refused, never silently defaulted.
code=0
out=$("$BIN" -engine bogus 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on unknown engine, got $code"
  fail=1
fi
echo "$out" | grep -q "unknown backend engine" || {
  echo "::error::unknown-engine sentinel missing from output"
  fail=1
}

# 3. -engine s3 with no storage lane — refuses pre-bind naming ADR-0011, and
#    no socket is ever bound.
tmp=$(mktemp -d)
code=0
out=$("$BIN" -engine s3 \
  -s3-bucket ocu-smoke \
  -s3-endpoint http://127.0.0.1:9 \
  -audit-sink "$tmp/audit.jsonl" \
  -south-socket-dir "$tmp/sock" \
  -filesystem-id fs-smoke \
  -broker-max-file-size 1 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on -engine s3 without a lane, got $code"
  fail=1
fi
echo "$out" | grep -q "ADR-0011" || {
  echo "::error::the lane refusal must name ADR-0011"
  fail=1
}
if ls "$tmp/sock"/*.sock >/dev/null 2>&1; then
  echo "::error::a socket was bound despite the lane refusal"
  fail=1
fi
rm -rf "$tmp"

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "real-binary smoke passed: all three pre-bind refusals hold"
