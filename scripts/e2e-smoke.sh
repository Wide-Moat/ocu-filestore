#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Real-binary smoke: assert the composed daemon refuses bad invocations
# BEFORE binding any listener. One committed source of truth so the e2e and
# release workflows assert the SAME load-bearing invariants against the SAME
# binary instead of hand-rolling drifting copies in YAML.
#
# The daemon serves a TLS HTTPS/HTTP-2 REST listener (no unix socket); the
# required transport flags are -tls-cert / -tls-key. Validation runs before any
# listener is bound, so each refusal below is a pre-bind, typed-error exit.
#
# Usage:  bash scripts/e2e-smoke.sh /path/to/ocu-filestored
#
# The three checks (each must exit 1 with a stable substring of the typed
# error main.go emits, and never bind a listener):
#   1. a missing required flag is named in the refusal text (here -tls-cert, a
#      load-bearing flag of the TLS REST transport);
#   2. an unknown engine is refused, never silently defaulted;
#   3. -engine s3 with its required backing-store config absent refuses pre-bind
#      (the engine-conditional required-flag matrix), naming the missing flag.
set -uo pipefail

BIN="${1:-}"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "::error::usage: e2e-smoke.sh <path-to-ocu-filestored> (executable)"
  exit 2
fi

# Isolate from any OCU_FILESTORE_* env fallback the host may carry: an exported
# value would otherwise satisfy a flag this smoke deliberately leaves unset and
# mask the refusal. Clear the whole namespace for the duration of the smoke.
for var in $(env | grep -oE '^OCU_FILESTORE_[A-Z0-9_]+' || true); do
  unset "$var"
done

fail=0

# 1. missing required flag — exit 1, typed error, the offending flag named.
#    A local-volume invocation that supplies the engine root but OMITS the
#    required TLS server certificate must name -tls-cert in the refusal.
tmp1=$(mktemp -d)
code=0
out=$("$BIN" \
  -engine local-volume \
  -engine-root "$tmp1/root" \
  -audit-sink "$tmp1/audit.jsonl" \
  -filesystem-id fs-smoke \
  -broker-max-file-size 1 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on a missing required flag, got $code"
  fail=1
fi
echo "$out" | grep -q "required flag missing or invalid" || {
  echo "::error::missing-required-flag error text missing from output"
  fail=1
}
echo "$out" | grep -q "tls-cert" || {
  echo "::error::expected the missing required flag (-tls-cert) to be named"
  fail=1
}
rm -rf "$tmp1"

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

# 3. -engine s3 with its required backing-store config absent — the engine-
#    conditional required-flag matrix refuses pre-bind and names the missing
#    flag. (-engine-root is omitted: it is invalid for the s3 engine, so the
#    first unmet s3 requirement surfaces.) No listener is ever bound.
tmp3=$(mktemp -d)
code=0
out=$("$BIN" \
  -engine s3 \
  -s3-endpoint http://127.0.0.1:9 \
  -audit-sink "$tmp3/audit.jsonl" \
  -tls-cert "$tmp3/cert.pem" \
  -tls-key "$tmp3/key.pem" \
  -filesystem-id fs-smoke \
  -broker-max-file-size 1 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on -engine s3 with missing s3 config, got $code"
  fail=1
fi
echo "$out" | grep -q "required flag missing or invalid" || {
  echo "::error::s3 missing-config refusal must carry the typed missing-flag error"
  fail=1
}
echo "$out" | grep -q "s3-bucket" || {
  echo "::error::the s3 missing-config refusal must name the missing -s3-bucket flag"
  fail=1
}
rm -rf "$tmp3"

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "real-binary smoke passed: all three pre-bind refusals hold"
