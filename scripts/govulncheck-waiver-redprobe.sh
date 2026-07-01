#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Two-sided RED-when-neutered proof for scripts/govulncheck-waiver.sh. A waiver
# gate that never fires would silence every advisory — the worst outcome for a
# supply-chain control; a gate that always fires guards nothing either. This
# drives the SAME gate script (it accepts a captured JSON stream as $1) against
# synthetic govulncheck NDJSON fixtures and asserts the exit code for each case,
# so the proof is hermetic — no real scan, nothing left on disk. The assertion
# logic is single-sourced in govulncheck-waiver.sh; this probe only feeds it
# fixtures and checks the direction of each verdict.
#
# This service's waiver table is EMPTY (a firsthand binary-mode scan reports zero
# reachable advisories), so the probe proves the directions that are LIVE on an
# empty table:
#
#   Skeptic A (reachable -> RED): a reachable finding (a called function in its
#     trace) must fail the gate. With an empty waiver EVERY reachable finding is
#     non-waived — this is the gate's whole job.
#   Skeptic B (empty input -> RED): a blank stream must fail closed — absence of a
#     result is never a pass.
#   Skeptic C (clean scan -> GREEN): the control case — a progress-only stream with
#     NO findings — must PASS, proving the gate is not a constant-RED stub that
#     "passes" the others vacuously.
#   Skeptic D (package-level -> RED): a finding whose trace carries a .package but
#     no .function must also fire, proving the reachability filter's package arm is
#     real, not decorative.
#   Skeptic E (stripped binary -> RED): findings present but ALL module-only (the
#     trace frame carries only .module — what binary mode emits for a stripped
#     -s -w binary) must fail closed via the strip-guard, never silently pass.
#
# ANTI-STALE + EXPIRY are guarded-vacuous while WAIVED is empty; their code paths
# are exercised the moment the first waiver lands (add a drop-a-waived-ID Skeptic
# and an all-waived-present control then).
set -euo pipefail

GATE="$(dirname "$0")/govulncheck-waiver.sh"
if [[ ! -x "$GATE" ]]; then
  chmod +x "$GATE" 2>/dev/null || true
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "::notice::jq not installed — skipping the govulncheck waiver red-probe (advisory parity for local dev)"
  exit 0
fi

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

finding() {
  jq -cn --arg id "$1" \
    '{finding: {osv: $id, trace: [{module: "example.com/some/dep", function: "Vulnerable"}]}}'
}
package_finding() {
  jq -cn --arg id "$1" \
    '{finding: {osv: $id, trace: [{module: "example.com/some/dep", package: "example.com/some/dep/client"}]}}'
}
module_only_finding() {
  jq -cn --arg id "$1" \
    '{finding: {osv: $id, trace: [{module: "example.com/some/dep"}]}}'
}
progress() {
  jq -cn '{progress: {message: "Scanning your code and 100 packages across 1 dependent module for known vulnerabilities..."}}'
}

# ── Skeptic A: a reachable (non-waived, since the table is empty) finding -> RED ──
finding "GO-2026-9999" >"$TMP/a.json"
if "$GATE" "$TMP/a.json" >/dev/null 2>&1; then
  echo "::error::Skeptic A — gate PASSED with a reachable finding (GO-2026-9999); it guards nothing"
  exit 1
fi
echo "ok: Skeptic A — a reachable finding fires RED (empty waiver => every finding is non-waived)"

# ── Skeptic B: an empty stream must fail closed ──
: >"$TMP/b.json"
if "$GATE" "$TMP/b.json" >/dev/null 2>&1; then
  echo "::error::Skeptic B — gate PASSED on empty input; it does not fail closed"
  exit 1
fi
echo "ok: Skeptic B — an empty scan fires RED (fail closed)"

# ── Skeptic C: the control — a clean scan (progress only, no findings) -> GREEN ──
progress >"$TMP/c.json"
if ! "$GATE" "$TMP/c.json" >/dev/null 2>&1; then
  echo "::error::Skeptic C — gate FAILED the clean-scan control case; it is a constant-RED stub, not a real gate"
  "$GATE" "$TMP/c.json" || true
  exit 1
fi
echo "ok: Skeptic C — a clean scan (no findings) PASSES (the gate is not constant-RED)"

# ── Skeptic D: a package-level reachable finding must go RED ──
package_finding "GO-2026-9998" >"$TMP/d.json"
if "$GATE" "$TMP/d.json" >/dev/null 2>&1; then
  echo "::error::Skeptic D — gate PASSED with a package-level reachable finding (GO-2026-9998); the package reachability arm is unguarded"
  exit 1
fi
echo "ok: Skeptic D — a package-level finding fires RED (reachability package arm)"

# ── Skeptic E: a stripped binary (findings present, ALL module-only) must go RED ──
module_only_finding "GO-2026-9997" >"$TMP/e.json"
if "$GATE" "$TMP/e.json" >/dev/null 2>&1; then
  echo "::error::Skeptic E — gate PASSED on an all-module-only stream (stripped binary); fail-open on an unresolvable scan"
  exit 1
fi
echo "ok: Skeptic E — an all-module-only (stripped-binary) stream fires RED (strip-guard)"

echo "govulncheck-waiver-redprobe: reachable RED, fail-closed RED, clean-scan GREEN, package-level RED, strip-guard RED all proven; tree clean"
