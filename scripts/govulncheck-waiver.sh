#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# GATE (SUPPLY-03): the govulncheck waiver gate. It runs govulncheck in binary
# mode against an already-built, UNSTRIPPED daemon and fails CI on any reachable
# vulnerability that is NOT on the explicit waiver list. This service is the
# storage broker: minimal dependencies, and a firsthand scan finds ZERO reachable
# advisories, so the waiver table below is EMPTY. The gate is not decorative on an
# empty table — rule 1 (fail on any reachable non-waived finding) is the whole
# point, and it fires the day a dependency introduces a reachable advisory.
#
# NON-EMPTINESS CHECK — O(n), NOT a pattern SUBSTITUTION. Whether the captured
# scan JSON is blank is tested with a glob match ([[ "$JSON" == *[![:space:]]* ]]),
# never ${JSON//[space]/}. The substitution form is QUADRATIC over the ~hundreds-
# of-KB scan stream on some runners' bash — a multi-minute pure-CPU spin that
# looks exactly like a "govulncheck hang" while the scan itself takes ~1 s. The
# glob match is linear and completes instantly. Any script that assigns a large
# scan stream to a variable MUST avoid the substitution form.
#
# Four structural rules carry this gate (a waiver that only suppresses is a
# silent hole an auditor opens first):
#
#   1. FAIL on any reachable finding whose OSV ID is NOT waived. govulncheck
#      reports a finding as reachable when its trace carries a called function
#      (or a present package); the gate keys on that, never on govulncheck's exit
#      code, so a newly-reachable advisory turns this RED rather than passing
#      under an exit-code check. With an empty waiver table, EVERY reachable
#      finding is non-waived — the gate is a pure "no reachable advisories" wall.
#   2. ANTI-STALE: FAIL when a waived ID is NO LONGER reported. A waived advisory
#      vanishing means upstream shipped a fix (or the path was removed) — the
#      waiver is dead weight. It goes RED and names the ID to drop. Vacuous while
#      WAIVED is empty; the code path stays live so the first added waiver is
#      governed from the moment it lands.
#   3. EXPIRY: a non-empty waiver carries a review-by date; past it the gate goes
#      RED regardless of findings, forcing a fresh reachability review rather than
#      letting a one-time judgement ride forever. Skipped while WAIVED is empty.
#   4. STRIP-GUARD: binary mode needs symbols. A stripped binary (-ldflags='-s
#      -w') degrades every finding to module granularity, so the reachability
#      filter returns ZERO even when findings exist — a fail-open hole. Findings
#      present but NONE carrying .function/.package => fail closed.
#
# A run that produces no parseable JSON fails CLOSED — absence of a result is
# never a pass.
set -euo pipefail

# --- waiver table -----------------------------------------------------------
# OSV ID -> one-line rationale (Fixed-in=N/A + reachability path + tracking
# issue). EMPTY for this service: a firsthand `govulncheck -mode binary` scan of
# the built daemon reports no reachable advisories. When a reachable, no-upstream-
# fix advisory appears, add its ID here with a rationale and set WAIVER_REVIEW_BY.
declare -A WAIVED=(
)

# Review-by date (YYYY-MM-DD), enforced ONLY when the waiver table is non-empty.
WAIVER_REVIEW_BY=""

# --- input ------------------------------------------------------------------
# Accept a pre-captured JSON stream as $1 (used by the red-probe), else run the
# pinned binary-mode govulncheck against the unstripped OCU_GATE_BINARY.
if [[ $# -ge 1 && -f "$1" ]]; then
  JSON="$(cat "$1")"
else
  if ! command -v govulncheck >/dev/null 2>&1; then
    echo "::error::govulncheck not found on PATH"
    echo "  Install the pinned version:"
    echo "    go install golang.org/x/vuln/cmd/govulncheck@v1.3.0"
    exit 1
  fi
  # MODE: `-mode binary`, NOT the default source scan. The source scan loads
  # packages and shells out to the `go` toolchain; binary mode reads the symbol
  # table of an ALREADY-BUILT binary — no package loading, no toolchain shell-out.
  # It finishes in ~1s and is deterministic against the same vuln.go.dev DB; the
  # only coverage delta is GOOS/GOARCH-bound (the one built platform), correct for
  # a single-platform CI gate.
  #
  # INVOCATION: `-mode binary` takes a positional path to ONE built binary, NOT
  # `./...`. The path is OCU_GATE_BINARY, an UNSTRIPPED daemon the CI job builds
  # (`go build -trimpath`, no `-s -w`). The JSON shape is identical to source mode.
  if [[ -z "${OCU_GATE_BINARY:-}" || ! -f "${OCU_GATE_BINARY:-/nonexistent}" ]]; then
    echo "::error::OCU_GATE_BINARY is unset or not a file — binary-mode govulncheck needs an unstripped built binary to scan; failing closed"
    echo "  The govulncheck CI job must build an UNSTRIPPED ocu-filestored (go build -trimpath, no -s -w) and export OCU_GATE_BINARY=<path>."
    exit 1
  fi
  SCAN_TIMEOUT="${GOVULNCHECK_TIMEOUT:-60}"
  JSON=""
  for attempt in 1 2 3; do
    GVJSON="$(mktemp)"
    timeout -s KILL --kill-after=10 "${SCAN_TIMEOUT}" \
      govulncheck -mode binary -format json "${OCU_GATE_BINARY}" >"${GVJSON}" 2>/dev/null </dev/null || true
    JSON="$(cat "${GVJSON}")"
    rm -f "${GVJSON}"
    # O(n) non-emptiness: a glob match, never a pattern substitution (which is
    # quadratic over the large scan stream and IS the historic "govulncheck hang").
    if [[ "$JSON" == *[![:space:]]* ]]; then
      break
    fi
    if (( attempt < 3 )); then
      echo "::warning::govulncheck attempt ${attempt}/3 produced no JSON (scan wedged or timed out after ${SCAN_TIMEOUT}s); retrying"
      sleep $(( attempt * 5 ))
    fi
  done
  if [[ "$JSON" != *[![:space:]]* ]]; then
    echo "::error::govulncheck produced no JSON after 3 bounded attempts — the vuln.go.dev DB fetch did not complete. If the runner has no egress to vuln.go.dev, the scan cannot run and this fail-closed is correct; investigate runner egress or switch to an offline DB (GOVULNDB)."
  fi
fi

if [[ "$JSON" != *[![:space:]]* ]]; then
  echo "::error::govulncheck produced no JSON output — failing closed"
  echo "  An empty scan is never a pass; investigate the toolchain before merging."
  exit 1
fi

# --- expiry check (only when the waiver table is non-empty) ------------------
if (( ${#WAIVED[@]} > 0 )); then
  if [[ -z "$WAIVER_REVIEW_BY" ]]; then
    echo "::error::the waiver table is non-empty but WAIVER_REVIEW_BY is unset — every waiver must carry a review-by date; failing closed"
    exit 1
  fi
  TODAY="$(date -I)"
  if [[ "$TODAY" > "$WAIVER_REVIEW_BY" ]]; then
    echo "::error::govulncheck waiver expired (review-by ${WAIVER_REVIEW_BY}, today ${TODAY})"
    echo "  Re-review each waived ID (still Fixed-in=N/A? still reachable?), update"
    echo "  WAIVER_REVIEW_BY, and refresh the tracking issue."
    exit 1
  fi
fi

# --- parse reachable findings ----------------------------------------------
# Reachability keys on a trace frame carrying a non-null .function (a called
# symbol) OR a non-null .package (present in the scanned binary's symbol table).
REACHED="$(printf '%s' "$JSON" | jq -r -s '
  [ .[]
    | select(.finding != null)
    | .finding
    | select([.trace[]? | select(.function != null or .package != null)] | length > 0)
    | .osv
  ] | unique | .[]' 2>/dev/null || true)"

# --- strip-guard: a stripped binary is a FAIL-OPEN hole, refuse it --------------
FINDING_COUNT="$(printf '%s' "$JSON" | jq -s '[ .[] | select(.finding != null) ] | length' 2>/dev/null || echo 0)"
RESOLVABLE_COUNT="$(printf '%s' "$JSON" | jq -s '
  [ .[] | select(.finding != null) | .finding
    | select([.trace[]? | select(.function != null or .package != null)] | length > 0)
  ] | length' 2>/dev/null || echo 0)"
if [[ "${FINDING_COUNT:-0}" -gt 0 && "${RESOLVABLE_COUNT:-0}" -eq 0 ]]; then
  echo "::error::govulncheck binary-mode produced ${FINDING_COUNT} finding(s) but NONE carry a .function or .package frame — the scanned binary is stripped (-s -w), so reachability cannot be resolved. Failing closed."
  echo "  Build the gate's binary WITHOUT -ldflags='-s -w' (default go build keeps symbols); OCU_GATE_BINARY must be unstripped."
  exit 1
fi

# --- rule 1: fail on any reachable, non-waived finding ----------------------
fail=0
non_waived=()
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  if [[ -z "${WAIVED[$id]+x}" ]]; then
    non_waived+=("$id")
  fi
done <<<"$REACHED"

if (( ${#non_waived[@]} > 0 )); then
  fail=1
  echo "::error::govulncheck: reachable vulnerabilities NOT on the waiver list:"
  for id in "${non_waived[@]}"; do
    echo "    - ${id} (https://pkg.go.dev/vuln/${id})"
  done
  echo "  Triage each: bump the dependency if a fix exists, else add to WAIVED"
  echo "  with a tracking issue + Fixed-in=N/A + reachability rationale and set"
  echo "  WAIVER_REVIEW_BY."
fi

# --- rule 2: anti-stale — fail on any waived ID no longer reported -----------
# Vacuous while WAIVED is empty; live the moment a waiver is added.
declare -A REACHED_SET=()
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  REACHED_SET[$id]=1
done <<<"$REACHED"

stale=()
for id in "${!WAIVED[@]}"; do
  if [[ -z "${REACHED_SET[$id]+x}" ]]; then
    stale+=("$id")
  fi
done

if (( ${#stale[@]} > 0 )); then
  fail=1
  echo "::error::govulncheck: waived IDs no longer reachable (upstream fix likely landed):"
  for id in "${stale[@]}"; do
    echo "    - ${id} — remove from WAIVED and bump the dependency to the fixed version"
  done
  echo "  A waiver must not outlive the condition that justified it."
fi

if (( fail == 0 )); then
  if (( ${#WAIVED[@]} == 0 )); then
    echo "govulncheck waiver gate: PASS"
    echo "  No reachable advisories, no waivers — clean supply-chain surface."
  else
    echo "govulncheck waiver gate: PASS"
    echo "  ${#WAIVED[@]} waived advisories all still reachable + Fixed-in=N/A; no"
    echo "  non-waived reachable findings; waiver valid until ${WAIVER_REVIEW_BY}."
  fi
fi

exit "$fail"
