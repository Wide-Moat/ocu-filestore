# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Two-sided red-probe for check-composeit-ran.sh: prove the component-it liveness
# gate does not lie in EITHER direction. The assertion logic is single-sourced in
# check-composeit-ran.sh; this probe drives that same script against synthetic
# go-test-json fixtures and asserts the exit code for each case.
#
# This applies anti-fake-green discipline to the gate itself — committed so the
# gate's correctness stays guarded going forward, not just verified once. It runs
# BEFORE the stack boot in CI so a regressed gate fails fast without spending a
# ~10-minute image build.
#
#   GREEN  : a real pass event for the target -> assertion exits 0  (gate PASS)
#   RED #1 : target skipped, no pass event    -> assertion exits !=0 (gate RED)
#   RED #2 : target entirely absent           -> assertion exits !=0 (gate RED)
#
# Usage: check-composeit-ran-redprobe.sh
# Exit 0  iff all three cases produce their expected exit code.
set -euo pipefail

cd "$(dirname "$0")"

readonly ASSERT='./check-composeit-ran.sh'

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Fixtures are realistic go-test-json streams: package + test events span
# multiple objects, fields appear in go's own emission order, and the matching
# pass object carries both Action and Test in one line.

# GREEN: the round-trip ran and passed against the live composed stack.
cat >"$work/green.json" <<'EOF'
{"Time":"2026-06-23T00:00:00Z","Action":"run","Package":"internal/composeit","Test":"TestComponentRoundTripOverTLSToMinIO"}
{"Time":"2026-06-23T00:00:00Z","Action":"output","Package":"internal/composeit","Test":"TestComponentRoundTripOverTLSToMinIO","Output":"=== RUN   TestComponentRoundTripOverTLSToMinIO\n"}
{"Time":"2026-06-23T00:02:00Z","Action":"output","Package":"internal/composeit","Test":"TestComponentRoundTripOverTLSToMinIO","Output":"--- PASS: TestComponentRoundTripOverTLSToMinIO (118.30s)\n"}
{"Time":"2026-06-23T00:02:00Z","Action":"pass","Package":"internal/composeit","Test":"TestComponentRoundTripOverTLSToMinIO","Elapsed":118.3}
{"Time":"2026-06-23T00:02:00Z","Action":"pass","Package":"internal/composeit","Elapsed":118.4}
EOF

# RED #1: OCU_COMPOSE_IT never reached the suite (or docker absent), so the target
# SKIPPED. No pass event for it. Package still reports pass (a skip counts as
# green) — exactly the false-green a brittle gate would wave through, and exactly
# the silent skip that left this leg unexercised before this job existed.
cat >"$work/skip.json" <<'EOF'
{"Time":"2026-06-23T00:00:00Z","Action":"run","Package":"internal/composeit","Test":"TestComponentRoundTripOverTLSToMinIO"}
{"Time":"2026-06-23T00:00:00Z","Action":"output","Package":"internal/composeit","Test":"TestComponentRoundTripOverTLSToMinIO","Output":"=== RUN   TestComponentRoundTripOverTLSToMinIO\n"}
{"Time":"2026-06-23T00:00:00Z","Action":"output","Package":"internal/composeit","Test":"TestComponentRoundTripOverTLSToMinIO","Output":"    composeit_test.go:124: OCU_COMPOSE_IT != 1 - component compose integration SKIPPED\n"}
{"Time":"2026-06-23T00:00:00Z","Action":"skip","Package":"internal/composeit","Test":"TestComponentRoundTripOverTLSToMinIO","Elapsed":0}
{"Time":"2026-06-23T00:00:00Z","Action":"pass","Package":"internal/composeit","Elapsed":0.02}
EOF

# RED #2: the target is entirely ABSENT — a different test passed, the suite ran
# green, but the round-trip case was never compiled/selected at all.
cat >"$work/absent.json" <<'EOF'
{"Time":"2026-06-23T00:00:00Z","Action":"run","Package":"internal/composeit","Test":"TestSomethingElse"}
{"Time":"2026-06-23T00:00:00Z","Action":"output","Package":"internal/composeit","Test":"TestSomethingElse","Output":"--- PASS: TestSomethingElse (0.00s)\n"}
{"Time":"2026-06-23T00:00:00Z","Action":"pass","Package":"internal/composeit","Test":"TestSomethingElse","Elapsed":0}
{"Time":"2026-06-23T00:00:00Z","Action":"pass","Package":"internal/composeit","Elapsed":0.456}
EOF

fail=0

# GREEN must exit 0.
if "$ASSERT" "$work/green.json" >/dev/null 2>&1; then
  echo "PASS  GREEN  : assertion exited 0 on a real pass event"
else
  echo "FAIL  GREEN  : assertion exited non-zero on a real pass event (false-RED)"
  fail=1
fi

# RED #1 (skip) must exit non-zero.
if "$ASSERT" "$work/skip.json" >/dev/null 2>&1; then
  echo "FAIL  RED #1 : assertion exited 0 on a SKIPPED target (false-GREEN)"
  fail=1
else
  echo "PASS  RED #1 : assertion exited non-zero on a skipped target"
fi

# RED #2 (absent) must exit non-zero.
if "$ASSERT" "$work/absent.json" >/dev/null 2>&1; then
  echo "FAIL  RED #2 : assertion exited 0 on an ABSENT target (false-GREEN)"
  fail=1
else
  echo "PASS  RED #2 : assertion exited non-zero on an absent target"
fi

if [ "$fail" -ne 0 ]; then
  echo "::error::component-it liveness gate is not two-sided-correct — see failures above" >&2
  exit 1
fi

echo "red-probe: component-it liveness gate is two-sided-correct (GREEN->0, SKIP->!=0, ABSENT->!=0)"
