# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Two-sided red-probe for check-s3-leg-ran.sh: prove the e2e-s3 liveness gate
# does not lie in EITHER direction. The assertion logic is single-sourced in
# check-s3-leg-ran.sh; this probe drives that same script against synthetic
# go-test-json fixtures and asserts the exit code for each case.
#
# This applies anti-fake-green discipline to the gate itself — committed so the
# gate's correctness stays guarded going forward, not just verified once.
#
#   GREEN  : a real pass event for the target  -> assertion exits 0  (gate PASS)
#   RED #1 : target skipped, no pass event     -> assertion exits !=0 (gate RED)
#   RED #2 : target entirely absent            -> assertion exits !=0 (gate RED)
#
# Usage: check-s3-leg-ran-redprobe.sh
# Exit 0  iff all three cases produce their expected exit code.
set -euo pipefail

cd "$(dirname "$0")"

readonly ASSERT='./check-s3-leg-ran.sh'

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Fixtures are realistic go-test-json streams: package + test events span
# multiple objects, fields appear in go's own emission order, and the matching
# pass object carries both Action and Test in one line.

# GREEN: EVERY target ran and passed against the rig (both the cmd composed-daemon
# leg and the filesapi real-engine leg).
cat >"$work/green.json" <<'EOF'
{"Time":"2026-06-23T00:00:00Z","Action":"run","Package":"internal/objectstore","Test":"TestComposeS3RealEngineServes"}
{"Time":"2026-06-23T00:00:00Z","Action":"output","Package":"internal/objectstore","Test":"TestComposeS3RealEngineServes","Output":"=== RUN   TestComposeS3RealEngineServes\n"}
{"Time":"2026-06-23T00:00:09Z","Action":"output","Package":"internal/objectstore","Test":"TestComposeS3RealEngineServes","Output":"--- PASS: TestComposeS3RealEngineServes (0.01s)\n"}
{"Time":"2026-06-23T00:00:09Z","Action":"pass","Package":"internal/objectstore","Test":"TestComposeS3RealEngineServes","Elapsed":0.01}
{"Time":"2026-06-23T00:00:09Z","Action":"pass","Package":"internal/objectstore","Elapsed":9.551}
{"Time":"2026-06-23T00:00:10Z","Action":"run","Package":"internal/filesapi","Test":"TestFilesAPIRealS3EngineRoundTrip"}
{"Time":"2026-06-23T00:00:10Z","Action":"output","Package":"internal/filesapi","Test":"TestFilesAPIRealS3EngineRoundTrip","Output":"=== RUN   TestFilesAPIRealS3EngineRoundTrip\n"}
{"Time":"2026-06-23T00:00:10Z","Action":"output","Package":"internal/filesapi","Test":"TestFilesAPIRealS3EngineRoundTrip","Output":"--- PASS: TestFilesAPIRealS3EngineRoundTrip (0.05s)\n"}
{"Time":"2026-06-23T00:00:10Z","Action":"pass","Package":"internal/filesapi","Test":"TestFilesAPIRealS3EngineRoundTrip","Elapsed":0.05}
{"Time":"2026-06-23T00:00:10Z","Action":"pass","Package":"internal/filesapi","Elapsed":0.9}
EOF

# RED #1: the rig env never reached the suite, so the target SKIPPED. No pass
# event for it. Package still reports pass (a skip counts as green) — exactly
# the false-green a brittle gate would wave through.
cat >"$work/skip.json" <<'EOF'
{"Time":"2026-06-23T00:00:00Z","Action":"run","Package":"internal/objectstore","Test":"TestComposeS3RealEngineServes"}
{"Time":"2026-06-23T00:00:00Z","Action":"output","Package":"internal/objectstore","Test":"TestComposeS3RealEngineServes","Output":"=== RUN   TestComposeS3RealEngineServes\n"}
{"Time":"2026-06-23T00:00:00Z","Action":"output","Package":"internal/objectstore","Test":"TestComposeS3RealEngineServes","Output":"    compose_s3_test.go:42: OCU_S3_TEST_ENDPOINT unset; skipping live s3 leg\n"}
{"Time":"2026-06-23T00:00:00Z","Action":"skip","Package":"internal/objectstore","Test":"TestComposeS3RealEngineServes","Elapsed":0}
{"Time":"2026-06-23T00:00:00Z","Action":"pass","Package":"internal/objectstore","Elapsed":0.123}
EOF

# RED #2: the target is entirely ABSENT — a different test passed, the suite
# ran green, but the liveness test was never compiled/selected at all.
cat >"$work/absent.json" <<'EOF'
{"Time":"2026-06-23T00:00:00Z","Action":"run","Package":"internal/objectstore","Test":"TestSomethingElse"}
{"Time":"2026-06-23T00:00:00Z","Action":"output","Package":"internal/objectstore","Test":"TestSomethingElse","Output":"--- PASS: TestSomethingElse (0.00s)\n"}
{"Time":"2026-06-23T00:00:00Z","Action":"pass","Package":"internal/objectstore","Test":"TestSomethingElse","Elapsed":0}
{"Time":"2026-06-23T00:00:00Z","Action":"pass","Package":"internal/objectstore","Elapsed":0.456}
EOF

# RED #3: PARTIAL — the cmd leg passed but the filesapi leg SKIPPED. This proves
# the gate asserts EACH target independently: one leg silently skipping (e.g. a
# package left out of the go test line, or an env var that reaches one suite but
# not the other) must fail closed even though the other leg is green.
cat >"$work/partial.json" <<'EOF'
{"Time":"2026-06-23T00:00:00Z","Action":"run","Package":"internal/objectstore","Test":"TestComposeS3RealEngineServes"}
{"Time":"2026-06-23T00:00:09Z","Action":"pass","Package":"internal/objectstore","Test":"TestComposeS3RealEngineServes","Elapsed":0.01}
{"Time":"2026-06-23T00:00:10Z","Action":"run","Package":"internal/filesapi","Test":"TestFilesAPIRealS3EngineRoundTrip"}
{"Time":"2026-06-23T00:00:10Z","Action":"output","Package":"internal/filesapi","Test":"TestFilesAPIRealS3EngineRoundTrip","Output":"    real_engine_leg_test.go:185: OCU_S3_TEST_ENDPOINT not set - filesapi real-engine leg SKIPPED\n"}
{"Time":"2026-06-23T00:00:10Z","Action":"skip","Package":"internal/filesapi","Test":"TestFilesAPIRealS3EngineRoundTrip","Elapsed":0}
{"Time":"2026-06-23T00:00:10Z","Action":"pass","Package":"internal/filesapi","Elapsed":0.9}
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

# RED #3 (partial: one leg passed, the other skipped) must exit non-zero.
if "$ASSERT" "$work/partial.json" >/dev/null 2>&1; then
  echo "FAIL  RED #3 : assertion exited 0 when one leg SKIPPED (false-GREEN on a partial run)"
  fail=1
else
  echo "PASS  RED #3 : assertion exited non-zero when one leg skipped (each target asserted independently)"
fi

if [ "$fail" -ne 0 ]; then
  echo "::error::s3-leg liveness gate is not two-sided-correct — see failures above" >&2
  exit 1
fi

echo "red-probe: s3-leg liveness gate is two-sided-correct (GREEN->0, SKIP->!=0, ABSENT->!=0, PARTIAL->!=0)"
