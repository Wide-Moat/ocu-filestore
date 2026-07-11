# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Red-probe for scripts/mutation-floor.sh: proves the armed floor is red-CAPABLE
# and NON-VACUOUS. The red must come from a genuine score-below-floor comparison
# on a real parsed score, never from a tooling failure that produced no score.
#
# Method: run the REAL go-mutesting lens on one custody package, once with a floor
# ABOVE the measured score (must FAIL on the comparison) and once with the shipped
# floor 80 (must PASS). The score is identical between the two runs; only the floor
# moves, so a RED here can only be the threshold firing. The high floor is 101, not
# 100: both custody packages measure a full 100% at the shipped settings, and the
# comparison is strict `-lt`, so a floor of 100 would NOT red a 100% score (100 is
# not < 100). 101 is unreachable by construction, so the high-floor run always reds
# on a real below-floor comparison regardless of the exact score. Two extra
# assertions defeat the vacuous-pass classes:
#   1. the high-floor run must report a real parsed score AND the below-floor
#      message, NOT the "no mutation score parsed" tool-failure path (that would
#      be a fake red from a killed/crashed run, not a threshold breach);
#   2. the floor-80 run must pass, proving the same real score clears the
#      shipped floor (so the RED was the floor moving, not a broken measurement).
# Scoped to a rig-free custody package (default internal/authz, the fastest) so
# go-mutesting runs without MinIO or the peer-credential socket.

set -u

PKG="${REDPROBE_PKG:-./internal/authz/...}"
HI_FLOOR="${REDPROBE_HI_FLOOR:-101}"
export MUTATION_PKGS="$PKG"
HERE="$(dirname "$0")"

echo "=== red-probe: floor ${HI_FLOOR} over ${PKG} (score < ${HI_FLOOR} -> expect RED) ==="
hi_out="$(MUTATION_FLOOR="$HI_FLOOR" bash "${HERE}/mutation-floor.sh" 2>&1)"; hi_rc=$?
printf '%s\n' "$hi_out"
if [ "$hi_rc" -eq 0 ]; then
  echo "PROBE UNSOUND: floor ${HI_FLOOR} did not red. The gate is vacuous." >&2
  exit 1
fi
# Non-vacuous guard 1: the red must be a real score comparison, not a no-score
# tool failure.
if printf '%s\n' "$hi_out" | grep -q 'no mutation score parsed'; then
  echo "PROBE UNSOUND: floor ${HI_FLOOR} redded on a NO-SCORE tool failure, not on" >&2
  echo "               the threshold comparison. Re-run without a killed go-mutesting." >&2
  exit 1
fi
if ! printf '%s\n' "$hi_out" | grep -q "is below the ${HI_FLOOR}% floor"; then
  echo "PROBE UNSOUND: floor ${HI_FLOOR} redded but not on the expected below-floor" >&2
  echo "               message. The red is not the score comparison." >&2
  exit 1
fi
# Record the real parsed score for the control assertion.
hi_score="$(printf '%s\n' "$hi_out" | grep -oE 'parsed score [0-9]+%' | head -1)"
echo "OK: floor ${HI_FLOOR} redded on a REAL below-floor comparison (${hi_score})"

echo ""
echo "=== control: floor 80 over ${PKG} (score >= 80 -> expect GREEN) ==="
lo_out="$(MUTATION_FLOOR=80 bash "${HERE}/mutation-floor.sh" 2>&1)"; lo_rc=$?
printf '%s\n' "$lo_out"
if [ "$lo_rc" -ne 0 ]; then
  echo "PROBE UNSOUND: floor 80 redded. Either the score is below the shipped floor" >&2
  echo "               or the measurement broke." >&2
  exit 1
fi
echo "OK: floor 80 passed (same real score clears the shipped floor)"

echo ""
echo "mutation-floor red-probe: PASSED (real score reds above it, greens at the shipped floor)"
