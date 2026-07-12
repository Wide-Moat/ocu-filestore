#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# go-mutesting custom exec script: one bounded test run per mutant.
#
# Contract (verified against the pinned go-mutesting source, cmd/go-mutesting/main.go):
#   - go-mutesting invokes this script once per mutant with MUTATE_CHANGED,
#     MUTATE_ORIGINAL, MUTATE_PACKAGE and MUTATE_TIMEOUT in the environment.
#     The script itself swaps the mutant into place, runs the suite, restores
#     the original (the tool does none of that on the custom-exec path).
#   - The script's EXIT CODE is the verdict, taken directly by go-mutesting:
#       0     -> mutant KILLED (the suite FAILED on the mutant - the good outcome)
#       1     -> mutant ESCAPED (the suite PASSED - an assertion gap)
#       2     -> SKIP (the mutant did not compile)
#       other -> an errored bucket that the score formula counts in the
#                NUMERATOR without printing it in the summary line;
#                mutation-floor.sh reds on it via the total-vs-parts
#                cross-check, so an unknown exit here fails closed at the
#                floor instead of silently inflating the score.
#     Note the INVERSION relative to `go test`: a failing suite means the
#     mutant was caught, so `go test` exit 1 maps to script exit 0 and vice
#     versa (same mapping as the tool's built-in executor).
#   - go-mutesting applies NO timeout to this script (its custom-exec path
#     carries an unenforced timeout TODO), so the script bounds the test run
#     ITSELF: an external hard KILL at MUTATE_TIMEOUT + 30 seconds. The +30s
#     covers package recompilation - `go test -timeout` arms only once the
#     test binary is running, so compile time is outside the Go-level flag.
#   - TIMEOUT-AS-KILLED: a mutant whose test run had to be externally killed
#     IS detected - a suite that hangs on a mutant would never let it ship.
#     Such a mutant exits 0 (killed) and appends one line to
#     MUTATION_TIMEOUT_LOG (when set) so mutation-floor.sh can red on a
#     timeout STORM: many timeouts mean the measurement is sick (a loaded
#     runner, a broken suite), not that the assertions got stronger.

set -u

for v in MUTATE_CHANGED MUTATE_ORIGINAL MUTATE_PACKAGE; do
  eval "val=\${$v:-}"
  if [ -z "$val" ]; then
    echo "mutation-exec: $v is not set" >&2
    exit 3
  fi
done

MUTATE_TIMEOUT="${MUTATE_TIMEOUT:-60}"
HARD_TIMEOUT=$((MUTATE_TIMEOUT + 30))

restore() {
  if [ -f "${MUTATE_ORIGINAL}.tmp" ]; then
    mv "${MUTATE_ORIGINAL}.tmp" "$MUTATE_ORIGINAL"
  fi
}
# On an outer signal (e.g. the whole-invocation timeout in mutation-floor.sh
# TERMs the group before the KILL), restore the original and exit into the
# errored bucket - never leave the mutant swapped in silently.
trap 'restore; exit 3' HUP INT TERM

mv "$MUTATE_ORIGINAL" "${MUTATE_ORIGINAL}.tmp"
cp "$MUTATE_CHANGED" "$MUTATE_ORIGINAL"

pkg="$MUTATE_PACKAGE"
if [ -n "${TEST_RECURSIVE:-}" ]; then
  pkg="${pkg}/..."
fi

# Per-mutant test output is discarded: go-mutesting already prints the diff of
# every escaped mutant, which is the artifact a triage needs.
if command -v timeout >/dev/null 2>&1; then
  # coreutils timeout (the CI/Linux path). --signal=KILL cannot be blocked by
  # a wedged test binary; expiry surfaces as exit 137 (128+9).
  timeout --signal=KILL "$HARD_TIMEOUT" \
    go test -timeout "${MUTATE_TIMEOUT}s" "$pkg" >/dev/null 2>&1
  rc=$?
else
  # Hosts without coreutils (macOS): run `go test` in its own session and
  # SIGKILL the whole group on the alarm, exit 124. A child that died on a
  # signal maps to 128+n so it lands in the errored bucket, never in a
  # verdict it did not earn.
  perl -e '
    use POSIX qw(setsid);
    my $t = shift;
    my $pid = fork();
    if ($pid == 0) {
      setsid();
      open(STDOUT, ">", "/dev/null");
      open(STDERR, ">", "/dev/null");
      exec @ARGV or die "exec: $!";
    }
    $SIG{ALRM} = sub { kill(-9, $pid); waitpid($pid, 0); exit 124; };
    alarm $t;
    waitpid($pid, 0);
    if ($? & 127) { exit(128 + ($? & 127)); }
    exit($? >> 8);
  ' "$HARD_TIMEOUT" go test -timeout "${MUTATE_TIMEOUT}s" "$pkg"
  rc=$?
fi

restore

case "$rc" in
  0)
    # Suite passed on the mutant -> ESCAPED.
    exit 1
    ;;
  1)
    # Suite failed on the mutant -> KILLED.
    exit 0
    ;;
  2)
    # Did not compile -> SKIP. mutation-floor.sh fails closed on any skip
    # (skips count in the score numerator), so this reds the nightly loudly.
    exit 2
    ;;
  124|137)
    # External hard timeout (124 = perl alarm, 137 = coreutils KILL):
    # the hang-class mutant. Killed by definition, logged for the storm guard.
    if [ -n "${MUTATION_TIMEOUT_LOG:-}" ]; then
      echo "TIMEOUT ${MUTATE_PACKAGE} ${MUTATE_CHANGED}" >>"$MUTATION_TIMEOUT_LOG"
    fi
    exit 0
    ;;
  *)
    # Unknown exit (a signal death, a tool anomaly) -> errored bucket; the
    # floor's total-vs-parts cross-check reds on it.
    exit "$rc"
    ;;
esac
