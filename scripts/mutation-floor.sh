# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Armed mutation-score floor over the custody-relevant packages, measured with
# go-mutesting (github.com/avito-tech/go-mutesting, avito-tech fork pinned to the
# pseudo-version below).
#
# Why go-mutesting and not gremlins for the ARMED gate: gremlins kills a mutant
# by re-running the suite under a timeout it calibrates from one clean run. The
# in-scope suites carry pgregory.net/rapid property tests that gremlins re-runs
# per mutant, so real mutants land in the timed-out bucket and BOTH gremlins
# dimensions (efficacy and mutant-coverage) collapse to a load-driven number.
# Arming a gremlins threshold there would red on runner timing, not on a real
# assertion regression  -  a flaky-required gate. go-mutesting resolves packages
# via `go list` and kills on real test PASS/FAIL, so its score is armable. The
# gremlins job stays advisory (its coverage now reads real, useful as a surfaced
# signal, but its kill stays timing-flaky).
#
# EXECUTION: every mutant runs through scripts/mutation-exec.sh (a go-mutesting
# custom --exec script) rather than the tool's built-in executor. Neither path
# is bounded by the tool itself: `go test -timeout` arms only once the test
# binary runs (compile and init time sit outside it) and the custom-exec path
# applies no timeout at all (an unenforced TODO in the tool). Whole runs have
# wedged indefinitely under environmental pressure (two mutation walks over
# one working tree corrupt each other; never run them concurrently), and an
# ARMED nightly gate must be hang-proof by construction, not by assuming a
# quiet runner. The exec script therefore hard-KILLs the test run at
# MUTATE_TIMEOUT + 30s and maps the timeout to KILLED - a mutant that hangs the
# suite IS detected (the suite would never let it ship). Each timeout is logged
# so the STORM guard below can red when timeouts stop being an exception.
#
# HARDENING - the gate fails CLOSED on every anomaly the score formula would
# otherwise absorb silently. The formula counts killed + errored + skipped in
# the numerator; the summary line prints killed (passed), escaped (failed),
# duplicated, skipped and total, but NOT errored:
#   - skipped > 0: a skip is a mutant that did not compile (the exec script
#     exits 2 only there; timeouts are killed, not skipped). Skips inflate the
#     numerator without any test asserting on anything -> red.
#   - errored > 0 (computed as total - killed - escaped - skipped): errored
#     mutants inflate the numerator INVISIBLY - the line does not print them.
#     An exec-script anomaly (a signal death, an unknown exit) lands here -> red.
#   - killed == 0 && escaped == 0: no mutant reached a PASS/FAIL verdict
#     ("100% of nothing", e.g. a misconfigured package path) -> red.
#   - unparsable summary line: a tool version bump could change the format and
#     silently disarm all of the above -> red rather than trust it.
#   - timeout STORM: more than 25% of verdicts reached only via the external
#     hard kill means the measurement is sick (a loaded runner, a broken
#     suite), not that assertions got stronger -> red for owner triage.
#
#   EXEC_TIMEOUT=60: feeds go-mutesting --exec-timeout, which the exec script
#     receives as MUTATE_TIMEOUT: the inner `go test -timeout`, plus +30s for
#     the external hard KILL (compile time sits outside the Go-level flag).
#
# The floor is FLOOR, an integer percent. A package whose go-mutesting score
# falls below FLOOR/100 fails the script (exit 1). FLOOR defaults to a value
# below the measured baselines; the caller may raise it as the ratchet target
# is approached.
#
# Measured baselines (local, full rapid, exec script, no exclusions):
#   internal/authz  : 16/16 killed (1.000000, 1 duplicated, 0 timeouts)
#   internal/broker : 49/52 killed (0.942308, 0 timeouts). The 3 survivors are
#     equivalent mutants, each sitting on a deliberate defence-in-depth
#     redundancy: the empty-after-TrimSpace prefix drop (re-dropped by the
#     bare-root drop below it), the empty-path pre-check (re-refused by the
#     filepath.Clean equality guard), and the "continue" after the "*" token
#     (prefixes after "*" are never consulted - the match-all shortcut
#     precedes the prefix loop). Killing them means deleting the redundancy.
# FLOOR default 80 sits below both, so a real regression reds while the score's
# small run-to-run wobble (duplicate/equivalent-mutant classification) does not.

set -u

FLOOR="${MUTATION_FLOOR:-80}"

# Per-mutant test timeout, in seconds. Passed to go-mutesting as --exec-timeout
# and surfaced to the exec script as MUTATE_TIMEOUT (inner `go test -timeout`;
# the script adds +30s for its external hard KILL). Overridable to red-probe
# the timeout path with an artificially tiny window.
EXEC_TIMEOUT="${MUTATION_EXEC_TIMEOUT:-60}"

# Custody-relevant packages: the authorization resolver and the downloadable /
# credential-scope broker. These carry no live-rig dependency, so go-mutesting
# runs them without MinIO or the peer-credential socket. Full rapid: the suites
# are fast, so more property iterations per mutant only sharpen the oracle.
PKGS="${MUTATION_PKGS:-./internal/authz/... ./internal/broker/...}"

if ! command -v go-mutesting >/dev/null 2>&1; then
  echo "go-mutesting not found. Install with:" >&2
  echo "  go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@v0.0.0-20251226130216-48d0401f00fb" >&2
  exit 2
fi

# The per-mutant exec script (timeout-as-killed; see the header). go-mutesting
# splits --exec on spaces, so the checkout path must not contain one.
EXEC_SCRIPT="$(cd "$(dirname "$0")" && pwd)/mutation-exec.sh"
case "$EXEC_SCRIPT" in
  *" "*)
    echo "::error::checkout path contains a space; go-mutesting splits --exec on spaces and cannot address ${EXEC_SCRIPT}" >&2
    exit 2
    ;;
esac
if [ ! -x "$EXEC_SCRIPT" ]; then
  echo "::error::${EXEC_SCRIPT} is missing or not executable" >&2
  exit 2
fi

# WHOLE-INVOCATION backstop, per go-mutesting invocation. The exec script
# bounds every mutant, so a healthy run cannot approach this; it catches a
# hang OUTSIDE the per-mutant path (the tool itself wedging). On expiry the
# process group is killed, no score line is emitted, and the no-score guard
# reds the gate LOUDLY instead of hanging. A required gate must never hang.
INVOCATION_TIMEOUT="${MUTATION_INVOCATION_TIMEOUT:-900}"

bounded_mutesting() {
  if command -v timeout >/dev/null 2>&1; then
    # coreutils timeout kills the whole process group on expiry (CI/Linux path).
    timeout --signal=KILL "${INVOCATION_TIMEOUT}" go-mutesting "$@"
  else
    # Fallback for hosts without coreutils (macOS). A plain `alarm; exec` cannot
    # reap go-mutesting's child `go test` tree on a hang, so run go-mutesting in a
    # new session and SIGKILL the whole group on the alarm.
    perl -e '
      use POSIX qw(setsid);
      my $t = shift;
      my $pid = fork();
      if ($pid == 0) { setsid(); exec @ARGV or die "exec: $!"; }
      $SIG{ALRM} = sub { kill(-9, $pid); waitpid($pid, 0); exit 124; };
      alarm $t;
      waitpid($pid, 0);
      exit($? >> 8);
    ' "${INVOCATION_TIMEOUT}" go-mutesting "$@"
  fi
}

rc=0
for pkg in $PKGS; do
  echo "--- go-mutesting ${pkg} (floor ${FLOOR}%, exec-timeout=${EXEC_TIMEOUT}s, invocation-timeout=${INVOCATION_TIMEOUT}s) ---"
  # Per-package timeout log: the exec script appends one line per mutant whose
  # verdict came from the external hard kill; the storm guard reads it below.
  tlog="$(mktemp)"
  # Capture the run; go-mutesting prints one line:
  #   The mutation score is <f> (<killed> passed, <escaped> failed, <dup> duplicated, <skipped> skipped, total is <n>)
  out="$(MUTATION_TIMEOUT_LOG="$tlog" bounded_mutesting --exec "$EXEC_SCRIPT" --exec-timeout "${EXEC_TIMEOUT}" "$pkg" 2>&1)" || true
  echo "$out" | tail -1

  # A KILLed invocation (or a KILLed exec script) can leave a mutant swapped
  # into the working tree with the original parked at <file>.tmp. Restore
  # before anything else so a red never leaves the tree mutated.
  find . -name '*.go.tmp' 2>/dev/null | while IFS= read -r t; do
    mv "$t" "${t%.tmp}"
  done

  timeouts="$(wc -l < "$tlog" | tr -d ' ')"
  rm -f "$tlog"

  score_line="$(printf '%s\n' "$out" | grep -E 'mutation score is' | tail -1)"
  if [ -z "$score_line" ]; then
    echo "::error::no mutation score parsed for ${pkg} (go-mutesting produced no score line)" >&2
    rc=1
    continue
  fi

  # HARD GUARDS (see header). Parse the counts out of the summary line and fail
  # closed on any anomaly.
  killed="$(printf '%s\n' "$score_line" | sed -n 's/.*is [0-9.]* (\([0-9]*\) passed.*/\1/p')"
  escaped="$(printf '%s\n' "$score_line" | sed -n 's/.* passed, \([0-9]*\) failed.*/\1/p')"
  skipped="$(printf '%s\n' "$score_line" | sed -n 's/.*duplicated, \([0-9]*\) skipped.*/\1/p')"
  total="$(printf '%s\n' "$score_line" | sed -n 's/.*total is \([0-9]*\)).*/\1/p')"
  # Fail closed on an UNPARSABLE summary: a go-mutesting version bump could change
  # the line and silently disarm the guards (an empty count in `[ "" -gt 0 ]` is a
  # bash error, not a false). Require all four counts to have parsed.
  if [ -z "$killed" ] || [ -z "$escaped" ] || [ -z "$skipped" ] || [ -z "$total" ]; then
    echo "::error::${pkg} summary line did not parse into killed/escaped/skipped/total counts - go-mutesting output format may have changed. Fail closed rather than trust an unparsed line: ${score_line}" >&2
    rc=1
    continue
  fi
  if [ "$skipped" -gt 0 ]; then
    echo "::error::${pkg} produced ${skipped} skipped mutant(s) - a mutant that did not compile. Skips count in the score numerator with no test asserting on anything, so this would fake-inflate the score. Fail closed; triage the non-compiling mutant, then re-run." >&2
    rc=1
    continue
  fi
  errored=$((total - killed - escaped - skipped))
  if [ "$errored" -ne 0 ]; then
    echo "::error::${pkg} produced ${errored} errored mutant(s) (total ${total} vs killed ${killed} + escaped ${escaped} + skipped ${skipped}). Errored mutants count in the score numerator WITHOUT appearing in the summary line - an invisible inflation. Fail closed; an exec-script anomaly (signal death, unknown exit) is the usual cause." >&2
    rc=1
    continue
  fi
  if [ "$killed" -eq 0 ] && [ "$escaped" -eq 0 ]; then
    echo "::error::${pkg} had no mutant reach a PASS/FAIL verdict (killed=0, escaped=0). The suite never ran against a mutant; the score is meaningless. Fail closed." >&2
    rc=1
    continue
  fi

  # TIMEOUT STORM guard: timeout-as-killed is sound for the odd hang-class
  # mutant, but when a quarter of all verdicts come only from the hard kill the
  # measurement itself is sick (a loaded runner, a broken suite) - the score no
  # longer reflects assertion strength. Red for owner triage.
  verdicts=$((killed + escaped))
  if [ "$timeouts" -gt 0 ]; then
    echo "note: ${timeouts} of ${verdicts} verdict(s) for ${pkg} came from the external hard timeout (timeout-as-killed)"
  fi
  if [ $((timeouts * 4)) -gt "$verdicts" ]; then
    echo "::error::${pkg}: ${timeouts} of ${verdicts} verdicts are timeout-kills (over the 25% storm ceiling). The measurement is dominated by hard kills, not assertions. Fail closed; triage the runner or the suite." >&2
    rc=1
    continue
  fi

  # Extract the float, scale to an integer percent (x100, truncated) with awk so
  # the comparison needs no floating-point shell arithmetic.
  score_pct="$(printf '%s\n' "$score_line" \
    | awk '{for(i=1;i<=NF;i++) if($i+0==$i){printf "%d", $i*100; exit}}')"
  if [ -z "$score_pct" ]; then
    echo "::error::could not parse a numeric score from: ${score_line}" >&2
    rc=1
    continue
  fi
  echo "parsed score ${score_pct}% for ${pkg} (killed=${killed}, escaped=${escaped}, skipped=${skipped}, timeouts=${timeouts}, floor ${FLOOR}%)"
  if [ "$score_pct" -lt "$FLOOR" ]; then
    echo "::error::${pkg} mutation score ${score_pct}% is below the ${FLOOR}% floor" >&2
    rc=1
  fi
done

if [ "$rc" -ne 0 ]; then
  echo "mutation-floor: FAILED (a package fell below the ${FLOOR}% floor or tripped a fail-closed guard: skipped/errored/no-verdict mutants, a timeout storm, or an unparsable summary)" >&2
  exit 1
fi
echo "mutation-floor: all custody packages at or above the ${FLOOR}% floor, no skipped/errored mutants, timeouts under the storm ceiling"
