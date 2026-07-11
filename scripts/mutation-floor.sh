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
# HARDENING: the go-mutesting score formula counts SKIPPED mutants in the
# numerator (score = (killed + error + skipped) / total). A skipped mutant is one
# whose `go test -timeout` exited non-zero-without-a-verdict (a timeout, or a
# compile-broken mutant), so a run where every mutant skips would report a fake
# 1.000000 and pass any floor while no test asserted on anything. The in-scope
# suites finish in about a second (rapid runs the whole property set well inside
# the per-mutant timeout below), so no skip occurs today; the guard below fails
# the gate closed if that ever changes - a slower runner, a fatter dependency, or
# a new slow property test that pushes a mutant past the timeout. The guard also
# fails closed when no mutant reaches a PASS/FAIL verdict at all (a misconfigured
# package path generating zero mutants: "100% of nothing").
#
#   EXEC_TIMEOUT=60: per-mutant `go test -timeout`, up from the tool default 10s.
#     Not required for correctness (the guard reds a timeout storm either way),
#     but it keeps a legitimately-slow-but-honest suite from tripping the guard on
#     a loaded runner, so nobody is tempted to weaken the guard to "fix" a flake.
#
# The floor is FLOOR, an integer percent. A package whose go-mutesting score
# falls below FLOOR/100 fails the script (exit 1). FLOOR defaults to a value
# below the measured baselines; the caller may raise it as the ratchet target
# is approached.
#
# Measured baselines (local, full rapid, exec-timeout 60):
#   internal/authz  : 16/16 killed (1.000000)
#   internal/broker : 52/52 killed (1.000000, 1 duplicated)
# FLOOR default 80 sits below both, so a real regression reds while the score's
# small run-to-run wobble (duplicate/equivalent-mutant classification) does not.

set -u

FLOOR="${MUTATION_FLOOR:-80}"

# Per-mutant `go test -timeout`, in seconds. Overridable only to red-probe the
# skip guard (a real skip is otherwise unreachable: the suites finish far inside
# any sane timeout, and an over-sleeping test panics -> FAIL -> counted killed,
# never skipped).
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

# EXTERNAL HARD TIMEOUT per go-mutesting invocation. go-mutesting's --exec-timeout
# is NOT reliably enforced (its custom executor path carries a `// TODO timeout`),
# so a mutant whose `go test` blocks in a syscall can hang the whole run
# indefinitely - which in CI would run to the job cap. Bound each invocation
# externally: on a hang, the process is killed, go-mutesting emits no score line,
# and the no-score guard below reds the gate LOUDLY instead of hanging. A required
# gate must never hang. Uses coreutils `timeout` when present, else a perl alarm.
INVOCATION_TIMEOUT="${MUTATION_INVOCATION_TIMEOUT:-600}"

# BLACKLIST of known go-mutesting-hanging mutant checksums. go-mutesting mutates in
# a deterministic AST order, so a hanging mutant reproduces with the same MD5 every
# run and is excluded by checksum. go-mutesting's built-in executor hangs on
# internal/authz branch/if-flip mutants: each COMPILES then blocks the executor in
# a syscall (~0% CPU, never returns; the tool's per-mutant timeout is unenforced -
# the `// TODO timeout` path). This is a go-mutesting defect, NOT a code defect
# (resolver.go has no loop; the range in intentGranted is finite over a slice).
# Because the hang is a whole CLASS (if-flips), this gate is scheduled NIGHTLY not
# per-PR (see mutation.yml): the external timeout above turns any UNLISTED hang
# into a red an owner triages, while the listed checksums let the nightly measure a
# real score. Excluded so far (both confirmed stable across runs):
#   49c3159a2b715624220d71abdcc5866c - internal/authz/resolver.go, a branch/if flip
#   6bbe942ee9d83d013b214fc59aefd94b - internal/authz/resolver.go, a second if flip
BLACKLIST="$(cd "$(dirname "$0")" && pwd)/mutation-blacklist.txt"

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

# Assemble the blacklist flag only if the file exists and is non-empty (an empty
# --blacklist file makes go-mutesting error).
bl_flag=""
if [ -s "$BLACKLIST" ]; then
  bl_flag="--blacklist=${BLACKLIST}"
fi

rc=0
for pkg in $PKGS; do
  echo "--- go-mutesting ${pkg} (floor ${FLOOR}%, exec-timeout=${EXEC_TIMEOUT}s, invocation-timeout=${INVOCATION_TIMEOUT}s) ---"
  # Capture the run; go-mutesting prints one line:
  #   The mutation score is <f> (<killed> passed, <escaped> failed, <dup> duplicated, <skipped> skipped, total is <n>)
  out="$(bounded_mutesting --exec-timeout "${EXEC_TIMEOUT}" ${bl_flag} "$pkg" 2>&1)" || true
  echo "$out" | tail -1
  score_line="$(printf '%s\n' "$out" | grep -E 'mutation score is' | tail -1)"
  if [ -z "$score_line" ]; then
    echo "::error::no mutation score parsed for ${pkg} (go-mutesting produced no score line)" >&2
    rc=1
    continue
  fi

  # HARD SKIP / NO-VERDICT GUARD (see header). Parse the counts out of the summary
  # line and fail closed on any anomaly. skipped counts as killed in the score
  # formula, so a skip would fake-inflate; a zero-verdict run measured nothing.
  killed="$(printf '%s\n' "$score_line" | sed -n 's/.*is [0-9.]* (\([0-9]*\) passed.*/\1/p')"
  escaped="$(printf '%s\n' "$score_line" | sed -n 's/.* passed, \([0-9]*\) failed.*/\1/p')"
  skipped="$(printf '%s\n' "$score_line" | sed -n 's/.*duplicated, \([0-9]*\) skipped.*/\1/p')"
  # Fail closed on an UNPARSABLE summary: a go-mutesting version bump could change
  # the line and silently disarm the guard (an empty count in `[ "" -gt 0 ]` is a
  # bash error, not a false). Require all three counts to have parsed.
  if [ -z "$killed" ] || [ -z "$escaped" ] || [ -z "$skipped" ]; then
    echo "::error::${pkg} summary line did not parse into killed/escaped/skipped counts - go-mutesting output format may have changed. Fail closed rather than trust an unparsed line: ${score_line}" >&2
    rc=1
    continue
  fi
  if [ "$skipped" -gt 0 ]; then
    echo "::error::${pkg} produced ${skipped} skipped mutant(s) - a mutant that did not reach a real test verdict (timeout, or a compile-broken mutant). go-mutesting counts skipped as killed, so this would fake-inflate the score. Fail closed; raise --exec-timeout, then re-run." >&2
    rc=1
    continue
  fi
  if [ "$killed" -eq 0 ] && [ "$escaped" -eq 0 ]; then
    echo "::error::${pkg} had no mutant reach a PASS/FAIL verdict (killed=0, escaped=0). The suite never ran against a mutant; the score is meaningless. Fail closed." >&2
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
  echo "parsed score ${score_pct}% for ${pkg} (killed=${killed}, escaped=${escaped}, skipped=${skipped}, floor ${FLOOR}%)"
  if [ "$score_pct" -lt "$FLOOR" ]; then
    echo "::error::${pkg} mutation score ${score_pct}% is below the ${FLOOR}% floor" >&2
    rc=1
  fi
done

if [ "$rc" -ne 0 ]; then
  echo "mutation-floor: FAILED (a package fell below the ${FLOOR}% floor, produced a skipped/no-verdict mutant, or emitted an unparsable summary)" >&2
  exit 1
fi
echo "mutation-floor: all custody packages at or above the ${FLOOR}% floor, no skipped mutants"
