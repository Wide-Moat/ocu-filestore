#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Red-probe the SECRETS gate: prove both required contexts redden on a planted
# credential.
#
# `.github/workflows/security.yml` publishes two required check contexts for
# secrets, and neither job declares a `name:`, so each context string is
# byte-identical to its job id:
#
#   secrets-gitleaks    -- docker zricethezav/gitleaks:v8.30.1,
#                          `detect --source=/repo --redact --no-banner`
#   secrets-trufflehog  -- the trufflehog action over the fetch-depth:0
#                          checkout with `--no-verification` (`--fail` is
#                          appended by the action entrypoint)
#
# A gate that has never been shown to fail is indistinguishable from a gate
# that cannot fail, and proving ONE scanner reddens says nothing about the
# other: they share no ruleset, no config file and no detector. So every leg
# here runs BOTH scanners and attributes findings PER SCANNER.
#
# Legs:
#   clean      the committed tree at REF, untouched      -> both scanners green
#   dirty      that tree plus planted credentials        -> both scanners red,
#                                                           each naming every
#                                                           planted file
#   allowlist  that tree plus the documented AWS example -> gitleaks green
#              value, at a path under docs/
#
# The allowlist leg is the control for this repository's own `.gitleaks.toml`.
# That file carries `[extend] useDefault = true` plus a single exact-value
# allowlist for the public AWS-documentation secret. An allowlist is one
# `paths = [...]` line away from blanketing a whole directory, and a blanket
# is invisible from a green gate. The leg is a control in BOTH directions: the
# documented value under docs/ must stay green, while the dirty leg plants a
# RANDOM AWS key at a sibling path under the same docs/ directory and must go
# red. Same directory, same file shape, only the value differs -- which is what
# separates "scoped to one constant" from "suppresses docs/".
#
# Discipline this probe is built to, each rule earned by a real defect:
#
#  * Never mount a git worktree into a scanner container. In a worktree `.git`
#    is a FILE pointing at the parent repo, which does not resolve inside the
#    container; the scanner then walks nothing and reports "0 findings, exit 0"
#    -- indistinguishable from success on the clean leg, and a false product
#    finding on the dirty leg. Every tree here comes from `git clone
#    --no-local` (whose `.git` is a real directory) and every tree is guarded
#    by an explicit directory test immediately before it is scanned.
#  * The gitleaks config is read with `git show REF:.gitleaks.toml`, never from
#    the working tree. A working-tree read that misses lets the scanner fall
#    back to a default ruleset and answer for a config the branch does not
#    have.
#  * Payloads are drawn from /dev/urandom, never from vendor documentation.
#    Every credential printed in a vendor's docs is in the scanners' allowlists
#    by construction -- otherwise the scanner would redden on the vendor's own
#    README -- so a documentation-sourced payload is guaranteed not to fire.
#  * Every payload is preflighted: it must fire on its own, under BOTH
#    scanners, before it is planted. The AWS rules apply an entropy threshold
#    and a random draw misses it in roughly one run in fifteen, so the draw is
#    retried. Retrying is what separates "this class is undetected", which is a
#    finding, from "this draw was unlucky", which is noise.
#  * Delivery is checked with `git cat-file -e HEAD:<payload>`, not with a
#    scanned-byte delta. Both scanners read commits; an unstaged payload is
#    invisible to them, and a byte delta has reported "delivered" when nothing
#    was.
#  * Scope is checked against an INDEPENDENT source: the scanner's own commit
#    count must equal `git rev-list --count HEAD` on the clone. Comparing a run
#    to a previous run of the same tool catches drift but not systematic error.
#  * Findings are attributed by planted FILENAME and pinned to an expected
#    RULE/DETECTOR name. A finding total proves the gate reddened; it does not
#    prove it reddened on the payload, and a count check is satisfied by a
#    pre-existing secret elsewhere in the tree.
#
# Output hygiene: gitleaks runs with --redact, but trufflehog prints raw secret
# material. Scanner output is therefore never echoed; only extracted
# (rule, file) pairs and the tools' own summary lines are printed. Use --keep
# to retain the raw logs under the work directory for local inspection.
#
# Usage:
#   scripts/secrets-gate-redprobe.sh [--ref REF] [--keep]
#
# Exit 0 only when every leg behaved in the asserted direction.

set -uo pipefail

REF="HEAD"
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:-}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '4,90p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Pinned to the tag security.yml runs. A movable tag would let the probe and
# the gate drift apart silently.
GITLEAKS_IMAGE='zricethezav/gitleaks:v8.30.1'

# The action pins trufflehog v3.95.7; that is the image this probe wants. If it
# is not present and cannot be pulled, fall back to any locally available
# trufflehog and say so loudly -- a version-drifted run is still evidence, a
# silently substituted one is not.
TRUFFLEHOG_WANT='trufflesecurity/trufflehog:v3.95.7'
TRUFFLEHOG_ALT='ghcr.io/trufflesecurity/trufflehog:v3.95.7'

command -v docker >/dev/null 2>&1 || { echo "FAIL: docker is required; the probe cannot run the real scanners" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "FAIL: the docker daemon is not reachable; the probe cannot run the real scanners" >&2; exit 2; }
git rev-parse --verify "$REF" >/dev/null 2>&1 || { echo "FAIL: no such ref: $REF" >&2; exit 2; }

have_image() { docker image inspect "$1" >/dev/null 2>&1; }

resolve_trufflehog() {
  for img in "$TRUFFLEHOG_WANT" "$TRUFFLEHOG_ALT"; do
    if have_image "$img"; then echo "$img"; return 0; fi
  done
  for img in "$TRUFFLEHOG_WANT" "$TRUFFLEHOG_ALT"; do
    if docker pull --quiet "$img" >/dev/null 2>&1; then echo "$img"; return 0; fi
  done
  # Nearest locally available build. Sorted so the pick is deterministic.
  docker image ls --format '{{.Repository}}:{{.Tag}}' \
    | grep -E '(^|/)trufflesecurity/trufflehog:' \
    | grep -v ':<none>$' \
    | sort -r | head -1
}

have_image "$GITLEAKS_IMAGE" || docker pull --quiet "$GITLEAKS_IMAGE" >/dev/null 2>&1
if ! have_image "$GITLEAKS_IMAGE"; then
  echo "FAIL: $GITLEAKS_IMAGE is not available locally and cannot be pulled."
  echo "      The probe does not simulate a scanner run. Reporting NOT RUN."
  exit 2
fi

TRUFFLEHOG_IMAGE="$(resolve_trufflehog)"
if [ -z "$TRUFFLEHOG_IMAGE" ]; then
  echo "FAIL: no trufflesecurity/trufflehog image is available locally and none can be pulled."
  echo "      The probe does not simulate a scanner run. Reporting NOT RUN."
  exit 2
fi

WORK="$(mktemp -d)"
cleanup() { if [ "$KEEP" -eq 1 ]; then echo "kept: $WORK"; else rm -rf "$WORK"; fi; }
trap cleanup EXIT

mkdir -p "$WORK/config"

echo "secrets-gate-redprobe: ref=$REF"
echo "  gitleaks image   : $GITLEAKS_IMAGE"
if [ "$TRUFFLEHOG_IMAGE" != "$TRUFFLEHOG_WANT" ] && [ "$TRUFFLEHOG_IMAGE" != "$TRUFFLEHOG_ALT" ]; then
  th_ver="$(docker image inspect "$TRUFFLEHOG_IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null)"
  echo "  trufflehog image : $TRUFFLEHOG_IMAGE (version ${th_ver:-unknown})"
  echo "  NOTE  version drift: security.yml pins the action at v3.95.7 and that image"
  echo "        could not be fetched here. The detectors exercised below are the same"
  echo "        classes, but this run does not prove the exact pinned build."
else
  echo "  trufflehog image : $TRUFFLEHOG_IMAGE"
fi

# ---------------------------------------------------------------------------
# Config, read from the ref under test.
# ---------------------------------------------------------------------------
if git cat-file -e "$REF:.gitleaks.toml" 2>/dev/null; then
  git show "$REF:.gitleaks.toml" > "$WORK/config/.gitleaks.toml"
  echo "ok   config: .gitleaks.toml read from $REF (not from the working tree)"
else
  echo "FAIL config: $REF has no .gitleaks.toml."
  echo "     security.yml runs gitleaks with no --config, so the root file is what the"
  echo "     gate loads. Probing against an invented default would answer for a config"
  echo "     this branch does not have."
  exit 1
fi
grep -q 'useDefault[[:space:]]*=[[:space:]]*true' "$WORK/config/.gitleaks.toml" || {
  echo "FAIL config: .gitleaks.toml at $REF does not set [extend] useDefault = true."
  echo "     A root config REPLACES the built-in ruleset; without the extend the gate"
  echo "     scans with zero rules and is vacuously green."
  exit 1
}

# ---------------------------------------------------------------------------
# Trees. Cloned, never mounted from a worktree.
# ---------------------------------------------------------------------------
SRC="$(git rev-parse --show-toplevel)"
git clone --no-local --quiet --no-checkout "$SRC" "$WORK/clean" || { echo "FAIL: clone failed"; exit 1; }
git -C "$WORK/clean" fetch --quiet "$SRC" "+$REF:refs/heads/probe-base" || { echo "FAIL: fetch of $REF failed"; exit 1; }

# Drop every ref except the one under test. A clone carries all of the source's
# branches and both scanners walk refs rather than the checkout, so without this
# the clean leg answers "clean across whatever branches happened to be cloned"
# while claiming to answer for REF. It is also what makes the scanned-commit
# count reproducible, and therefore usable as evidence at all.
git -C "$WORK/clean" for-each-ref --format='%(refname)' \
  | grep -v '^refs/heads/probe-base$' \
  | while read -r r; do git -C "$WORK/clean" update-ref -d "$r"; done
git -C "$WORK/clean" checkout --quiet probe-base
git -C "$WORK/clean" reflog expire --expire=now --all >/dev/null 2>&1
git -C "$WORK/clean" gc --prune=now --quiet >/dev/null 2>&1

cp -R "$WORK/clean" "$WORK/dirty"
cp -R "$WORK/clean" "$WORK/allow"

# Rule 1 guard, asserted immediately before any container ever sees the path.
assert_real_git_dir() {
  if [ ! -d "$1/.git" ]; then
    echo "FAIL scan-surface: $1/.git is not a directory."
    echo "     In a git worktree .git is a FILE pointing at the parent repo, which does"
    echo "     not resolve inside a container: the scanner walks zero bytes and reports"
    echo "     success. Refusing to scan."
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Payloads.
# ---------------------------------------------------------------------------
P_AWS='redprobe_planted_aws.txt'
P_PAT='redprobe_planted_pat.env'
P_KEY='redprobe_planted_key.pem'
P_DOC='docs/redprobe_planted_docs_aws.md'
P_CTL='docs/redprobe_allowlist_control.md'
PLANTED="$P_AWS $P_PAT $P_KEY $P_DOC"

rand() { LC_ALL=C tr -dc "$1" < /dev/urandom | head -c "$2"; }

draw_payloads() {
  local d="$1"
  mkdir -p "$d/docs"
  printf 'aws_access_key_id = AKIA%s\naws_secret_access_key = %s\n' \
    "$(rand 'A-Z0-9' 16)" "$(rand 'A-Za-z0-9/+' 40)" > "$d/$P_AWS"
  printf 'GITHUB_TOKEN=ghp_%s\n' "$(rand 'A-Za-z0-9' 36)" > "$d/$P_PAT"
  openssl genrsa 2048 2>/dev/null > "$d/$P_KEY"
  # Same directory as the allowlist control, random value. This is the arm that
  # proves the allowlist is not a docs/ blanket.
  printf 'aws_access_key_id = AKIA%s\naws_secret_access_key = %s\n' \
    "$(rand 'A-Z0-9' 16)" "$(rand 'A-Za-z0-9/+' 40)" > "$d/$P_DOC"
}

# The exact value this repository's .gitleaks.toml allowlists, in the two-line
# credential-file shape docs/engines.md and docs/operations.md use. It is the
# canonical AWS-documentation example secret: publicly published for over a
# decade, no authentication capability against any account.
write_allowlist_control() {
  mkdir -p "$(dirname "$1/$P_CTL")"
  printf 'access_key_id=AKIAEXAMPLE\nsecret_access_key=wJalrXUtnFEMI/K7MDENG\n' > "$1/$P_CTL"
}

commit_tree() {
  git -C "$1" add -A >/dev/null 2>&1
  git -C "$1" -c user.email=redprobe@local -c user.name=redprobe commit -qm "$2" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Scanner invocations. These mirror security.yml; the added flags change
# reporting, never detection:
#   gitleaks   --verbose is what prints the per-finding File: lines. Without it
#              only a count is printed and every per-file attribution check
#              silently matches nothing. --exit-code 1 makes the outcome usable.
#              --config points at the file extracted from REF, which is the same
#              file the gate auto-loads from the repository root.
#   trufflehog git mode over the full history, mirroring the action's
#              fetch-depth: 0 checkout. --no-update only suppresses the version
#              self-check. --fail is what the action's entrypoint appends.
# ---------------------------------------------------------------------------
run_gitleaks() {
  local tree="$1" out="$2"
  assert_real_git_dir "$tree"
  docker run --rm --read-only --user "$(id -u):$(id -g)" \
    -v "$tree:/repo:ro" -v "$WORK/config:/config:ro" \
    "$GITLEAKS_IMAGE" detect --source=/repo --no-banner --redact --verbose --exit-code 1 \
    --config=/config/.gitleaks.toml > "$out" 2>&1
  return $?
}

run_trufflehog() {
  local tree="$1" out="$2"
  assert_real_git_dir "$tree"
  docker run --rm -v "$tree:/repo:ro" \
    "$TRUFFLEHOG_IMAGE" git file:///repo --no-verification --fail --no-update > "$out" 2>&1
  return $?
}

strip_ansi() { sed $'s/\033\\[[0-9;]*[a-zA-Z]//g' "$1"; }

# (rule, file) pairs. gitleaks prints RuleID before File inside one record.
gl_pairs() { strip_ansi "$1" | awk '/^RuleID:/ {r=$2} /^File:/ {print r "\t" $2}'; }
# (detector, file) pairs. trufflehog prints Detector Type before File.
th_pairs() { strip_ansi "$1" | awk '/^Detector Type: / {d=$3} /^File: / {print d "\t" $2}'; }

fail=0
note() { echo "$1"; }

# ---------------------------------------------------------------------------
# Preflight: every payload must fire, under BOTH scanners, before it is planted.
# ---------------------------------------------------------------------------
PRE="$WORK/preflight"
attempt=0
while :; do
  attempt=$((attempt + 1))
  rm -rf "$PRE"; mkdir -p "$PRE"
  draw_payloads "$PRE"
  git -C "$PRE" init -q .
  commit_tree "$PRE" payloads

  run_gitleaks "$PRE" "$WORK/preflight.gl.out"; gl_rc=$?
  run_trufflehog "$PRE" "$WORK/preflight.th.out"; th_rc=$?

  # 0 = nothing found, 1/183 = findings. Anything else means the scanner did
  # not run, which must never be re-drawn as though it were an unlucky payload.
  if [ "$gl_rc" -ne 0 ] && [ "$gl_rc" -ne 1 ]; then
    echo "FAIL preflight: gitleaks exited $gl_rc, so it did not scan."
    strip_ansi "$WORK/preflight.gl.out" | sed -n '1,15p'
    exit 1
  fi
  if [ "$th_rc" -ne 0 ] && [ "$th_rc" -ne 183 ]; then
    echo "FAIL preflight: trufflehog exited $th_rc, so it did not scan."
    grep -E '^(Detector Type|File):|finished scanning|error' "$WORK/preflight.th.out" | sed -n '1,15p'
    exit 1
  fi

  gl_pairs "$WORK/preflight.gl.out" > "$WORK/pre.gl.pairs"
  th_pairs "$WORK/preflight.th.out" > "$WORK/pre.th.pairs"

  missing=""
  for p in $PLANTED; do
    grep -q "	$p\$" "$WORK/pre.gl.pairs" || missing="$missing gitleaks:$p"
    grep -q "	$p\$" "$WORK/pre.th.pairs" || missing="$missing trufflehog:$p"
  done
  [ -z "$missing" ] && break
  if [ "$attempt" -ge 5 ]; then
    echo "FAIL preflight: after $attempt draws these scanner/class pairs are still undetected:$missing"
    echo "     At five draws this is no longer an entropy miss: the rule is absent for that"
    echo "     scanner, or the class is allowlisted. That is a finding about the gate."
    exit 1
  fi
done
[ "$attempt" -gt 1 ] && note "note preflight: re-drew payloads $((attempt - 1)) time(s) before every class fired under both scanners"
note "ok   preflight: all 4 payload classes fire in isolation under BOTH scanners"

# Pin the message, not a count: the class each payload is expected to be
# reported AS. A self-test that only counts violations passes a violation
# raised for the wrong reason.
#   The two AWS payloads accept an alternation because which gitleaks rule
#   claims them depends on the drawn entropy; both are AWS-credential rules and
#   an empty match still fails the check.
expect_gl_aws='^(aws-access-token|generic-api-key)$'
expect_gl_pat='^github-pat$'
expect_gl_key='^private-key$'
expect_th_aws='^AWS$'
expect_th_pat='^Github$'
expect_th_key='^PrivateKey$'

# ---------------------------------------------------------------------------
# Plant, and build the allowlist control tree.
# ---------------------------------------------------------------------------
mkdir -p "$WORK/dirty/docs"
cp "$PRE/$P_AWS" "$WORK/dirty/$P_AWS"
cp "$PRE/$P_PAT" "$WORK/dirty/$P_PAT"
cp "$PRE/$P_KEY" "$WORK/dirty/$P_KEY"
cp "$PRE/$P_DOC" "$WORK/dirty/$P_DOC"
commit_tree "$WORK/dirty" "tree at $REF plus planted credentials"

write_allowlist_control "$WORK/allow"
commit_tree "$WORK/allow" "tree at $REF plus the documented AWS example value"

# ---------------------------------------------------------------------------
# Runs.
# ---------------------------------------------------------------------------
note "running: clean leg (gitleaks + trufflehog over $(git -C "$WORK/clean" rev-list --count HEAD) commits)"
run_gitleaks   "$WORK/clean" "$WORK/clean.gl.out";  clean_gl_rc=$?
run_trufflehog "$WORK/clean" "$WORK/clean.th.out";  clean_th_rc=$?
note "running: dirty leg"
run_gitleaks   "$WORK/dirty" "$WORK/dirty.gl.out";  dirty_gl_rc=$?
run_trufflehog "$WORK/dirty" "$WORK/dirty.th.out";  dirty_th_rc=$?
# The allowlist is a gitleaks config, so gitleaks is the leg that matters here;
# trufflehog is run on the same tree to show the documented value is not merely
# suppressed by our config but is inert for the other required context too.
note "running: allowlist control leg"
run_gitleaks   "$WORK/allow" "$WORK/allow.gl.out";  allow_gl_rc=$?
run_trufflehog "$WORK/allow" "$WORK/allow.th.out";  allow_th_rc=$?

gl_pairs "$WORK/dirty.gl.out" > "$WORK/dirty.gl.pairs"
th_pairs "$WORK/dirty.th.out" > "$WORK/dirty.th.pairs"
gl_pairs "$WORK/allow.gl.out" > "$WORK/allow.gl.pairs"
th_pairs "$WORK/allow.th.out" > "$WORK/allow.th.pairs"

commits_of()   { strip_ansi "$1" | sed -n 's/.*[^0-9]\([0-9]*\) commits scanned.*/\1/p' | head -1; }
gl_leaks_of()  { strip_ansi "$1" | sed -n 's/.*leaks found: \([0-9]*\).*/\1/p' | head -1; }
th_unver_of()  { sed -n 's/.*"unverified_secrets": \([0-9]*\).*/\1/p' "$1" | head -1; }
th_bytes_of()  { sed -n 's/.*"bytes": \([0-9]*\).*/\1/p' "$1" | head -1; }

# --- scope, against an independent source -----------------------------------
# gitleaks walks the history as a patch log, and a patch log carries no diff for
# a merge commit, so its "commits scanned" counter is the NON-MERGE count. The
# expectation is built from git rev-list -- a different source than the
# scanner's own counter, which is the whole point: comparing a run to a previous
# run of the same tool catches drift but not systematic error, and the defects
# this construction exists to catch (a replayed one-commit history, a clone
# carrying every branch) are systematic. The merge/non-merge split is asserted
# to sum back to the total so the expectation cannot be quietly narrowed until
# it happens to match.
total_commits="$(git -C "$WORK/clean" rev-list --count HEAD)"
merge_commits="$(git -C "$WORK/clean" rev-list --count --merges HEAD)"
expected_commits="$(git -C "$WORK/clean" rev-list --count --no-merges HEAD)"
scanned_commits="$(commits_of "$WORK/clean.gl.out")"
if [ "$((expected_commits + merge_commits))" -ne "$total_commits" ]; then
  note "FAIL scope: git rev-list does not add up ($expected_commits non-merge + $merge_commits merge != $total_commits total)"
  fail=1
elif [ -z "$scanned_commits" ]; then
  note "FAIL scope: gitleaks reported no commit count; it did not walk a history"
  fail=1
elif [ "$scanned_commits" != "$expected_commits" ]; then
  note "FAIL scope: gitleaks walked $scanned_commits commits, git rev-list says $REF reaches $expected_commits non-merge commits (of $total_commits total)."
  note "     The scan surface is not the ref under test, so no leg answers for $REF."
  fail=1
else
  note "ok   scope: gitleaks walked $scanned_commits commits = git rev-list --no-merges for $REF ($total_commits total - $merge_commits merges)"
fi
clean_th_bytes="$(th_bytes_of "$WORK/clean.th.out")"
if [ -z "$clean_th_bytes" ] || [ "$clean_th_bytes" -eq 0 ] 2>/dev/null; then
  note "FAIL scope: trufflehog reported no scanned bytes on the clean leg; it scanned nothing"
  fail=1
elif ! grep -q '^Commit: ' "$WORK/dirty.th.out"; then
  note "FAIL scope: trufflehog findings carry no Commit: field; it did not run in git-history mode"
  fail=1
else
  note "ok   scope: trufflehog scanned $clean_th_bytes bytes in git-history mode (findings carry Commit:)"
fi

# --- delivery ---------------------------------------------------------------
undelivered=""
for p in $PLANTED; do
  git -C "$WORK/dirty" cat-file -e "HEAD:$p" 2>/dev/null || undelivered="$undelivered $p"
done
git -C "$WORK/allow" cat-file -e "HEAD:$P_CTL" 2>/dev/null || undelivered="$undelivered $P_CTL"
if [ -n "$undelivered" ]; then
  note "FAIL delivery: not present in the committed history of their leg:$undelivered"
  note "     Both scanners read commits, so an unstaged payload is invisible and the leg's"
  note "     result -- green or red -- is about the harness, not the gate."
  fail=1
else
  note "ok   delivery: all 4 payloads in dirty HEAD, control in allow HEAD (git cat-file)"
fi

# --- clean leg --------------------------------------------------------------
if [ "$clean_gl_rc" -ne 0 ]; then
  note "FAIL clean/gitleaks: the committed tree at $REF reports a leak (exit $clean_gl_rc)."
  note "     Either a real secret is committed, or the config is broken. Findings:"
  gl_pairs "$WORK/clean.gl.out" | sed 's/^/       /'
  fail=1
else
  note "ok   clean/gitleaks: committed tree at $REF is clean (exit 0)"
fi
if [ "$clean_th_rc" -ne 0 ]; then
  note "FAIL clean/trufflehog: the committed tree at $REF reports a secret (exit $clean_th_rc). Findings:"
  th_pairs "$WORK/clean.th.out" | sed 's/^/       /'
  fail=1
else
  note "ok   clean/trufflehog: committed tree at $REF is clean (exit 0)"
fi

# --- dirty leg --------------------------------------------------------------
check_attribution() {
  # $1 pairs file, $2 label, $3..: file:regex expectations
  local pairs="$1" label="$2"; shift 2
  local bad="" spec p rx got
  for spec in "$@"; do
    p="${spec%%=*}"; rx="${spec#*=}"
    got="$(awk -F'\t' -v f="$p" '$2==f {print $1}' "$pairs" | head -1)"
    if [ -z "$got" ]; then
      bad="$bad
       $p: NOT NAMED by $label"
    elif ! printf '%s' "$got" | grep -Eq "$rx"; then
      bad="$bad
       $p: $label reported rule '$got', expected /$rx/"
    fi
  done
  printf '%s' "$bad"
}

if [ "$dirty_gl_rc" -ne 1 ]; then
  note "FAIL dirty/gitleaks: four planted credential classes did NOT redden the gate (exit $dirty_gl_rc)."
  note "     This is the fake-green case: the gate runs, reports success, and would pass a real leak."
  fail=1
else
  found="$(gl_leaks_of "$WORK/dirty.gl.out")"
  if [ -z "$found" ]; then
    note "FAIL dirty/gitleaks: exit 1 but no 'leaks found:' line -- the scanner failed rather than detected."
    fail=1
  else
    bad="$(check_attribution "$WORK/dirty.gl.pairs" gitleaks \
      "$P_AWS=$expect_gl_aws" "$P_PAT=$expect_gl_pat" "$P_KEY=$expect_gl_key" "$P_DOC=$expect_gl_aws")"
    if [ -n "$bad" ]; then
      note "FAIL dirty/gitleaks: reddened, but not correctly attributed:$bad"
      note "     A finding total proves the gate reddened; only the filename plus the expected"
      note "     rule proves it reddened ON the planted payload, for the expected reason."
      fail=1
    else
      note "ok   dirty/gitleaks: exit 1, leaks found: $found, all 4 planted files named with the expected rule"
      gl_pairs "$WORK/dirty.gl.out" | grep -E "	($P_AWS|$P_PAT|$P_KEY|$P_DOC)\$" | sed 's/^/       /'
    fi
  fi
fi

if [ "$dirty_th_rc" -ne 183 ]; then
  note "FAIL dirty/trufflehog: four planted credential classes did NOT redden the gate (exit $dirty_th_rc; --fail exits 183 on findings)."
  note "     Proving gitleaks reddens says nothing about this context: it is a separate"
  note "     required check with a separate detector set."
  fail=1
else
  unver="$(th_unver_of "$WORK/dirty.th.out")"
  if [ -z "$unver" ] || [ "$unver" -eq 0 ] 2>/dev/null; then
    note "FAIL dirty/trufflehog: exit 183 but the summary reports no unverified secrets -- it failed rather than detected."
    fail=1
  else
    bad="$(check_attribution "$WORK/dirty.th.pairs" trufflehog \
      "$P_AWS=$expect_th_aws" "$P_PAT=$expect_th_pat" "$P_KEY=$expect_th_key" "$P_DOC=$expect_th_aws")"
    if [ -n "$bad" ]; then
      note "FAIL dirty/trufflehog: reddened, but not correctly attributed:$bad"
      fail=1
    else
      note "ok   dirty/trufflehog: exit 183, unverified_secrets: $unver, all 4 planted files named with the expected detector"
      th_pairs "$WORK/dirty.th.out" | grep -E "	($P_AWS|$P_PAT|$P_KEY|$P_DOC)\$" | sed 's/^/       /'
    fi
  fi
fi

# --- allowlist control ------------------------------------------------------
# Direction 1: the allowlisted value, at a path under docs/, must NOT redden.
if [ "$allow_gl_rc" -ne 0 ]; then
  note "FAIL allowlist/gitleaks: the documented AWS example value reddens the gate (exit $allow_gl_rc)."
  note "     Findings:"
  gl_pairs "$WORK/allow.gl.out" | sed 's/^/       /'
  fail=1
elif grep -q "	$P_CTL\$" "$WORK/allow.gl.pairs"; then
  note "FAIL allowlist/gitleaks: exit 0 yet $P_CTL is named in the report -- inconsistent report state."
  fail=1
else
  note "ok   allowlist/gitleaks: the documented AWS example value at $P_CTL does not redden (exit 0)"
fi
if [ "$allow_th_rc" -ne 0 ]; then
  note "FAIL allowlist/trufflehog: the documented AWS example value reddens trufflehog (exit $allow_th_rc)."
  note "     trufflehog does not read .gitleaks.toml, so nothing in this repo can suppress it;"
  note "     the value would have to leave the docs."
  th_pairs "$WORK/allow.th.out" | sed 's/^/       /'
  fail=1
else
  note "ok   allowlist/trufflehog: the documented AWS example value does not redden trufflehog either (exit 0)"
fi
# Direction 2: a RANDOM AWS key at a sibling path in the SAME directory must
# redden. Without this arm a green control leg is equally consistent with an
# allowlist that blankets docs/.
if grep -q "	$P_DOC\$" "$WORK/dirty.gl.pairs"; then
  note "ok   allowlist scope: a random AWS key at $P_DOC (same directory as the control) DOES redden"
  note "     -> the allowlist is scoped to the one documented value, not a docs/ blanket"
else
  note "FAIL allowlist scope: the random AWS key at $P_DOC was not reported."
  note "     The allowlist may have become a path blanket over docs/, which would pass a real"
  note "     credential committed to any doc."
  fail=1
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "SECRETS GATE RED-PROBE FAILED"
  [ "$KEEP" -eq 1 ] || echo "(re-run with --keep to retain raw scanner logs; they are not printed because trufflehog emits raw secret material)"
  exit 1
fi
echo "secrets gate proven two-sided against $REF:"
echo "  secrets-gitleaks   green on the committed tree, red on 4 planted classes, each attributed"
echo "  secrets-trufflehog green on the committed tree, red on 4 planted classes, each attributed"
echo "  allowlist          value-scoped: documented example green, random key in the same directory red"
