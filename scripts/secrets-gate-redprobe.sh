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
#   secrets-gitleaks    -- a `docker run` of the gitleaks image, written out in
#                          the job's own run block
#   secrets-trufflehog  -- the trufflehog ACTION over the fetch-depth:0 checkout
#
# THE PROBE RUNS WHAT THE GATE RUNS, DERIVED FROM THE GATE
# Every image, tag and flag below is read out of security.yml at the ref under
# test. None of it is typed into this file as a constant. That rule is the whole
# reason this script was rebuilt: the previous version hard-coded its own idea of
# each scanner invocation, and both halves of that idea were wrong.
#
#  * It ran `trufflesecurity/trufflehog:v3.95.7`. No such image exists in any
#    registry: `v3.95.7` is the git tag of the ACTION, and the action is not
#    distributed as that image. On a runner with no local images the probe
#    reported NOT RUN and exited 2; on a developer machine that happened to have
#    some trufflehog image cached it silently substituted it and reported a PASS.
#    A gate probe that is unrunnable in CI and fake-green on a laptop measures
#    nothing in either place.
#  * It ran `git file:///repo --no-verification --fail --no-update`. The action
#    runs something else entirely, and the difference is not cosmetic: the
#    action's `--github-actions` flag replaces the whole result format, so the
#    probe's per-finding attribution parser matched ZERO findings against real
#    gate output while matching four against the format only the probe produced.
#    Every "all 4 planted files named with the expected detector" line it printed
#    was about a command the gate never issues.
#
# WHAT THE TRUFFLEHOG ACTION ACTUALLY DOES
# The action is a COMPOSITE action, not a container action. Its final step is a
# `docker run`, and that is the mechanism this probe mirrors:
#
#   docker run --rm -v .:/tmp -w /tmp \
#     ghcr.io/trufflesecurity/trufflehog:${VERSION} \
#     git file:///tmp/ --since-commit ${BASE:-''} --branch ${HEAD:-''} \
#     --fail --no-update --github-actions ${ARGS:-''}
#
# Three consequences, each of which the probe now honours:
#
#   REGISTRY AND TAG. The image is ghcr.io/trufflesecurity/trufflehog, tagged
#   with the action's `version` input, which DEFAULTS TO `latest`. security.yml
#   does not set `version`, so the 40-hex action pin fixes the wrapper and
#   leaves the scanner build floating on a moving tag. That is reported on every
#   run, not asserted against: pinning it is a change to the gate, and this
#   script measures the gate rather than editing it.
#
#   MOUNT. The checkout is mounted READ-WRITE at /tmp, because trufflehog's git
#   source clones the repository into a temp directory INSIDE that mount. The
#   old probe's read-only mount is not a hardened version of the same run; under
#   the action's paths it fails outright with "failed to create temporary clone
#   path: read-only file system", which is a scanner that never ran.
#
#   RANGE. BASE and HEAD come from the event. On a pull_request they are the
#   base and head SHAs, so the required PR context scans the PULL REQUEST'S
#   COMMITS, not the whole history; on a schedule they are empty strings and the
#   scan covers everything. Both shapes are exercised below, because proving the
#   gate reddens on a full-history scan says nothing about the range scan that
#   actually runs on a pull request.
#
# The action's own command shape is a contract this file mirrors by hand, so it
# is pinned to the action revision it was read from (MIRRORED_ACTION_SHA). When
# security.yml moves to a different revision the probe REFUSES TO RUN rather than
# keep asserting against a stale mirror.
#
# A gate that has never been shown to fail is indistinguishable from a gate that
# cannot fail, and proving ONE scanner reddens says nothing about the other: they
# share no ruleset, no config file and no detector. So every leg here runs BOTH
# scanners and attributes findings PER SCANNER.
#
# Legs:
#   clean      the committed tree at REF, untouched      -> both scanners green
#   dirty      that tree plus planted credentials        -> both scanners red,
#                                                           each naming every
#                                                           planted file
#   pr-range   the dirty tree scanned the way the action -> trufflehog red over
#              scans a pull request (base..head)            the planted commit
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
#  * Never hand-copy the gate's command into the probe. Derive image, tag and
#    flags from the workflow at REF, and prove the derivation actually reads the
#    workflow by mutating a COPY of it and requiring the derived values to move
#    (the extractor self-test below). A constant that agrees with the gate today
#    is indistinguishable from one that has silently drifted, and the drift is
#    invisible precisely because the probe stays green.
#  * Parse the output format the mirrored command actually EMITS. An attribution
#    parser that matches nothing reports "not named" for every payload -- or, if
#    the leg only counts, passes while reading a format that was never produced.
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
#  * A scanner exit code is classified, never merely compared against zero.
#    gitleaks answers 0/1 and trufflehog answers 0/183; anything else is a
#    scanner that did not run, and reporting that as "the tree contains a
#    secret" sends the reader to look for a leak that is not there.
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
# Exit 2 is NOT RUN: docker, a scanner image, or a gate definition this probe
# can still mirror was unavailable. The probe never simulates a scanner run.

set -uo pipefail

REF="HEAD"
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:-}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    # Printed from the comment block above rather than from a hand-maintained
    # line range: a range drifts the moment the header is edited, and then the
    # help output describes a probe nobody is running.
    -h|--help) awk 'NR>3 && /^#/ {sub(/^# ?/, ""); print; next} NR>3 {exit}' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# The gate definition is the subject; everything the probe runs is read from it.
WORKFLOW_REL='.github/workflows/security.yml'

# The revision of the trufflehog action whose entrypoint the trufflehog
# invocation below mirrors. This is not a preference and not a pin of the
# scanner: it records WHICH action source was read to learn the command shape.
# security.yml pointing anywhere else means the mirror is unverified, and an
# unverified mirror asserting "the gate reddens" is a guess.
MIRRORED_ACTION_SHA='f446421baf832d6356c42c1743d99abff52ff334'

# The registry the action hard-codes. It is NOT configurable through the
# action's inputs, so it is the one part of the command that cannot be derived
# from security.yml.
TRUFFLEHOG_REGISTRY='ghcr.io/trufflesecurity/trufflehog'
# The action's default when its `version` input is unset.
TRUFFLEHOG_DEFAULT_VERSION='latest'

command -v docker >/dev/null 2>&1 || { echo "NOT RUN: docker is required; the probe cannot run the real scanners" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "NOT RUN: the docker daemon is not reachable; the probe cannot run the real scanners" >&2; exit 2; }
git rev-parse --verify "$REF" >/dev/null 2>&1 || { echo "NOT RUN: no such ref: $REF" >&2; exit 2; }

WORK="$(mktemp -d)"
cleanup() { if [ "$KEEP" -eq 1 ]; then echo "kept: $WORK"; else rm -rf "$WORK"; fi; }
trap cleanup EXIT

mkdir -p "$WORK/config"

fail=0
note() { echo "$1"; }

# ---------------------------------------------------------------------------
# GATE DEFINITION EXTRACTOR
#
# Reads the two secrets jobs out of security.yml. Deliberately narrow: it
# understands the shape this repository's workflow is written in and refuses to
# guess at any other. Refusing is the correct failure -- a probe that fell back
# to a built-in default would go on measuring a command the gate stopped
# issuing, which is the exact defect this file exists to have removed.
# ---------------------------------------------------------------------------

# Everything under the top-level `jobs:` key. Scoped this way because `on:` also
# carries bare two-space keys (push, pull_request, schedule) that are
# indistinguishable from job ids by indentation alone.
jobs_section() {
  awk '/^jobs:[[:space:]]*$/ {inj = 1; next} inj && /^[A-Za-z]/ {inj = 0} inj {print}' "$1"
}

# One job's body, read from stdin.
job_block() {
  awk -v j="$1" '
    $0 ~ "^  " j ":[[:space:]]*$" {b = 1; next}
    b && /^  [^[:space:]]/ {b = 0}
    b {print}'
}

# A single-line scalar from the trufflehog step's `with:` mapping. Trailing
# comments and surrounding quotes are stripped; a block scalar (| or >) is
# returned as the indicator itself so the caller can refuse it rather than
# silently scan with half a value.
th_with_value() {
  jobs_section "$1" | job_block secrets-trufflehog \
    | sed -n "s/^[[:space:]]*$2:[[:space:]]*//p" | head -1 \
    | sed -e 's/[[:space:]]\{1,\}#.*$//' -e 's/[[:space:]]*$//' \
          -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

gitleaks_image_of() {
  jobs_section "$1" | job_block secrets-gitleaks \
    | grep -oE 'zricethezav/gitleaks:[A-Za-z0-9._-]+' | head -1
}

th_action_sha_of() {
  jobs_section "$1" | job_block secrets-trufflehog \
    | sed -n 's|^[[:space:]]*uses:[[:space:]]*trufflesecurity/trufflehog@\([0-9a-f]\{40\}\).*|\1|p' | head -1
}

# The whole-file counts are the vacuity guard on the extractor: a second
# gitleaks run or a second trufflehog step means the probe would mirror one of
# several gate invocations while claiming to answer for the context.
count_gitleaks_refs() { grep -c 'zricethezav/gitleaks:' "$1"; }
count_th_steps()      { grep -c 'uses:[[:space:]]*trufflesecurity/trufflehog@' "$1"; }

# ---------------------------------------------------------------------------
# Extract the gate definition at REF.
# ---------------------------------------------------------------------------
if ! git cat-file -e "$REF:$WORKFLOW_REL" 2>/dev/null; then
  echo "NOT RUN: $REF has no $WORKFLOW_REL. The subject under test is absent; there is" >&2
  echo "         no gate definition to derive a scanner invocation from." >&2
  exit 2
fi
git show "$REF:$WORKFLOW_REL" > "$WORK/security.yml"

GITLEAKS_IMAGE="$(gitleaks_image_of "$WORK/security.yml")"
TH_ACTION_SHA="$(th_action_sha_of "$WORK/security.yml")"
TH_VERSION="$(th_with_value "$WORK/security.yml" version)"
TH_EXTRA_ARGS="$(th_with_value "$WORK/security.yml" extra_args)"
GL_REFS="$(count_gitleaks_refs "$WORK/security.yml")"
TH_STEPS="$(count_th_steps "$WORK/security.yml")"

extractor_refusal=""
[ "$GL_REFS" = "1" ] || extractor_refusal="$extractor_refusal
       $GL_REFS gitleaks image reference(s) in the workflow, expected exactly 1"
[ "$TH_STEPS" = "1" ] || extractor_refusal="$extractor_refusal
       $TH_STEPS trufflehog action step(s) in the workflow, expected exactly 1"
[ -n "$GITLEAKS_IMAGE" ] || extractor_refusal="$extractor_refusal
       no zricethezav/gitleaks:<tag> found in job secrets-gitleaks"
[ -n "$TH_ACTION_SHA" ] || extractor_refusal="$extractor_refusal
       no 40-hex-pinned trufflesecurity/trufflehog step found in job secrets-trufflehog"
case "$TH_EXTRA_ARGS" in
  '|'*|'>'*) extractor_refusal="$extractor_refusal
       extra_args is a block scalar; this extractor reads single-line scalars only" ;;
esac
if [ -n "$extractor_refusal" ]; then
  echo "NOT RUN: $REF:$WORKFLOW_REL is not a gate definition this probe can mirror:$extractor_refusal" >&2
  echo "         Refusing to fall back to a built-in command. A probe that scans with its" >&2
  echo "         own idea of the gate reports on a run that never happens -- which is the" >&2
  echo "         defect this extractor replaced." >&2
  exit 2
fi

if [ "$TH_ACTION_SHA" != "$MIRRORED_ACTION_SHA" ]; then
  echo "NOT RUN: security.yml pins the trufflehog action at $TH_ACTION_SHA," >&2
  echo "         but the invocation in this probe mirrors ${MIRRORED_ACTION_SHA}." >&2
  echo "         The action is composite: its entrypoint composes the docker run, the" >&2
  echo "         image registry, and the flags this probe reproduces by hand. A different" >&2
  echo "         revision may compose a different command, and asserting 'the gate reddens'" >&2
  echo "         against a stale mirror is a guess wearing a measurement's label." >&2
  echo "         Read action.yml at the new revision, update the invocation and" >&2
  echo "         MIRRORED_ACTION_SHA together." >&2
  exit 2
fi

[ -n "$TH_VERSION" ] || TH_VERSION="$TRUFFLEHOG_DEFAULT_VERSION"
TRUFFLEHOG_IMAGE="${TRUFFLEHOG_REGISTRY}:${TH_VERSION}"

# The action word-splits ${ARGS:-''} unquoted, so the probe does too. When
# extra_args is unset the action still passes one empty word; reproducing that
# keeps the argv identical rather than merely equivalent.
TH_EXTRA_WORDS=()
if [ -n "$TH_EXTRA_ARGS" ]; then
  read -r -a TH_EXTRA_WORDS <<< "$TH_EXTRA_ARGS"
else
  TH_EXTRA_WORDS=("")
fi

# ---------------------------------------------------------------------------
# EXTRACTOR SELF-TEST
#
# Deriving the command from the workflow only removes the drift class if the
# derivation actually reads the workflow. A function that returned a constant
# would satisfy every assertion above on today's file. So each derived value is
# probed the way the release-signing analyzer is probed: mutate a COPY of
# security.yml and require the reported value to MOVE with the mutation, and
# require the extractor to REFUSE when the step it mirrors is gone.
# ---------------------------------------------------------------------------
selftest_fail=""
st_expect() { # $1 label, $2 expected, $3 got
  [ "$2" = "$3" ] || selftest_fail="$selftest_fail
       $1: expected '$2', extractor said '$3'"
}

ST="$WORK/selftest.yml"

sed 's|zricethezav/gitleaks:v8.30.1|zricethezav/gitleaks:v9.99.9-probe|' "$WORK/security.yml" > "$ST"
st_expect "gitleaks image follows the workflow" \
  "zricethezav/gitleaks:v9.99.9-probe" "$(gitleaks_image_of "$ST")"

sed 's|^\([[:space:]]*\)path: \./|\1version: 3.95.7-probe|' "$WORK/security.yml" > "$ST"
st_expect "trufflehog version follows the workflow" \
  "3.95.7-probe" "$(th_with_value "$ST" version)"

sed 's|^\([[:space:]]*\)extra_args: .*|\1extra_args: --no-verification --exclude-detectors=AWS|' \
  "$WORK/security.yml" > "$ST"
st_expect "trufflehog extra_args follow the workflow" \
  "--no-verification --exclude-detectors=AWS" "$(th_with_value "$ST" extra_args)"

# The extractor must not read the trufflehog step out of some other job, so the
# job body itself is what carries the answer.
sed 's|^  secrets-trufflehog:|  secrets-trufflehog-renamed:|' "$WORK/security.yml" > "$ST"
st_expect "no trufflehog action sha once the job id moves" "" "$(th_action_sha_of "$ST")"
st_expect "no extra_args once the job id moves" "" "$(th_with_value "$ST" extra_args)"

# A commented-out invocation is not an invocation.
sed 's|^\([[:space:]]*\)uses: trufflesecurity/trufflehog@|\1# uses: trufflesecurity/trufflehog@|' \
  "$WORK/security.yml" > "$ST"
st_expect "a commented-out action step is not read as pinned" "" "$(th_action_sha_of "$ST")"

if [ -n "$selftest_fail" ]; then
  echo "NOT RUN: the gate-definition extractor does not track the workflow:$selftest_fail" >&2
  echo "         Every scanner invocation below is derived by these functions. If they do" >&2
  echo "         not move when the workflow moves, the probe measures a command of its own" >&2
  echo "         invention and its verdict says nothing about the gate." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Image availability. NOT RUN, never a simulated scan.
# ---------------------------------------------------------------------------
have_image() { docker image inspect "$1" >/dev/null 2>&1; }
image_version_label() {
  docker image inspect "$1" --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null
}

# A moving tag is re-pulled when the registry is reachable: on a fresh runner
# the gate always gets the newest build under that tag, and a probe answering
# from a months-old local copy would be measuring a scanner the gate retired.
# A failed pull is not fatal while a local copy exists -- it is reported, and
# the build that produced the evidence is printed either way.
resolve_image() { # $1 image, $2 label for messages
  local img="$1" moving=0 pulled=0
  case "$img" in *:latest|*:main|*:master|*:edge) moving=1 ;; esac
  if [ "$moving" -eq 1 ] || ! have_image "$img"; then
    docker pull --quiet "$img" >/dev/null 2>&1 && pulled=1
  fi
  if ! have_image "$img"; then
    echo "NOT RUN: $img is not available locally and cannot be pulled." >&2
    echo "         This is the image the $2 context itself runs; the probe does not" >&2
    echo "         substitute another build and does not simulate a scanner run." >&2
    return 1
  fi
  if [ "$moving" -eq 1 ] && [ "$pulled" -eq 0 ]; then
    note "NOTE $2: '$img' is a moving tag and could not be refreshed from the registry;"
    note "     this run used the local copy, so it may be behind the build the gate pulls."
  fi
  return 0
}

resolve_image "$GITLEAKS_IMAGE" secrets-gitleaks || exit 2
resolve_image "$TRUFFLEHOG_IMAGE" secrets-trufflehog || exit 2

echo "secrets-gate-redprobe: ref=$REF"
echo "  gate definition  : $REF:$WORKFLOW_REL"
echo "  gitleaks image   : $GITLEAKS_IMAGE (from job secrets-gitleaks)"
echo "  trufflehog action: trufflesecurity/trufflehog@$TH_ACTION_SHA (mirror verified against this revision)"
echo "  trufflehog image : $TRUFFLEHOG_IMAGE (build $(image_version_label "$TRUFFLEHOG_IMAGE"))"
echo "  trufflehog args  : --fail --no-update --github-actions $TH_EXTRA_ARGS"
if [ "$TH_VERSION" = "$TRUFFLEHOG_DEFAULT_VERSION" ]; then
  echo "  NOTE  the action's 'version' input is unset in security.yml, so the gate runs the"
  echo "        moving tag '$TRUFFLEHOG_DEFAULT_VERSION'. The 40-hex action pin fixes the wrapper, not the"
  echo "        scanner build: two runs of the same commit can scan with different detectors."
  echo "        Reported, not asserted -- pinning it changes the gate, which this probe measures."
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
# Scanner invocations.
#
# gitleaks   mirrors the job's run block. The added flags change reporting,
#            never detection: --verbose is what prints the per-finding File:
#            lines, without which every per-file attribution check silently
#            matches nothing; --exit-code 1 makes the outcome usable; --config
#            points at the file extracted from REF, which is the same file the
#            gate auto-loads from the repository root of the tree it mounts.
# trufflehog mirrors the composite action's entrypoint argv exactly: the ghcr
#            image at the action's `version` input, a READ-WRITE mount at /tmp
#            (the git source clones into a temp dir inside the mount), the
#            file:///tmp/ source, the event's since-commit/branch range, and
#            --fail --no-update --github-actions followed by the workflow's
#            extra_args, word-split the way the action word-splits them.
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

# $3/$4 are the action's BASE/HEAD. Empty strings are the schedule shape (whole
# history); two SHAs are the pull_request shape (that range only).
run_trufflehog() {
  local tree="$1" out="$2" base="$3" head="$4"
  assert_real_git_dir "$tree"
  docker run --rm -v "$tree:/tmp" -w /tmp "$TRUFFLEHOG_IMAGE" \
    git file:///tmp/ --since-commit "$base" --branch "$head" \
    --fail --no-update --github-actions "${TH_EXTRA_WORDS[@]}" > "$out" 2>&1
  return $?
}

strip_ansi() { sed $'s/\033\\[[0-9;]*[a-zA-Z]//g' "$1"; }

# (rule, file) pairs. gitleaks prints RuleID before File inside one record.
gl_pairs() { strip_ansi "$1" | awk '/^RuleID:/ {r=$2} /^File:/ {print r "\t" $2}'; }
# (detector, file) pairs from the action's --github-actions result format:
#   ::warning file=<path>,line=N,endLine=M::Found <un>verified <Detector> result
# This is NOT the human format: under --github-actions trufflehog emits no
# "Detector Type:" / "File:" records at all, so a parser written for those reads
# every gate run as zero findings.
th_pairs() {
  strip_ansi "$1" | awk '
    /^::[a-z]+ file=.*::Found / {
      f = $0; sub(/^::[a-z]+ file=/, "", f); sub(/,line=[0-9]+,endLine=[0-9]+::Found .*$/, "", f)
      d = $0; sub(/^.*::Found [a-z]+ /, "", d); sub(/ result.*$/, "", d)
      if (f != "" && d != "") print d "\t" f
    }'
}

# gitleaks: 0 = clean, 1 = findings. trufflehog under --fail: 0 = clean,
# 183 = findings. Everything else is a scanner that did not run, and must never
# be reported as a verdict about the tree.
gl_ran()  { [ "$1" -eq 0 ] || [ "$1" -eq 1 ]; }
th_ran()  { [ "$1" -eq 0 ] || [ "$1" -eq 183 ]; }

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
  run_trufflehog "$PRE" "$WORK/preflight.th.out" "" ""; th_rc=$?

  # A scanner that did not run must never be re-drawn as though it were an
  # unlucky payload.
  if ! gl_ran "$gl_rc"; then
    echo "FAIL preflight: gitleaks exited $gl_rc, so it did not scan."
    strip_ansi "$WORK/preflight.gl.out" | sed -n '1,15p'
    exit 1
  fi
  if ! th_ran "$th_rc"; then
    echo "FAIL preflight: trufflehog exited $th_rc, so it did not scan."
    grep -E '^::|error|finished scanning' "$WORK/preflight.th.out" | sed -n '1,15p'
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
note "ok   preflight: all 4 payload classes fire in isolation under BOTH scanners, each run with the gate's own invocation"

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

# The pull_request range the action would scan for that plant: its parent is the
# tip of REF, exactly as a PR's base is.
PR_BASE="$(git -C "$WORK/dirty" rev-parse HEAD~1)"
PR_HEAD="$(git -C "$WORK/dirty" rev-parse HEAD)"

write_allowlist_control "$WORK/allow"
commit_tree "$WORK/allow" "tree at $REF plus the documented AWS example value"

# ---------------------------------------------------------------------------
# Runs.
# ---------------------------------------------------------------------------
note "running: clean leg (gitleaks + trufflehog over $(git -C "$WORK/clean" rev-list --count HEAD) commits)"
run_gitleaks   "$WORK/clean" "$WORK/clean.gl.out";      clean_gl_rc=$?
run_trufflehog "$WORK/clean" "$WORK/clean.th.out" "" ""; clean_th_rc=$?
# The action mounts read-write because trufflehog clones into the mount. That is
# a write the old read-only mount never permitted, so it is checked rather than
# assumed: a scanner that left the subject modified would silently change what
# every later leg is answering about.
clean_residue="$(git -C "$WORK/clean" status --porcelain)"
note "running: dirty leg"
run_gitleaks   "$WORK/dirty" "$WORK/dirty.gl.out";      dirty_gl_rc=$?
run_trufflehog "$WORK/dirty" "$WORK/dirty.th.out" "" ""; dirty_th_rc=$?
note "running: pull-request-range leg (the shape the required context runs on a PR)"
run_trufflehog "$WORK/dirty" "$WORK/range.th.out" "$PR_BASE" "$PR_HEAD"; range_th_rc=$?
# The allowlist is a gitleaks config, so gitleaks is the leg that matters here;
# trufflehog is run on the same tree to show the documented value is not merely
# suppressed by our config but is inert for the other required context too.
note "running: allowlist control leg"
run_gitleaks   "$WORK/allow" "$WORK/allow.gl.out";      allow_gl_rc=$?
run_trufflehog "$WORK/allow" "$WORK/allow.th.out" "" ""; allow_th_rc=$?

gl_pairs "$WORK/dirty.gl.out" > "$WORK/dirty.gl.pairs"
th_pairs "$WORK/dirty.th.out" > "$WORK/dirty.th.pairs"
th_pairs "$WORK/range.th.out" > "$WORK/range.th.pairs"
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
elif ! grep -q '"repo": "file:///tmp' "$WORK/clean.th.out"; then
  # Under --github-actions there are no per-finding Commit: fields to read, so
  # git-source mode is established from the scanner's own source log line
  # instead. Asserting a field the gate's output format never carries would fail
  # every run for a reason that has nothing to do with the gate.
  note "FAIL scope: trufflehog logged no git source over the mount; it did not run in git mode"
  fail=1
else
  note "ok   scope: trufflehog scanned $clean_th_bytes bytes as a git source over the mount (file:///tmp)"
fi
if [ -n "$clean_residue" ]; then
  note "FAIL scope: the read-write mount left the clean clone modified:"
  printf '%s\n' "$clean_residue" | sed 's/^/       /'
  note "     Later legs would then be answering about a tree the scanner edited."
  fail=1
else
  note "ok   scope: the read-write mount the action requires left the scanned clone unmodified"
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
if ! gl_ran "$clean_gl_rc"; then
  note "FAIL clean/gitleaks: the scanner exited $clean_gl_rc, so it did not scan at all."
  strip_ansi "$WORK/clean.gl.out" | sed -n '1,15p'
  fail=1
elif [ "$clean_gl_rc" -ne 0 ]; then
  note "FAIL clean/gitleaks: the committed tree at $REF reports a leak (exit $clean_gl_rc)."
  note "     Either a real secret is committed, or the config is broken. Findings:"
  gl_pairs "$WORK/clean.gl.out" | sed 's/^/       /'
  fail=1
else
  note "ok   clean/gitleaks: committed tree at $REF is clean (exit 0)"
fi
if ! th_ran "$clean_th_rc"; then
  note "FAIL clean/trufflehog: the scanner exited $clean_th_rc, so it did not scan at all."
  grep -E 'error|finished scanning' "$WORK/clean.th.out" | sed -n '1,10p'
  fail=1
elif [ "$clean_th_rc" -ne 0 ]; then
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

# --- pull-request-range leg -------------------------------------------------
# The full-history legs above are the SCHEDULED run's shape. On a pull request
# the action passes the base and head SHAs, and trufflehog then walks only that
# range -- so a gate proven to redden over the whole history is still unproven
# for the scan that actually decides a merge. The clean direction needs no
# separate run: the clean leg is green over the entire history, and a range is a
# subset of it.
if [ "$range_th_rc" -ne 183 ]; then
  note "FAIL pr-range/trufflehog: the planted commit did NOT redden the pull-request-shaped scan (exit $range_th_rc)."
  note "     Range: --since-commit $PR_BASE --branch $PR_HEAD."
  note "     The full-history legs can pass while this one fails; this is the invocation the"
  note "     required context runs on a pull request, so this is the one that gates a merge."
  fail=1
else
  bad="$(check_attribution "$WORK/range.th.pairs" trufflehog \
    "$P_AWS=$expect_th_aws" "$P_PAT=$expect_th_pat" "$P_KEY=$expect_th_key" "$P_DOC=$expect_th_aws")"
  if [ -n "$bad" ]; then
    note "FAIL pr-range/trufflehog: reddened, but not correctly attributed:$bad"
    fail=1
  else
    note "ok   pr-range/trufflehog: exit 183 scanning base..head only, all 4 planted files named"
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
echo "secrets gate proven two-sided against $REF, each context driven by its own definition:"
echo "  secrets-gitleaks   green on the committed tree, red on 4 planted classes, each attributed"
echo "  secrets-trufflehog green on the committed tree, red on 4 planted classes, each attributed,"
echo "                     over both the scheduled full-history scan and the pull-request range"
echo "  allowlist          value-scoped: documented example green, random key in the same directory red"
