#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Red-probe the two Layer-0 SAST/SCA gates: prove each one reddens on a
# planted defect that it names by file or by package.
#
# Required branch-protection contexts covered here (job ids in
# .github/workflows/security.yml; no job declares a `name:`, so each context
# string is byte-identical to its job id):
#
#   sast-semgrep   -- `semgrep ci` with SEMGREP_RULES = the five packs
#   sca-trivy-fs   -- `trivy fs` over the repo root, CRITICAL,HIGH, exit 1
#
# A gate that has never been shown to fail is indistinguishable from a gate
# that cannot fail. Each scanner is driven against two trees and asserted in
# opposite directions:
#
#   clean = the committed tree at REF, untouched     -> expect the gate to pass
#   dirty = that same tree plus one planted defect   -> expect the gate to fail
#           AND to name the planted artefact
#
# Construction rules this script obeys, each of which is a defect that has
# already cost a component a run:
#
#  1. Never mount a git worktree into a scanner container. In a worktree .git
#     is a FILE pointing at the parent repository, which does not resolve
#     inside the container; the scanner then walks zero tracked files and
#     reports "0 findings, exit 0", which reads as a pass on the clean leg and
#     as a false product finding on the dirty leg. Every tree here comes from
#     `git clone --no-local` (a clone's .git is a real directory) and the
#     directory-ness is asserted before any scan.
#  2. Configuration is read with `git show <ref>:<path>` on an explicitly
#     named ref, never from the working tree. Reading the working tree lets a
#     local edit decide whether the probe passes.
#  4. Every payload is preflighted: it must fire on its own, in an isolated
#     one-file repository, BEFORE it is planted. This separates "this class is
#     not covered by the configured rules", which is a finding, from "the
#     planted tree is odd", which is noise. It also catches ruleset drift --
#     both scanners here pull their rules from a moving upstream.
#  5. Delivery is checked with `git cat-file -e HEAD:<path>` in the dirty
#     clone, never with a scanned-byte or finding-count delta.
#  6. Scan scope is checked against an INDEPENDENT source (git's own file
#     count, the tree's own go.mod count), not against a previous run of the
#     same tool. Comparing tool to tool catches drift but not systematic error.
#  7. Findings are ATTRIBUTED by planted artefact -- file name for semgrep,
#     package plus CVE id for trivy. A finding total proves the gate reddened;
#     it does not prove it reddened on the planted payload, and this tree
#     already carries a pre-existing HIGH (see the clean-leg report) that
#     would satisfy any count check on its own.
#  8. The expected MESSAGE FRAGMENT is pinned, not just an exit code or a
#     count. A check that compares only the number of violations passes a
#     violation reported for the wrong reason.
#
# Payloads are static source patterns and known-vulnerable module versions,
# not credentials, so no entropy re-draw loop is needed here; the preflight
# still runs because ruleset drift can retire a rule at any time.
#
# Usage:
#   scripts/sast-sca-gate-redprobe.sh [--ref REF] [--keep] [--skip-image-gap]
#
# Exit 0 only when every leg behaved as asserted.

set -uo pipefail

REF="HEAD"
KEEP=0
SKIP_IMAGE_GAP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --skip-image-gap) SKIP_IMAGE_GAP=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# security.yml pins neither scanner by digest: the semgrep job runs in the
# bare `semgrep/semgrep` container image, and the trivy job runs
# aquasecurity/trivy-action, which carries its own trivy build. Both are
# moving targets, so this probe follows the same moving targets rather than
# pinning and drifting away from the gate it claims to measure. The resolved
# versions are printed so a run is reproducible after the fact.
SEMGREP_IMAGE='semgrep/semgrep:latest'
TRIVY_IMAGE='aquasec/trivy:latest'
SEMGREP_RULESETS='p/security-audit p/owasp-top-ten p/golang p/github-actions p/secrets'

# The stdlib advisory component-01 reported against the pinned builder base.
# Measured, not bumped -- the digest bump is owned elsewhere.
BUILDER_CVE='CVE-2026-39822'

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "the docker daemon is not reachable" >&2; exit 2; }
git rev-parse --verify "$REF" >/dev/null 2>&1 || { echo "no such ref: $REF" >&2; exit 2; }

have_image() {
  docker image inspect "$1" >/dev/null 2>&1 && return 0
  docker pull --quiet "$1" >/dev/null 2>&1
}
for img in "$SEMGREP_IMAGE" "$TRIVY_IMAGE"; do
  have_image "$img" || {
    echo "NOT RUN: image $img is neither present locally nor pullable from this host." >&2
    echo "         The probe refuses to simulate a scanner run." >&2
    exit 2
  }
done

SRC="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
cleanup() { if [ "$KEEP" -eq 1 ]; then echo "kept: $WORK"; else rm -rf "$WORK"; fi; }
trap cleanup EXIT

fail=0
note() { echo "$1"; }

# --- tree construction -------------------------------------------------------
#
# Clone the real history rather than replaying a tree into one synthetic
# commit: `semgrep ci` scans "files tracked by git" and will silently scan
# nothing at all if the checkout is not a real repository.
make_clone() {
  dest="$1"
  git clone --no-local --quiet --no-checkout "$SRC" "$dest" || return 1
  git -C "$dest" fetch --quiet "$SRC" "+$REF:refs/heads/probe-base" || return 1
  # Drop every other ref. A clone carries all of the source's branches, and a
  # history-walking scanner reads refs rather than the checkout, so without
  # this the clean leg would answer "clean across whatever branches happened
  # to be in the clone" while claiming to answer for REF.
  git -C "$dest" for-each-ref --format='%(refname)' \
    | grep -v '^refs/heads/probe-base$' \
    | while read -r r; do git -C "$dest" update-ref -d "$r"; done
  git -C "$dest" checkout --quiet probe-base || return 1
  # Rule 1, asserted rather than assumed.
  if [ ! -d "$dest/.git" ]; then
    note "FAIL construction: $dest/.git is not a directory."
    note "     A worktree-style .git file does not resolve inside the scanner"
    note "     container; the scan would walk zero files and report a pass."
    return 1
  fi
  return 0
}

make_clone "$WORK/clean" || { echo "SAST/SCA GATE RED-PROBE FAILED (tree construction)"; exit 1; }
cp -R "$WORK/clean" "$WORK/dirty-semgrep"
cp -R "$WORK/clean" "$WORK/dirty-trivy"
note "ok   construction: three clones of $REF, each with a real .git directory"

semgrep_version="$(docker run --rm --entrypoint semgrep "$SEMGREP_IMAGE" --version 2>/dev/null | tr -d '\r')"
trivy_version="$(docker run --rm "$TRIVY_IMAGE" --version 2>/dev/null | sed -n '1s/^Version: //p' | tr -d '\r')"
note "note versions: semgrep ${semgrep_version:-unknown}, trivy ${trivy_version:-unknown}"

# =============================================================================
# GATE: sast-semgrep
# =============================================================================

SEMGREP_PAYLOAD='redprobe_planted_sast.go'
write_semgrep_payload() {
  cat > "$1/$SEMGREP_PAYLOAD" <<'PAYLOAD'
// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// Planted SAST defect. Never committed to the repository -- this file exists
// only inside a throwaway clone for the duration of a red-probe run.
package redprobeplanted

import (
	"crypto/md5"
	"crypto/tls"
	"math/rand"
)

// Weak hash used where a cryptographic digest is expected.
func PlantedWeakDigest(b []byte) [16]byte { return md5.Sum(b) }

// TLS client configuration with verification disabled and no minimum version.
func PlantedLooseTLS() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

// Non-cryptographic randomness used to mint a token.
func PlantedToken() int { return rand.Int() }
PAYLOAD
}

# Rule ids and message fragments, pinned together. The id alone would pass a
# rule that fired for an unrelated reason after an upstream rewrite.
SEMGREP_RULE_IDS=(
  'go.lang.security.audit.crypto.use_of_weak_crypto.use-of-md5'
  'go.lang.security.audit.crypto.math_random.math-random-used'
  'go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion'
)
SEMGREP_FRAGMENTS=(
  'Detected MD5 hash algorithm'
  'Do not use `math/rand`'
  '`MinVersion` is missing'
)

run_semgrep() {
  # Mirrors the gating pass of the sast-semgrep job. The job's first pass is
  # `semgrep ci --sarif --output=... || true`, which cannot fail the job; the
  # second bare `semgrep ci` is the gate, so that is what is measured.
  docker run --rm -v "$1:/src" -w /src \
    -e SEMGREP_RULES="$SEMGREP_RULESETS" \
    -e SEMGREP_SUPPRESS_ERRORS=false \
    "$SEMGREP_IMAGE" semgrep ci > "$2" 2>&1
  echo $?
}

# --- preflight (rule 4) ------------------------------------------------------
PRE="$WORK/pre-semgrep"
mkdir -p "$PRE"
write_semgrep_payload "$PRE"
git -C "$PRE" init -q .
git -C "$PRE" add -A
git -C "$PRE" -c user.email=probe@local -c user.name=probe commit -qm payload
pre_rc="$(run_semgrep "$PRE" "$WORK/pre-semgrep.out")"
if [ "$pre_rc" -ne 1 ]; then
  note "FAIL semgrep preflight: the payload alone exited $pre_rc, expected 1 (blocking findings)."
  note "     Either the configured rule packs no longer cover these patterns, or"
  note "     semgrep could not fetch its rules and never scanned."
  sed -n '1,25p' "$WORK/pre-semgrep.out"
  fail=1
else
  missing=""
  for i in 0 1 2; do
    grep -qF "${SEMGREP_RULE_IDS[$i]}" "$WORK/pre-semgrep.out" || missing="$missing ${SEMGREP_RULE_IDS[$i]}"
  done
  if [ -n "$missing" ]; then
    note "FAIL semgrep preflight: these rules did not fire in isolation:$missing"
    note "     The class is not covered by the configured packs -- that is a finding,"
    note "     not a flaky run. Do not plant a pattern the rules do not detect."
    fail=1
  else
    note "ok   semgrep preflight: all three planted patterns fire in isolation (exit 1)"
  fi
fi

# --- clean leg ---------------------------------------------------------------
sem_clean_rc="$(run_semgrep "$WORK/clean" "$WORK/semgrep-clean.out")"

# Scope (rule 6): semgrep's own accounting must reconcile with git's file
# count, a source the scanner does not produce. targets scanned + files it
# reports skipping must equal the number of tracked files.
sem_targets="$(sed -n 's/.*Targets scanned: \([0-9]*\).*/\1/p' "$WORK/semgrep-clean.out" | head -1)"
sem_skipped="$(sed -n 's/.*Files matching .semgrepignore patterns: \([0-9]*\).*/\1/p' "$WORK/semgrep-clean.out" | head -1)"
sem_excluded="$(sed -n 's/.*Matching --exclude patterns: \([0-9]*\).*/\1/p' "$WORK/semgrep-clean.out" | head -1)"
tracked="$(git -C "$WORK/clean" ls-files | wc -l | tr -d ' ')"
if [ -z "$sem_targets" ]; then
  note "FAIL semgrep scope: no target count reported; the scanner did not walk a tree"
  fail=1
else
  accounted=$(( sem_targets + ${sem_skipped:-0} + ${sem_excluded:-0} ))
  if [ "$accounted" -ne "$tracked" ]; then
    note "FAIL semgrep scope: scanned $sem_targets + skipped ${sem_skipped:-0} + excluded ${sem_excluded:-0} = $accounted, git tracks $tracked files at $REF."
    note "     The scan surface is not the ref under test, so neither leg answers for $REF."
    fail=1
  else
    note "ok   semgrep scope: $sem_targets scanned + ${sem_skipped:-0} ignored + ${sem_excluded:-0} excluded = $tracked, matching git ls-files at $REF"
  fi
fi

if [ "$sem_clean_rc" -ne 0 ]; then
  note "FAIL semgrep clean leg: the committed tree at $REF reports blocking findings (exit $sem_clean_rc)."
  note "     Either the gate is genuinely red on this ref, or semgrep failed to run."
  sed -n '1,25p' "$WORK/semgrep-clean.out"
  fail=1
else
  note "ok   semgrep clean leg: committed tree at $REF is clean (exit 0)"
fi

# --- dirty leg ---------------------------------------------------------------
write_semgrep_payload "$WORK/dirty-semgrep"
git -C "$WORK/dirty-semgrep" add -A
git -C "$WORK/dirty-semgrep" -c user.email=probe@local -c user.name=probe \
  commit -qm "tree at $REF plus a planted SAST defect"

# Delivery (rule 5). semgrep scans only files tracked by git, so an unstaged
# payload is invisible and a green dirty leg would say nothing about the gate.
if git -C "$WORK/dirty-semgrep" cat-file -e "HEAD:$SEMGREP_PAYLOAD" 2>/dev/null; then
  note "ok   semgrep delivery: $SEMGREP_PAYLOAD is present in the dirty clone's HEAD"
else
  note "FAIL semgrep delivery: $SEMGREP_PAYLOAD is not in the dirty clone's committed tree."
  note "     semgrep scans tracked files only, so the dirty leg measures nothing."
  fail=1
fi

sem_dirty_rc="$(run_semgrep "$WORK/dirty-semgrep" "$WORK/semgrep-dirty.out")"
if [ "$sem_dirty_rc" -ne 1 ]; then
  note "FAIL semgrep dirty leg: a planted weak-crypto / weak-random / weak-TLS file did NOT redden the gate (exit $sem_dirty_rc)."
  note "     This is the fake-green case: the gate runs, reports success, and would pass the same defect in product code."
  sed -n '1,25p' "$WORK/semgrep-dirty.out"
  fail=1
else
  # Attribution (rule 7) and message pin (rule 8) together: the planted file
  # must be named, each expected rule id must appear, and each expected
  # message fragment must appear.
  problems=""
  grep -qF "$SEMGREP_PAYLOAD" "$WORK/semgrep-dirty.out" || problems="$problems payload-file-not-named"
  for i in 0 1 2; do
    grep -qF "${SEMGREP_RULE_IDS[$i]}" "$WORK/semgrep-dirty.out" || problems="$problems rule-missing:${SEMGREP_RULE_IDS[$i]}"
    grep -qF "${SEMGREP_FRAGMENTS[$i]}" "$WORK/semgrep-dirty.out" || problems="$problems message-missing:${SEMGREP_FRAGMENTS[$i]}"
  done
  if [ -n "$problems" ]; then
    note "FAIL semgrep dirty leg: the gate reddened, but not demonstrably on the planted defect:$problems"
    note "     Something else in the tree produced the findings, or a rule fired for a different reason."
    fail=1
  else
    sem_found="$(sed -n 's/.*Findings: \([0-9]*\).*/\1/p' "$WORK/semgrep-dirty.out" | head -1)"
    note "ok   semgrep dirty leg: gate reddened (exit 1, findings ${sem_found:-?}), naming $SEMGREP_PAYLOAD and all three planted rule ids with their messages"
  fi
fi

# =============================================================================
# GATE: sca-trivy-fs
# =============================================================================
#
# Two planted dependency versions, chosen so one carries a fix and one does
# not: `ignore-unfixed: false` in the gate means an unfixed advisory must
# block too, and a single fixed-only payload would leave that half of the
# gate's configuration unproven.
TRIVY_PLANTED_PKGS=('github.com/dgrijalva/jwt-go' 'github.com/gogo/protobuf')
TRIVY_PLANTED_CVES=('CVE-2020-26160' 'CVE-2021-3121')
TRIVY_FRAGMENTS=('access restriction bypass' 'index validation')

plant_go_mod() {
  # Appended, not substituted: the existing require block stays byte-identical
  # so the clean and dirty legs differ only by the planted lines.
  {
    echo ''
    echo 'require ('
    echo '	github.com/dgrijalva/jwt-go v3.2.0+incompatible // redprobe planted'
    echo '	github.com/gogo/protobuf v1.3.1 // redprobe planted'
    echo ')'
  } >> "$1/go.mod"
}

run_trivy_fs() {
  # Mirrors the sca-trivy-fs job: scan-type fs, scan-ref the repo root,
  # severity CRITICAL,HIGH, exit-code 1, ignore-unfixed false. The cache is
  # shared with the host so an offline run uses the database already on disk
  # instead of silently scanning with none.
  docker run --rm -v trivy-cache:/root/.cache -v "$1:/src:ro" "$TRIVY_IMAGE" \
    fs --severity CRITICAL,HIGH --exit-code 1 --ignore-unfixed=false \
    --no-progress /src > "$2" 2>&1
  echo $?
}

# --- preflight (rule 4) ------------------------------------------------------
PRET="$WORK/pre-trivy"
mkdir -p "$PRET"
printf 'module redprobe/preflight\n\ngo 1.26\n' > "$PRET/go.mod"
plant_go_mod "$PRET"
pret_rc="$(run_trivy_fs "$PRET" "$WORK/pre-trivy.out")"
if [ "$pret_rc" -ne 1 ]; then
  note "FAIL trivy preflight: the planted module versions alone exited $pret_rc, expected 1."
  note "     Either the advisories left the database, or trivy has no database and never scanned."
  sed -n '1,25p' "$WORK/pre-trivy.out"
  fail=1
else
  missing=""
  for c in "${TRIVY_PLANTED_CVES[@]}"; do
    grep -qF "$c" "$WORK/pre-trivy.out" || missing="$missing $c"
  done
  if [ -n "$missing" ]; then
    note "FAIL trivy preflight: these advisories did not fire in isolation:$missing"
    note "     Pick payload versions the current database still reports; do not plant a silent one."
    fail=1
  else
    note "ok   trivy preflight: both planted advisories fire in isolation (exit 1)"
  fi
fi

# --- clean leg ---------------------------------------------------------------
trivy_clean_rc="$(run_trivy_fs "$WORK/clean" "$WORK/trivy-clean.out")"

# Scope (rule 6): trivy's own "language-specific files" count must equal the
# number of go.mod files git tracks at REF.
trivy_langfiles="$(sed -n 's/.*Number of language-specific files[^0-9]*\([0-9][0-9]*\).*/\1/p' "$WORK/trivy-clean.out" | head -1)"
gomods="$(git -C "$WORK/clean" ls-files | grep -c '\(^\|/\)go\.mod$')"
if [ -z "$trivy_langfiles" ]; then
  note "FAIL trivy scope: no language-file count reported; the scanner did not walk the tree"
  fail=1
elif [ "$trivy_langfiles" != "$gomods" ]; then
  note "FAIL trivy scope: trivy found $trivy_langfiles language-specific files, git tracks $gomods go.mod file(s) at $REF."
  fail=1
else
  note "ok   trivy scope: $trivy_langfiles language-specific file(s), matching the $gomods go.mod tracked at $REF"
fi

if [ "$trivy_clean_rc" -ne 0 ]; then
  note "FAIL trivy clean leg: the committed tree at $REF already reddens the gate (exit $trivy_clean_rc)."
  note "     Read the table below before treating this as a harness defect: if the"
  note "     finding names a real dependency in go.mod with a fixed version, the"
  note "     sca-trivy-fs context is genuinely red on this ref and needs a bump."
  sed -n '/^go.mod (gomod)/,$p' "$WORK/trivy-clean.out" | sed -n '1,25p'
  fail=1
else
  note "ok   trivy clean leg: committed tree at $REF passes CRITICAL,HIGH (exit 0)"
fi

# --- dirty leg ---------------------------------------------------------------
plant_go_mod "$WORK/dirty-trivy"
git -C "$WORK/dirty-trivy" add -A
git -C "$WORK/dirty-trivy" -c user.email=probe@local -c user.name=probe \
  commit -qm "tree at $REF plus planted vulnerable dependencies"

# Delivery (rule 5).
undelivered=""
for p in "${TRIVY_PLANTED_PKGS[@]}"; do
  git -C "$WORK/dirty-trivy" show "HEAD:go.mod" 2>/dev/null | grep -qF "$p" || undelivered="$undelivered $p"
done
if [ -n "$undelivered" ]; then
  note "FAIL trivy delivery: these planted requires are not in the dirty clone's committed go.mod:$undelivered"
  fail=1
else
  note "ok   trivy delivery: both planted requires present in the dirty clone's HEAD:go.mod"
fi

trivy_dirty_rc="$(run_trivy_fs "$WORK/dirty-trivy" "$WORK/trivy-dirty.out")"
if [ "$trivy_dirty_rc" -ne 1 ]; then
  note "FAIL trivy dirty leg: two known-vulnerable dependencies did NOT redden the gate (exit $trivy_dirty_rc)."
  sed -n '1,25p' "$WORK/trivy-dirty.out"
  fail=1
else
  # Attribution (rule 7): the planted package AND its advisory id must appear,
  # and -- because this tree may already carry an unrelated finding -- each
  # planted advisory must be ABSENT from the clean leg's output. That
  # differential is what makes the dirty leg evidence about the payload rather
  # than about the baseline.
  problems=""
  for i in 0 1; do
    grep -qF "${TRIVY_PLANTED_PKGS[$i]}" "$WORK/trivy-dirty.out" || problems="$problems package-not-named:${TRIVY_PLANTED_PKGS[$i]}"
    grep -qF "${TRIVY_PLANTED_CVES[$i]}" "$WORK/trivy-dirty.out" || problems="$problems cve-missing:${TRIVY_PLANTED_CVES[$i]}"
    grep -qF "${TRIVY_FRAGMENTS[$i]}" "$WORK/trivy-dirty.out" || problems="$problems message-missing:${TRIVY_FRAGMENTS[$i]}"
    grep -qF "${TRIVY_PLANTED_CVES[$i]}" "$WORK/trivy-clean.out" && problems="$problems baseline-already-had:${TRIVY_PLANTED_CVES[$i]}"
  done
  if [ -n "$problems" ]; then
    note "FAIL trivy dirty leg: the gate reddened, but not demonstrably on the planted dependencies:$problems"
    fail=1
  else
    note "ok   trivy dirty leg: gate reddened (exit 1), naming both planted packages, both advisory ids and their titles, none of which the clean leg reported"
  fi
fi

# =============================================================================
# COVERAGE GAP: the fs scan cannot see the builder base image
# =============================================================================
#
# `sca-trivy-fs` is a required context. There is no image-scan context in the
# required set at all, and the two scans do not cover the same ground: a Go
# stdlib advisory against the pinned builder base is invisible to a filesystem
# scan of the source tree because no file in the tree carries the compiler.
# This section measures the asymmetry rather than asserting it. It does not
# change the pin -- that is owned elsewhere.
if [ "$SKIP_IMAGE_GAP" -eq 1 ]; then
  note "note image gap: skipped by request (--skip-image-gap)"
else
  # Rule 2: read the Dockerfile from the named ref, not the working tree.
  builder_ref="$(git show "$REF:Dockerfile" 2>/dev/null \
    | sed -n 's/^FROM .*\(golang:[0-9.]*@sha256:[0-9a-f]*\) .*/\1/p' | head -1)"
  if [ -z "$builder_ref" ]; then
    note "NOT RUN image gap: no digest-pinned golang builder base found in $REF:Dockerfile"
  elif ! have_image "$builder_ref"; then
    note "NOT RUN image gap: $builder_ref is neither present locally nor pullable from this host."
    note "     The probe will not simulate an image scan."
  else
    docker run --rm -v trivy-cache:/root/.cache \
      -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
      image --severity CRITICAL,HIGH --scanners vuln --no-progress "$builder_ref" \
      > "$WORK/trivy-image.out" 2>&1
    img_rc=$?
    if [ "$img_rc" -ne 0 ]; then
      note "NOT RUN image gap: trivy image exited $img_rc without producing a report"
      sed -n '1,15p' "$WORK/trivy-image.out"
    else
      in_fs=no; in_img=no
      grep -qF "$BUILDER_CVE" "$WORK/trivy-clean.out" && in_fs=yes
      grep -qF "$BUILDER_CVE" "$WORK/trivy-image.out" && in_img=yes
      note "note image gap: $builder_ref"
      note "note image gap: $BUILDER_CVE seen by 'trivy fs' over the tree: $in_fs"
      note "note image gap: $BUILDER_CVE seen by 'trivy image' over the builder base: $in_img"
      if [ "$in_fs" = no ] && [ "$in_img" = yes ]; then
        note "note image gap: CONFIRMED -- the required sca-trivy-fs context cannot see this class of"
        note "     advisory, and no image-scan context is required in branch protection."
        sed -n "/$BUILDER_CVE/p" "$WORK/trivy-image.out" | head -1
      elif [ "$in_fs" = yes ]; then
        note "note image gap: NOT confirmed -- the fs scan does report $BUILDER_CVE, so the coverage claim is wrong."
      else
        note "note image gap: NOT confirmed -- the image scan does not report $BUILDER_CVE either."
        note "     Check the database date and the digest before drawing a conclusion."
      fi
    fi
  fi
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "SAST/SCA GATE RED-PROBE FAILED"
  exit 1
fi
echo "SAST/SCA GATE RED-PROBE PASSED: sast-semgrep and sca-trivy-fs each redden on a planted defect they name"
