#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Red-probe the secrets-gitleaks gate INLINE: prove the required context
# actually reddens on a planted credential, and is clean on the tree as
# committed.
#
# A gate nobody proves fires is indistinguishable from a gate that matches
# nothing: both report green. This probe tells those apart by planting a
# credential and requiring the scan to redden, then requiring it to pass once
# the plant is gone.
#
# RELATIONSHIP TO scripts/secrets-gate-redprobe.sh
# That probe is the DEEP one and this file neither replaces nor duplicates it.
# It drives both secrets contexts across four legs -- clean, dirty, the
# pull-request range trufflehog actually walks, and an allowlist control that
# separates a value-scoped suppression from a docs/ blanket -- attributing every
# finding to a planted filename and an expected rule name. That costs minutes
# and a preflight loop, which is why gate-redprobe.yml runs it on a narrow paths
# filter plus a daily cron.
#
# The two answer different questions. The deep probe answers "is the gate still
# shaped the way we believe", thoroughly, on the changes that can reshape it.
# This one answers "does the gate still fire at all", cheaply, on EVERY pull
# request -- because it rides the secrets-gitleaks job itself, which is already
# in main's required contexts. A backstop on a schedule reports its verdict to a
# run nobody reads, a day after the merge; a step inside a required job turns
# the same verdict into a blocked merge, with no branch-protection edit and no
# second context to keep in sync. Deliberately one scanner, one plant, two arms:
# anything richer belongs in the deep probe, and anything slower stops being
# affordable per-PR.
set -euo pipefail

# The scanner invocation is DERIVED from security.yml rather than restated here.
# A hand-copied invocation drifts from the gate it claims to measure -- a probe
# pinned to one image while the job runs another reports on a scanner no PR ever
# uses. Pulling the pin out of the workflow keeps the two in lockstep by
# construction.
readonly WORKFLOW=".github/workflows/security.yml"
if [ ! -f "$WORKFLOW" ]; then
  echo "::error::$WORKFLOW not found; the probe cannot derive the scanner it must measure (fail-closed)"
  exit 1
fi

image=$(grep -oE 'zricethezav/gitleaks:v[0-9]+\.[0-9]+\.[0-9]+' "$WORKFLOW" | head -1)
if [ -z "$image" ]; then
  echo "::error::no pinned zricethezav/gitleaks:vX.Y.Z image found in $WORKFLOW -- the job moved to a different scanner or an unpinned tag, and this probe has not been checked against it (fail-closed)"
  exit 1
fi

# The ARGUMENTS are derived too, not just the image. Pinning the image while
# hardcoding the flags leaves the probe measuring a scan the job does not run:
# point the job at a path that does not exist and it stops scanning anything,
# while a probe with its own --source keeps reporting a healthy gate.
args=$(grep -oE 'detect --source=[^ ]+( --[a-z-]+)*' "$WORKFLOW" | head -1)
if [ -z "$args" ]; then
  echo "::error::no 'detect --source=...' invocation found in $WORKFLOW -- the job's scan arguments changed shape and this probe has not been checked against them (fail-closed)"
  exit 1
fi
# shellcheck disable=SC2206 # deliberate word-splitting: the derived flags are a
# fixed set of literals from the workflow, not user input.
readonly scan_args=($args)
echo "probe derives the scan from $WORKFLOW: $image ${scan_args[*]}"

# Note on ruleset: the job mounts the checkout at the path it passes to
# --source, so gitleaks auto-loads the repository's root .gitleaks.toml -- the
# allowlist in that file is live in every scan this probe makes, exactly as it
# is in the gate. The planted value below is therefore chosen to be nothing the
# allowlist names.
#
# The job scans COMMITS (`detect --source=...` with no --no-git), so a planted
# working-tree file is invisible to it -- probing with one would report a green
# gate that had simply looked elsewhere. The probe therefore commits the planted
# value to a scratch branch and scans that, which is the path a real leak takes.
probe_file=".gitleaks-redprobe.tmp.toml"
# The COMMIT, not the branch name. CI checks out a detached HEAD, where
# `rev-parse --abbrev-ref HEAD` answers the literal string "HEAD" -- checking
# that back out is a no-op, so the planted commit would survive cleanup and the
# clean arm would fail against the probe's own plant. A SHA restores the
# starting point on a branch and a detached HEAD alike.
start_ref=$(git rev-parse HEAD)
readonly start_ref
# The starting BRANCH when there was one, so a developer running this locally
# does not get handed back a detached HEAD. Empty in CI, which is correct: the
# run started detached and restoring the SHA is the whole restoration.
start_branch=$(git symbolic-ref --quiet --short HEAD || true)
readonly start_branch
cleanup() {
  rm -f "$probe_file"
  # Leave HEAD where the run found it BEFORE deleting anything, and do it
  # unconditionally rather than only when the scratch branch still exists: an
  # early return here is how a half-finished run strands HEAD on the planted
  # commit, and the clean arm then scans a history containing the probe's own
  # plant and reports a leak that is not in the tree.
  #
  # --force because a plain checkout REFUSES when the working tree carries an
  # edit it would overwrite -- a developer editing this very script is enough.
  # Under `|| true` that refusal is silent, and the run ends parked on the
  # plant. Forcing is safe precisely here: the only commit being left behind is
  # the one this function is about to delete.
  if [ -n "$start_branch" ]; then
    git checkout -q --force "$start_branch" 2>/dev/null || true
  else
    # Started detached (the CI shape): restoring the SHA is the restoration.
    git checkout -q --force --detach "$start_ref" 2>/dev/null || true
  fi
  git branch -q -D redprobe-scratch 2>/dev/null || true
}
trap cleanup EXIT

# Assembled at runtime from parts so the literal never appears in the tree. A
# committed probe value is exactly what an allowlist entry (or a scanner's own
# example-secret exclusion) would neutralise -- the probe would then pass while
# proving nothing, which is the failure mode it exists to catch.
planted="glpat-$(printf 'PROBE')onlyFAKE0987654321"
# -B, not -b: a prior run killed before its trap fired leaves the scratch branch
# behind, and `-b` would abort on it -- turning one interrupted run into a probe
# that can never run again without manual repair.
git checkout -q -B redprobe-scratch
printf 'gitlab_pat = "%s"\n' "$planted" >"$probe_file"
git add "$probe_file"
git -c user.email=redprobe@localhost -c user.name=redprobe commit -q -m "probe: planted credential (scratch branch, never pushed)"

# (1) PLANTED: the scan MUST report a leak. The status is captured rather than
# left to `set -e`, because a non-zero exit is the expected outcome here.
if docker run --rm -v "$PWD:/repo" "$image" "${scan_args[@]}" >/dev/null 2>&1; then
  echo "::error::gitleaks reported NO leak on a planted GitLab PAT -- the secrets gate is not detecting credentials. Check the image pin and the detect arguments in $WORKFLOW, and the allowlist in .gitleaks.toml; a scanner that finds a planted PAT nowhere finds a real one nowhere."
  exit 1
fi
echo "ok: gate is RED on a planted secret"

# (2) CLEAN: back on the real branch the same scan must pass. Without this arm a
# scanner that failed on everything would satisfy arm (1) and look healthy.
cleanup
trap - EXIT
if ! docker run --rm -v "$PWD:/repo" "$image" "${scan_args[@]}" >/dev/null 2>&1; then
  echo "::error::gitleaks did not pass on the clean tree. Either a real secret is committed, the probe branch was not cleaned up, or the scan derived from $WORKFLOW is broken (a --source path that does not exist, or an image pin whose entrypoint differs) -- check the derived invocation printed above."
  exit 1
fi
echo "ok: gate is clean on the tree as committed"

echo "gitleaks-inline-redprobe: the gate fires RED on a planted secret and green on a clean tree"
