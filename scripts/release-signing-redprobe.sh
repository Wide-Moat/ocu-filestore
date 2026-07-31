#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Red-probe the SIGNED SBOM + PROVENANCE gate (`sbom-and-sign` in
# .github/workflows/release.yml).
#
# This gate is structurally unlike the secrets/SAST/SCA gates. release.yml
# triggers ONLY on `push: tags: [v*]` — there is no pull_request trigger — so
# `sbom-and-sign` cannot be a required PR context, and must not be made one:
# GitHub counts a SKIPPED required check as PASSED, so a release-only job
# marked required-on-PR would be eternally, meaninglessly green. DONE for this
# gate is therefore not "required in branch protection". DONE is: the release
# pipeline FAILS when the SBOM or the signature is absent.
#
# A tag cannot be pushed from a probe, so the subject under test is the
# pipeline DEFINITION rather than a live run. This script is two things in one
# file:
#
#   1. an ANALYZER over the workflow YAML (`--check FILE`), which asserts the
#      properties that make the gate real; and
#   2. a RED-PROBE of that analyzer, which mutates a COPY of the workflow in a
#      temp directory — never the committed file — so that each property is
#      violated in turn, and requires the analyzer to redden with the RIGHT
#      MESSAGE, not merely with a nonzero violation count. A self-test that
#      compares only the NUMBER of violations passes a violation raised for the
#      wrong reason; every mutation below pins the expected violation codes as
#      a SET, pins how many violations may carry each of them, and pins the
#      substrings that must appear in THAT violation's own message. Matching
#      the substrings against a join of every message is the same false-green
#      class the analyzer itself is probed for, and is not done here.
#
# A gate can be defeated without being removed, so three of the analyzer's
# assertions are about defeat rather than absence: `if:` on the signing job, a
# truthy `continue-on-error:` on the job or on any of its signing steps (the
# job fails and is recorded as a success, satisfying every downstream needs
# edge), and an always()-style condition anywhere on the needs-path from a
# publisher back to the signing job (the edge survives; the gate does not).
#
# The probe's GREEN control is a "repaired baseline": the committed workflow
# with its publish/sign ordering restructured so that every assertion holds.
# Without a leg that produces zero violations, an analyzer that is a
# constant-RED stub would pass every red leg vacuously. The repaired baseline
# is a control construction only — it is NOT a proposed remedy for the ordering
# finding below; the owner chooses that.
#
# ORDERING FINDING (confirmed firsthand, reported, deliberately NOT fixed here):
# in the committed workflow `ghcr-image` pushes the container image
# (docker/build-push-action with push: true) and needs only
# [tag-format, security-gates, verify], while `sbom-and-sign` needs
# [..., ghcr-image, image-scan]. Signing therefore runs AFTER publish: the
# image is pullable under its release tag before any signature exists. If
# sbom-and-sign fails — expired OIDC, Rekor unavailable, the SBOM action
# down — the unsigned image stays published and red CI retracts nothing.
# The analyzer reports this as SIGN-AFTER-PUBLISH.
#
# THE EXCEPTIONS LEDGER
# Closing that finding restructures the release pipeline, which is the owner's
# call, so left alone the probe exits 3 forever and can never be a CI gate. Both
# obvious ways out are worse than the disease: a blocking job left permanently
# red teaches every reader that "filestore checks is always red" is the normal
# state, and a real regression then rides through unnoticed; and marking the job
# continue-on-error is precisely the false-green pattern this probe exists to
# detect. So neither. A finding the change in hand can close gets FIXED; a
# finding that needs work elsewhere gets NAMED, in
# .github/signing-order-exceptions (override with $SIGNING_ORDER_EXCEPTIONS),
# together with the condition that deletes the entry.
#
# An entry is keyed on FILE PLUS JOB — `path/to/workflow.yml::job-id` — not on a
# file. A file-keyed entry would admit every present and future signing-order
# violation anywhere in release.yml, including one raised against a second
# publishing job added months later; that is an allow-list, not an admission. A
# malformed entry is refused rather than skipped, an entry naming a workflow
# outside the tree is refused (it could never match, so it could never be
# reported stale either), and a violation with no single job to attribute it to
# cannot be admitted at all. Every admitted gap PRINTS on every run, so a reader
# can tell "the gate found nothing" from "the gate found something we agreed to
# carry". An entry whose file+job no longer violates is a HARD ERROR: growth in
# the ledger shows up in a diff a reviewer has to agree to, shrinkage does not,
# so the probe forces the shrinkage instead of asking for it.
#
# EXIT CODES
#   0  the analyzer and its ledger are proven two-sided AND the committed
#      workflow carries no violation beyond the ones the ledger admits (which
#      are printed, never silent)
#   1  PROBE INTEGRITY FAILURE — a mutation failed to redden, reddened with the
#      wrong message, the green control did not come back clean, or a ledger leg
#      failed. Nothing the analyzer says about the committed workflow can be
#      trusted in this state.
#   2  the probe could not run (missing python3 / PyYAML / workflow file, or an
#      exceptions ledger it could not parse — running on a ledger half of which
#      was silently dropped would report a gap as unadmitted with no way to see
#      why)
#   3  the analyzer is sound, and the COMMITTED workflow carries a violation
#      that no ledger entry admits. Non-zero on purpose: a live finding must
#      never read as green, and it is reported separately from exit 1 so a
#      broken probe is never mistaken for a broken pipeline.
#   4  the LEDGER has rotted: an entry names a file+job that no longer violates.
#      Delete the entry. Separate from 3 because the pipeline is fine and only
#      the bookkeeping is not; both are printed when both apply.
#
# Usage:
#   scripts/release-signing-redprobe.sh             # full probe, working tree
#   scripts/release-signing-redprobe.sh --ref REF   # probe the workflow AT REF
#   scripts/release-signing-redprobe.sh --check F   # analyzer only, on file F
#   scripts/release-signing-redprobe.sh --keep      # keep the temp mutations
#   scripts/release-signing-redprobe.sh --registry [IMAGE]
#                                                   # ask the REGISTRY whether
#                                                   # the published images are
#                                                   # actually signed (opt-in,
#                                                   # needs cosign + network;
#                                                   # own exit codes 0/1/2)
#
# The subject is named in the first line of output. Default is the working
# tree, which is what a developer wants pre-push; --ref extracts the workflow
# with `git show REF:...` so a CI or audit run can pin exactly which revision
# was judged instead of whatever happens to be checked out.
#
# Wired into .github/workflows/gate-redprobe.yml as a blocking job, on a paths
# filter that includes release.yml and the ledger, so an edit to either arrives
# in the same pull request as the probe's verdict on it. Not wired into
# `make check`: it needs python3 + PyYAML, which the Go toolchain does not
# carry.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="${REPO_ROOT}/.github/workflows/release.yml"

# --- registry mode -----------------------------------------------------------
#
# A separate question the pipeline SHAPE cannot answer: for the images that are
# actually published, does a signature actually EXIST? A workflow can be
# present, active and hardened and still never have run — a sibling repository
# was measured at 0 signatures across 4 published images with exactly this
# pipeline in place. So this leg asks the registry, not the YAML.
#
# Opt-in because it needs cosign and network egress. It never infers presence
# from the workflow definition, and it never infers absence from a failure:
# only an artifact set cosign actually read earns a signed/unsigned verdict.
# Everything else — an unreachable registry, an auth wall, any output this
# script cannot classify — is NOT MEASURED (exit 2), never "no signatures".
if [ "${1:-}" = "--registry" ]; then
  shift
  IMAGE="${1:-ghcr.io/wide-moat/ocu-filestore}"
  command -v cosign >/dev/null 2>&1 || {
    echo "NOT MEASURED: cosign is not installed; signature presence cannot be checked" >&2
    exit 2
  }
  echo "registry signature census — $IMAGE"
  # docker/metadata-action's type=semver,pattern={{version}} strips the leading
  # v, so the registry tag for git tag v1.2.3 is 1.2.3. Probing the git spelling
  # reports MANIFEST_UNKNOWN for every release and reads as "nothing published".
  #
  # Classification defaults to NOT MEASURED. The ONLY outputs that earn a
  # verdict about a tag are the ones this loop recognises: an artifact-absent
  # reply, or a tree cosign actually read. Anything else — DNS failure, a proxy
  # error, an authentication wall, a future cosign message — is unknown, not
  # "unsigned". The inverse default (enumerate the failures, treat the
  # fall-through as no-signature) printed a confident "carries NO cosign
  # signature" for every tag when this was pointed at an unreachable host,
  # which is the loudest possible way to be wrong about a supply chain.
  published=0; signed=0; attested=0; unsigned_list=""; absent=0; unreachable=0
  for gtag in $(git -C "$REPO_ROOT" tag --list 'v*' | sort); do
    rtag="${gtag#v}"
    out=""
    for _ in 1 2 3; do
      out="$(cosign tree "${IMAGE}:${rtag}" 2>&1)"
      case "$out" in *"TLS handshake timeout"*|*"connection reset"*|*"i/o timeout"*) continue ;; esac
      break
    done
    case "$out" in
      *MANIFEST_UNKNOWN*|*NAME_UNKNOWN*)
        echo "  $rtag  no image published under this tag"; absent=$((absent + 1)); continue ;;
      *UNAUTHORIZED*|*"denied"*)
        echo "  $rtag  NOT MEASURED (no anonymous read access)"; unreachable=$((unreachable + 1)); continue ;;
      *"TLS handshake timeout"*|*"connection reset"*|*"i/o timeout"*|*"no such host"*|\
      *"context deadline exceeded"*|*"connection refused"*)
        echo "  $rtag  NOT MEASURED (registry unreachable)"; unreachable=$((unreachable + 1)); continue ;;
    esac
    # Did cosign actually READ the artifact set for this image? Either it said
    # there is none, or it printed a tree. Both are measurements; nothing else
    # is.
    read_ok=no
    case "$out" in
      *"No Supply Chain Security Related Artifacts found"*) read_ok=yes ;;
      *"artifacts via OCI referrer"*) read_ok=yes ;;
      *"for an image tag"*) read_ok=yes ;;
    esac
    if [ "$read_ok" = no ]; then
      why="$(printf '%s\n' "$out" | head -2 | tail -1)"
      echo "  $rtag  NOT MEASURED (cosign output not recognised: ${why:-empty})"
      unreachable=$((unreachable + 1)); continue
    fi
    published=$((published + 1))
    s=no; a=no
    case "$out" in *"cosign/sign"*|*"Signatures for an image tag"*) s=yes; signed=$((signed + 1)) ;; esac
    case "$out" in *"slsa.dev/provenance"*|*"Attestations for an image tag"*) a=yes; attested=$((attested + 1)) ;; esac
    [ "$s" = no ] && unsigned_list="$unsigned_list $rtag"
    echo "  $rtag  published, signature=$s provenance=$a"
  done
  echo
  echo "published=$published signed=$signed attested=$attested absent=$absent not-measured=$unreachable"
  if [ -n "$unsigned_list" ]; then
    echo "FINDING: these published images carry NO cosign signature:$unsigned_list"
    echo "         cosign read the artifact set for each of these tags and it does not"
    echo "         contain a signature; no error path reaches this verdict."
    echo "         A signing pipeline that exists but has never signed a shipped image"
    echo "         protects nothing a consumer can verify."
    exit 1
  fi
  if [ "$unreachable" -gt 0 ]; then
    echo "NOT MEASURED: $unreachable tag(s) could not be read, so this census is partial" >&2
    echo "              and presence is unknown for them — which is NOT the same claim" >&2
    echo "              as 'no signatures exist'." >&2
    exit 2
  fi
  if [ "$published" -eq 0 ]; then
    echo "no image is published under any release tag; nothing to measure"
    exit 0
  fi
  echo "every published image carries a cosign signature."
  echo "NOTE: this measures PRESENCE only. Cryptographic verification"
  echo "      (cosign verify) additionally needs the Sigstore TUF root."
  exit 0
fi

command -v python3 >/dev/null 2>&1 || {
  echo "NOT RUN: python3 is required by the release-signing red-probe" >&2
  exit 2
}
python3 -c 'import yaml' >/dev/null 2>&1 || {
  echo "NOT RUN: python3 PyYAML is required by the release-signing red-probe" >&2
  exit 2
}
[ -f "$WORKFLOW" ] || {
  echo "NOT RUN: no workflow at $WORKFLOW — the subject under test is absent" >&2
  exit 2
}

exec python3 - "$WORKFLOW" "$REPO_ROOT" "$@" <<'PYEOF'
import copy
import itertools
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

WORKFLOW = sys.argv[1]
REPO_ROOT = sys.argv[2]
ARGS = sys.argv[3:]

WORKFLOW_REL = ".github/workflows/release.yml"
MODE_CHECK = None
REF = None
KEEP = False
i = 0
while i < len(ARGS):
    a = ARGS[i]
    if a == "--check":
        MODE_CHECK = ARGS[i + 1]
        i += 2
    elif a == "--ref":
        REF = ARGS[i + 1]
        i += 2
    elif a == "--keep":
        KEEP = True
        i += 1
    else:
        print("unknown argument: %s" % a, file=sys.stderr)
        sys.exit(2)

SIGN_JOB = "sbom-and-sign"


# ---------------------------------------------------------------------------
# EXCEPTIONS LEDGER
#
# A finding the change in hand can close gets FIXED. A finding that needs work
# elsewhere gets NAMED here, with the condition that removes it. Neither gets
# switched off: a gate left permanently red decays into noise exactly as a
# disabled one decays into absence, and a real regression then rides through it.
#
# Entries are keyed on FILE PLUS JOB. Keying on the file alone would admit every
# present and future signing-order violation anywhere in that workflow, which is
# an allow-list wearing an admission's label.
# ---------------------------------------------------------------------------

EXCEPTIONS_DEFAULT = os.path.join(REPO_ROOT, ".github", "signing-order-exceptions")
SEPARATOR = "::"


def ledger_key(path):
    """The name a ledger entry must use for this file.

    Repo-relative when the file is inside the repository — so an entry reads the
    way a reviewer writes it and survives a different checkout directory — and
    an absolute real path otherwise.
    """
    real = os.path.realpath(path)
    root = os.path.realpath(REPO_ROOT)
    if real.startswith(root + os.sep):
        return os.path.relpath(real, root)
    return real


def load_ledger(path):
    """Parse the ledger into ({(file key, job id)}, [complaints]).

    A caller handed a complaint must REFUSE TO RUN rather than proceed on a
    ledger it did not understand. Every rejection below exists because the
    silent alternative rots: a line the parser skipped would leave a gap
    unadmitted and the gate red for a reason the ledger claims to have named,
    with nothing on screen connecting the two; and an entry naming a workflow
    that is not in the tree could never match a violation, so it could never be
    reported stale either, and would sit there forever.
    """
    entries, errors = set(), []
    if not os.path.exists(path):
        return entries, errors
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(SEPARATOR)
            if len(parts) != 2:
                errors.append(
                    "%s:%d: %r is not '<workflow path>%s<job id>' — %d separator(s), "
                    "exactly 1 required" % (path, lineno, line, SEPARATOR, len(parts) - 1))
                continue
            f, job = parts[0].strip(), parts[1].strip()
            if not f or not job:
                errors.append(
                    "%s:%d: %r leaves the %s empty; an entry keyed on a file alone "
                    "would admit every violation in that workflow, present and future"
                    % (path, lineno, line, "job id" if f else "workflow path"))
                continue
            abs_ = os.path.realpath(os.path.join(REPO_ROOT, f))
            if not os.path.isfile(abs_):
                errors.append(
                    "%s:%d: %r names a workflow that is not in the tree; it can never "
                    "match a violation, and so can never be reported stale either"
                    % (path, lineno, line))
                continue
            entries.add((ledger_key(abs_), job))
    return entries, errors


def partition(violations, subject_key, entries):
    """Split violations into (reported, admitted) and name the stale entries.

    A violation is admitted only when an entry names BOTH this file and the
    exact job the violation is attributed to. A violation with no job — a
    missing tag trigger, a workflow in which no publisher is recognised at all —
    belongs to the workflow rather than to one job, so no entry can name it and
    it is always reported.

    STALE is the anti-rot rule: an entry for THIS file that admitted nothing no
    longer has a violation to carry, and must be deleted. It is scoped to the
    subject because a run judges one workflow, and an entry about a file this
    run did not analyze has not been shown to be stale — only unexercised.
    """
    reported, admitted, used = [], [], set()
    for code, job, msg in violations:
        key = (subject_key, job)
        if job is not None and key in entries:
            admitted.append((code, job, msg))
            used.add(key)
        else:
            reported.append((code, job, msg))
    stale = sorted(e for e in entries if e[0] == subject_key and e not in used)
    return reported, admitted, stale


# ---------------------------------------------------------------------------
# ANALYZER
#
# Returns a list of (CODE, job, message). CODE is the pinned fragment the
# red-probe asserts on; the message carries the evidence a human needs; job is
# the job the violation is attributed to, or None when it belongs to the
# workflow as a whole. The ledger admits by (file, job), so an unattributed
# violation is one no entry can ever admit — that is deliberate.
# ---------------------------------------------------------------------------

def triggers_of(wf):
    # PyYAML resolves the bare key `on:` to the boolean True (YAML 1.1). Both
    # spellings must be accepted or the trigger check silently passes on a
    # workflow with no trigger at all.
    if True in wf:
        return wf[True]
    return wf.get("on")


def steps_of(job):
    s = job.get("steps")
    return s if isinstance(s, list) else []


def uses_of(step):
    u = step.get("uses")
    return u if isinstance(u, str) else ""


def run_of(step):
    r = step.get("run")
    return r if isinstance(r, str) else ""


def run_lines(step):
    # Shell comments inside a run block must not be read as commands: the
    # committed workflow explains `cosign sign` in a comment directly above the
    # call, and a naive substring match would find the explanation and pass
    # even after the call itself was deleted.
    out = []
    for line in run_of(step).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append(stripped)
    return out


def show(val):
    # YAML booleans round-trip through PyYAML as Python bools; print them in
    # the spelling a reader will find in the workflow file.
    if isinstance(val, bool):
        return "true" if val else "false"
    return val


def continue_on_error_set(node):
    """True unless continue-on-error is absent or literally false.

    An expression (`${{ ... }}`) is not literally false, and whether it
    evaluates false on a release run cannot be read off the file, so it counts
    as set.
    """
    val = (node or {}).get("continue-on-error")
    return val is not None and str(val).strip().lower() != "false"


def is_signing_step(step):
    """A step whose failure means the release is unsigned or unattested."""
    uses = uses_of(step)
    for prefix in ("sigstore/cosign-installer", "anchore/sbom-action",
                   "anchore/syft-action", "actions/attest-build-provenance"):
        if uses.startswith(prefix):
            return True
    for line in run_lines(step):
        if re.search(r"\bcosign\b", line) or "syft " in line or "cyclonedx" in line:
            return True
    return False


def needs_of(job):
    n = job.get("needs")
    if n is None:
        return []
    if isinstance(n, str):
        return [n]
    return list(n)


def transitive_needs(jobs, name, seen=None):
    if seen is None:
        seen = set()
    for dep in needs_of(jobs.get(name, {}) or {}):
        if dep in seen:
            continue
        seen.add(dep)
        if dep in jobs:
            transitive_needs(jobs, dep, seen)
    return seen


# `if:` conditions that make a job run even when a job it needs did NOT
# succeed. Under one of these a `needs` edge is an ordering hint, not a gate:
# always() and !cancelled() run the job after an upstream failure or skip, and
# failure() runs it precisely when the upstream failed.
DEFEATING_IF = re.compile(r"always\s*\(\s*\)|!\s*cancelled\s*\(\s*\)|\bfailure\s*\(\s*\)")


def defeats_gate(job):
    """How this job stops gating the jobs it needs, if it does.

    Two fields do it, and both leave the `needs` edge in the file: an
    always()-style condition (the job runs whatever the upstream did) and
    continue-on-error (the job's own failure is recorded as a success, so
    everything downstream of it proceeds). Returns the field as a reader would
    find it in the workflow, or None.
    """
    job = job or {}
    cond = job.get("if")
    if cond is not None and DEFEATING_IF.search(str(cond)):
        return "if: %s" % cond
    if continue_on_error_set(job):
        return "continue-on-error: %s" % show(job.get("continue-on-error"))
    return None


def leads_to(jobs, name, target):
    return name == target or target in transitive_needs(jobs, name)


def hard_gated(jobs, name, target, path=frozenset()):
    """True when `name` cannot start unless `target` SUCCEEDED.

    The existence of a needs-edge does not establish this, which is why the
    edge alone is not what the ordering check asserts: an always()-style
    condition or a continue-on-error on the publisher — or on any job along
    the needs-path — keeps the edge in the file while removing the gate it
    appears to be.
    """
    if name in path:
        return False
    path = path | {name}
    if defeats_gate(jobs.get(name)):
        return False
    for dep in needs_of(jobs.get(name) or {}):
        if dep == target:
            return True
        if dep in jobs and hard_gated(jobs, dep, target, path):
            return True
    return False


def defeated_by(jobs, name, target, path=frozenset()):
    """(job, field) that turns every needs-path to `target` into a non-gate."""
    if name in path:
        return None
    path = path | {name}
    field = defeats_gate(jobs.get(name))
    if field:
        return (name, field)
    for dep in needs_of(jobs.get(name) or {}):
        if dep == target or dep not in jobs:
            continue
        if not leads_to(jobs, dep, target):
            continue
        found = defeated_by(jobs, dep, target, path)
        if found:
            return found
    return None


def publishers(jobs):
    """Jobs that make an artifact publicly retrievable.

    Detected by STEP CONTENT, never by job name. A name-keyed check would be
    satisfied by renaming the job, and would then report nothing while the
    pipeline still published before signing.
    """
    found = []
    for name, job in jobs.items():
        job = job or {}
        for step in steps_of(job):
            uses = uses_of(step)
            with_ = step.get("with") or {}
            if uses.startswith("docker/build-push-action"):
                if str(with_.get("push", "")).strip().lower() == "true":
                    found.append((name, "docker/build-push-action with push: true"))
                    break
            if uses.startswith("softprops/action-gh-release"):
                found.append((name, "softprops/action-gh-release publishes release assets"))
                break
            body = " ".join(run_lines(step))
            if "docker push" in body or "crane push" in body or "gh release create" in body:
                found.append((name, "a run step pushes an artifact"))
                break
    return found


def analyze(path):
    with open(path, "r", encoding="utf-8") as fh:
        wf = yaml.safe_load(fh)
    v = []

    def bad(code, msg, job=None):
        # `job` is the job this violation is attributed to, and it is the second
        # half of the ledger key. None means the violation belongs to the
        # workflow rather than to any one job, and is therefore unadmittable.
        v.append((code, job, msg))

    jobs = wf.get("jobs") or {}

    # --- A. the job exists, is reachable from the tag trigger, is not skipped -
    trig = triggers_of(wf) or {}
    push = (trig.get("push") or {}) if isinstance(trig, dict) else {}
    tags = push.get("tags") if isinstance(push, dict) else None
    if not tags:
        bad("TAG-TRIGGER-MISSING",
            "the workflow does not trigger on push tags, so '%s' can never run "
            "on a release" % SIGN_JOB)

    if SIGN_JOB not in jobs:
        bad("SBOM-SIGN-JOB-MISSING",
            "job '%s' is absent from the workflow; nothing signs a release" % SIGN_JOB,
            SIGN_JOB)
        job = {}
    else:
        job = jobs[SIGN_JOB] or {}

    for name, j in jobs.items():
        j = j or {}
        for dep in needs_of(j):
            if dep not in jobs:
                bad("NEEDS-UNKNOWN-JOB",
                    "job '%s' needs '%s', which is not defined; the graph never "
                    "runs" % (name, dep), name)
    if SIGN_JOB in jobs and SIGN_JOB in transitive_needs(jobs, SIGN_JOB):
        bad("NEEDS-CYCLE",
            "job '%s' transitively needs itself; the graph is unrunnable" % SIGN_JOB,
            SIGN_JOB)

    if "if" in job:
        bad("SBOM-SIGN-CONDITIONAL",
            "job '%s' carries an if: (%s); a skipped job reports success and "
            "signs nothing" % (SIGN_JOB, job.get("if")), SIGN_JOB)
    # continue-on-error is the same class as if: and just as invisible in a
    # green run — the difference is that the job DOES run, fails, and is then
    # recorded as successful. Every downstream needs-edge is satisfied by a job
    # that signed nothing, and the pipeline publishes with a green tick.
    if continue_on_error_set(job):
        bad("SBOM-SIGN-CONTINUE-ON-ERROR",
            "job '%s' carries continue-on-error: %s; the job's failure is "
            "recorded as success, so every downstream needs-edge is satisfied "
            "by a run that signed nothing"
            % (SIGN_JOB, show(job.get("continue-on-error"))), SIGN_JOB)
    for step in steps_of(job):
        if is_signing_step(step) and continue_on_error_set(step):
            bad("SBOM-SIGN-CONTINUE-ON-ERROR",
                "step '%s' in job '%s' carries continue-on-error: %s; the "
                "signing step can fail while the job still reports success"
                % (step.get("name") or uses_of(step) or "<unnamed>", SIGN_JOB,
                   show(step.get("continue-on-error"))), SIGN_JOB)
    for dep in sorted(transitive_needs(jobs, SIGN_JOB)):
        if "if" in (jobs.get(dep) or {}):
            bad("SBOM-SIGN-UPSTREAM-CONDITIONAL",
                "'%s' depends on '%s', which carries an if:; when the upstream "
                "skips, the signing job skips with it" % (SIGN_JOB, dep), dep)

    perms = job.get("permissions") or {}
    if str(perms.get("id-token", "")).strip().lower() != "write":
        bad("OIDC-PERMISSION-MISSING",
            "job '%s' does not grant id-token: write; cosign keyless signing "
            "cannot obtain an OIDC token" % SIGN_JOB, SIGN_JOB)
    if str(perms.get("attestations", "")).strip().lower() != "write":
        bad("ATTESTATION-PERMISSION-MISSING",
            "job '%s' does not grant attestations: write; build provenance "
            "cannot be recorded" % SIGN_JOB, SIGN_JOB)

    # --- B. it really produces an SBOM and real signatures -------------------
    has_installer = False
    has_sbom = False
    has_blob_sign = False
    image_sign_refs = []
    attest_steps = []
    for step in steps_of(job):
        uses = uses_of(step)
        with_ = step.get("with") or {}
        if uses.startswith("sigstore/cosign-installer"):
            has_installer = True
        if uses.startswith("anchore/sbom-action") or uses.startswith("anchore/syft-action"):
            has_sbom = True
        if uses.startswith("actions/attest-build-provenance"):
            attest_steps.append(with_)
        for line in run_lines(step):
            if "syft " in line or "cyclonedx" in line:
                has_sbom = True
            if "cosign sign-blob" in line:
                has_blob_sign = True
            elif re.search(r"\bcosign\s+sign\b", line):
                image_sign_refs.append(line)

    if not has_installer:
        bad("COSIGN-INSTALL-MISSING",
            "job '%s' never installs cosign; no step can sign" % SIGN_JOB, SIGN_JOB)
    if not has_sbom:
        bad("SBOM-STEP-MISSING",
            "job '%s' has no SBOM generation step; the release ships without a "
            "bill of materials" % SIGN_JOB, SIGN_JOB)
    if not has_blob_sign:
        bad("COSIGN-BLOB-MISSING",
            "job '%s' never runs 'cosign sign-blob'; the released binaries are "
            "unsigned" % SIGN_JOB, SIGN_JOB)

    if not image_sign_refs:
        bad("COSIGN-IMAGE-SIGN-MISSING",
            "job '%s' never runs 'cosign sign' on the container image; the "
            "published image is unsigned" % SIGN_JOB, SIGN_JOB)
    else:
        for line in image_sign_refs:
            # Signing by digest is the property under test. A mutable tag can be
            # repointed after signing, so a tag signature attests to whatever the
            # tag happens to resolve to at verification time.
            if "@" not in line:
                bad("COSIGN-IMAGE-BY-TAG",
                    "'cosign sign' targets a mutable tag, not a digest (%s); the "
                    "tag can be repointed after signing" % line, SIGN_JOB)
            elif not re.search(r"@\s*(\$\{\{[^}]*digest[^}]*\}\}|sha256:)", line):
                bad("COSIGN-IMAGE-BY-TAG",
                    "'cosign sign' reference carries no resolvable digest (%s)" % line,
                    SIGN_JOB)

    if not attest_steps:
        bad("PROVENANCE-ATTEST-MISSING",
            "job '%s' has no actions/attest-build-provenance step; no build "
            "provenance is attested" % SIGN_JOB, SIGN_JOB)
    else:
        if not any("subject-path" in w for w in attest_steps):
            bad("PROVENANCE-BINARY-MISSING",
                "no build-provenance attestation covers a released binary "
                "(no subject-path)", SIGN_JOB)
        if not any("subject-digest" in w for w in attest_steps):
            bad("PROVENANCE-IMAGE-MISSING",
                "no build-provenance attestation covers the container image "
                "(no subject-digest)", SIGN_JOB)

    # --- C. signing precedes publish ----------------------------------------
    pubs = publishers(jobs)
    if not pubs:
        # Without this the ordering check is vacuous: a workflow the detector
        # does not understand would silently satisfy "no publisher runs before
        # signing" while publishing on every tag.
        bad("NO-PUBLISHER-DETECTED",
            "no publishing step was recognised anywhere in the workflow; the "
            "signing-before-publish check would be vacuous")
    for name, why in pubs:
        if name == SIGN_JOB:
            continue
        if SIGN_JOB not in transitive_needs(jobs, name):
            bad("SIGN-AFTER-PUBLISH",
                "publishing job '%s' (%s) does not depend on '%s'; the artifact "
                "is publicly retrievable before any signature exists, and a "
                "later signing failure retracts nothing" % (name, why, SIGN_JOB),
                name)
        elif not hard_gated(jobs, name, SIGN_JOB):
            # The edge exists but does not gate. Asserting only the edge makes
            # this check satisfiable by an ordering hint: the publisher runs
            # after a FAILED or SKIPPED signing job and publishes anyway, which
            # is the exposure the edge was supposed to close.
            culprit = defeated_by(jobs, name, SIGN_JOB) or (name, "(unknown)")
            bad("SIGN-GATE-DEFEATED",
                "publishing job '%s' (%s) declares a needs-path to '%s', but "
                "job '%s' carries %s: it does not hold the pipeline when the "
                "signing job fails or is skipped, so the edge orders the jobs "
                "without gating them"
                % (name, why, SIGN_JOB, culprit[0], culprit[1]), name)
    return v


def render(violations, prefix=""):
    for code, _job, msg in violations:
        print("%sVIOLATION %s: %s" % (prefix, code, msg))


def admitted_lines(admitted, subject_key):
    """One line per admitted gap, naming the exact ledger key that carries it.

    Built as a list rather than printed in place so the self-test can assert
    that an admission is VISIBLE. An admitted gap that printed nothing would be
    indistinguishable from a gate that found nothing, which is the failure mode
    a switched-off gate has.
    """
    return ["ADMITTED %s (%s%s%s): %s" % (code, subject_key, SEPARATOR, job, msg)
            for code, job, msg in admitted]


def render_stale(stale, prefix=""):
    for f, job in stale:
        print("%sSTALE LEDGER ENTRY %s%s%s: this file+job no longer violates the "
              "signing-order invariant. DELETE the entry — a ledger that keeps "
              "entries it no longer needs stops shrinking on its own and becomes "
              "a permanent allow-list wearing a temporary label."
              % (prefix, f, SEPARATOR, job))


LEDGER_PATH = os.environ.get("SIGNING_ORDER_EXCEPTIONS", EXCEPTIONS_DEFAULT)
LEDGER_ENTRIES, LEDGER_ERRORS = load_ledger(LEDGER_PATH)
if LEDGER_ERRORS:
    print("NOT RUN: %s is not a ledger this probe understands. Refusing to judge the"
          % LEDGER_PATH, file=sys.stderr)
    print("         workflow on a ledger half of which was silently dropped: a skipped",
          file=sys.stderr)
    print("         line leaves a named gap unadmitted and the gate red with nothing on",
          file=sys.stderr)
    print("         screen connecting the two.", file=sys.stderr)
    for e in LEDGER_ERRORS:
        print("  %s" % e, file=sys.stderr)
    sys.exit(2)

if MODE_CHECK:
    key = ledger_key(MODE_CHECK)
    vs, adm, st = partition(analyze(MODE_CHECK), key, LEDGER_ENTRIES)
    render(vs)
    for line in admitted_lines(adm, key):
        print(line)
    render_stale(st)
    if not vs and not st:
        print("ok: %s satisfies every release-signing assertion%s"
              % (MODE_CHECK, " beyond the admitted gap(s) above" if adm else ""))
    sys.exit(1 if vs else (4 if st else 0))


# ---------------------------------------------------------------------------
# MUTATORS
#
# Every mutator receives a deep copy of the parsed workflow and returns it
# mutated. The committed file is opened read-only, once, and is never written.
# ---------------------------------------------------------------------------

def load_real():
    with open(WORKFLOW, "r", encoding="utf-8") as fh:
        return fh.read()


def build_repaired(text):
    """The GREEN control: the committed workflow, restructured so that the one
    publishing job runs only AFTER signing.

    Renaming ghcr-image -> ghcr-build is done on the TEXT so that the
    `${{ needs.ghcr-image.outputs.digest }}` expressions move with it; the
    remaining edits are structural.

    This is a control, not a remedy. Its only job is to prove the analyzer can
    return zero violations, so that the red legs below are not vacuous.
    """
    wf = yaml.safe_load(text.replace("ghcr-image", "ghcr-build"))
    jobs = wf["jobs"]
    build_uses = None
    for step in steps_of(jobs["ghcr-build"]):
        if uses_of(step).startswith("docker/build-push-action"):
            build_uses = uses_of(step)
            step["with"]["push"] = False
    jobs["ghcr-publish"] = {
        "runs-on": "ubuntu-latest",
        "needs": [SIGN_JOB],
        "permissions": {"contents": "read", "packages": "write"},
        "steps": [{
            "name": "push the already-signed image",
            "uses": build_uses,
            "with": {
                "context": ".",
                "push": True,
                "tags": "ghcr.io/${{ github.repository }}:${{ github.ref_name }}",
            },
        }],
    }
    jobs["release"]["needs"].append("ghcr-publish")
    return wf


def sign_job(wf):
    return wf["jobs"][SIGN_JOB]


def drop_step(wf, predicate):
    job = sign_job(wf)
    job["steps"] = [s for s in steps_of(job) if not predicate(s)]
    return wf


def m_drop_blob_sign(wf):
    return drop_step(wf, lambda s: "cosign sign-blob" in run_of(s))


def m_drop_image_sign(wf):
    return drop_step(
        wf,
        lambda s: bool(re.search(r"\bcosign\s+sign\b", run_of(s)))
        and "cosign sign-blob" not in run_of(s),
    )


def m_sign_by_tag(wf):
    for step in steps_of(sign_job(wf)):
        if re.search(r"\bcosign\s+sign\b", run_of(step)) and "sign-blob" not in run_of(step):
            step["run"] = re.sub(
                r"@\$\{\{\s*needs\.[\w-]+\.outputs\.digest\s*\}\}",
                ":${{ github.ref_name }}",
                step["run"],
            )
    return wf


def m_drop_sbom(wf):
    return drop_step(wf, lambda s: uses_of(s).startswith("anchore/"))


def m_drop_all_attest(wf):
    return drop_step(wf, lambda s: uses_of(s).startswith("actions/attest-build-provenance"))


def m_drop_image_attest(wf):
    return drop_step(
        wf,
        lambda s: uses_of(s).startswith("actions/attest-build-provenance")
        and "subject-digest" in (s.get("with") or {}),
    )


def m_drop_cosign_installer(wf):
    return drop_step(wf, lambda s: uses_of(s).startswith("sigstore/cosign-installer"))


def m_drop_sign_job(wf):
    del wf["jobs"][SIGN_JOB]
    return wf


def m_conditional_job(wf):
    sign_job(wf)["if"] = "${{ github.event_name == 'workflow_dispatch' }}"
    return wf


def m_continue_on_error_job(wf):
    sign_job(wf)["continue-on-error"] = True
    return wf


def m_continue_on_error_steps(wf):
    for step in steps_of(sign_job(wf)):
        if re.search(r"\bcosign\s+sign(-blob)?\b", run_of(step)):
            step["continue-on-error"] = True
    return wf


def m_needs_defeated_by_always(wf):
    wf["jobs"]["ghcr-publish"]["if"] = "${{ always() }}"
    return wf


def m_needs_routed_through_ignored_failure(wf):
    """Keep the needs-path, route it through a job whose failure is ignored.

    Nothing about the edge changes on a green run, which is the point: the
    publisher still declares a path back to the signing job, and still
    publishes when signing failed.
    """
    wf["jobs"]["publish-gate"] = {
        "runs-on": "ubuntu-latest",
        "needs": [SIGN_JOB],
        "continue-on-error": True,
        "steps": [{"name": "hold the publish until signing is done",
                   "run": "echo signed"}],
    }
    wf["jobs"]["ghcr-publish"]["needs"] = ["publish-gate"]
    return wf


def m_false_green_subject(wf):
    """The exact shape that made the analyzer print "every assertion holds".

    Nothing is deleted: the signing job, its cosign steps and the needs-edge
    from the publisher are all still in the file. The job may fail, the cosign
    steps may fail, and the publisher runs regardless — the pipeline signs
    nothing, reports success, and publishes anyway.
    """
    m_continue_on_error_job(wf)
    m_continue_on_error_steps(wf)
    return m_needs_defeated_by_always(wf)


def m_conditional_upstream(wf):
    wf["jobs"]["verify"]["if"] = "${{ github.event_name != 'push' }}"
    return wf


def m_no_tag_trigger(wf):
    key = True if True in wf else "on"
    wf[key] = {"pull_request": {"branches": ["main"]}}
    return wf


def m_drop_oidc_permission(wf):
    sign_job(wf)["permissions"].pop("id-token", None)
    return wf


def m_publish_before_sign(wf):
    wf["jobs"]["ghcr-publish"]["needs"] = ["ghcr-build"]
    return wf


def m_publish_before_sign_renamed(wf):
    job = wf["jobs"].pop("ghcr-publish")
    job["needs"] = ["ghcr-build"]
    wf["jobs"]["container-push"] = job
    wf["jobs"]["release"]["needs"] = [
        n if n != "ghcr-publish" else "container-push"
        for n in wf["jobs"]["release"]["needs"]
    ]
    return wf


def m_no_publisher(wf):
    for step in steps_of(wf["jobs"]["ghcr-publish"]):
        step["with"]["push"] = False
    rel = wf["jobs"]["release"]
    rel["steps"] = [s for s in steps_of(rel)
                    if not uses_of(s).startswith("softprops/action-gh-release")]
    return wf


def m_dangling_need(wf):
    sign_job(wf)["needs"].append("attest-and-notarise")
    return wf


def m_needs_cycle(wf):
    wf["jobs"]["image-scan"]["needs"].append("release")
    return wf


def m_comment_out_image_sign(wf):
    # The step, and the comment block explaining it, both stay. Only the call
    # is commented out. A substring match for "cosign sign" over the raw run
    # body would find the explanation and report the pipeline as fine.
    for step in steps_of(sign_job(wf)):
        body = run_of(step)
        if re.search(r"\bcosign\s+sign\b", body) and "sign-blob" not in body:
            step["run"] = "\n".join(
                ("# " + ln) if re.search(r"\bcosign\s+sign\b", ln) else ln
                for ln in body.splitlines()
            )
    return wf


# Each mutation declares:
#   expect — the violations that MUST be reported, as (CODE, [substrings that
#            must appear IN THAT violation's own message]). One entry per
#            expected violation: listing a code twice requires two violations
#            carrying it, each matching its own substrings.
#   also   — collateral codes this mutation legitimately produces as well.
#            Their messages are not pinned; their COUNT is not pinned either.
#
# Pinning the message per violation, and pinning how many violations carry each
# expected code, is what makes this a MESSAGE assertion rather than a count
# assertion. Two legs can share a code (SIGN-AFTER-PUBLISH below appears twice)
# and are then distinguishable only by the message. Any code outside
# (expect | also) fails the leg.
MUTATIONS = [
    ("drop the cosign sign-blob step",
     m_drop_blob_sign,
     [("COSIGN-BLOB-MISSING", ["never runs 'cosign sign-blob'"])], []),
    ("drop the cosign image-sign step",
     m_drop_image_sign,
     [("COSIGN-IMAGE-SIGN-MISSING",
       ["never runs 'cosign sign' on the container image"])], []),
    ("comment out the cosign image-sign call, keeping its comment block",
     m_comment_out_image_sign,
     [("COSIGN-IMAGE-SIGN-MISSING",
       ["never runs 'cosign sign' on the container image"])], []),
    ("sign the image by mutable tag instead of by digest",
     m_sign_by_tag,
     [("COSIGN-IMAGE-BY-TAG",
       ["mutable tag, not a digest", "github.ref_name"])], []),
    ("drop the SBOM generation step",
     m_drop_sbom,
     [("SBOM-STEP-MISSING", ["no SBOM generation step"])], []),
    ("drop every build-provenance attestation",
     m_drop_all_attest,
     [("PROVENANCE-ATTEST-MISSING",
       ["no actions/attest-build-provenance step"])], []),
    ("drop only the image build-provenance attestation",
     m_drop_image_attest,
     [("PROVENANCE-IMAGE-MISSING", ["no subject-digest"])], []),
    ("drop the cosign installer",
     m_drop_cosign_installer,
     [("COSIGN-INSTALL-MISSING", ["never installs cosign"])], []),
    ("delete the sbom-and-sign job entirely",
     m_drop_sign_job,
     [("SBOM-SIGN-JOB-MISSING", ["job 'sbom-and-sign' is absent"])],
     ["NEEDS-UNKNOWN-JOB", "OIDC-PERMISSION-MISSING",
      "ATTESTATION-PERMISSION-MISSING", "COSIGN-INSTALL-MISSING",
      "SBOM-STEP-MISSING", "COSIGN-BLOB-MISSING",
      "COSIGN-IMAGE-SIGN-MISSING", "PROVENANCE-ATTEST-MISSING",
      "SIGN-AFTER-PUBLISH"]),
    ("gate the signing job behind an if: that skips on a tag push",
     m_conditional_job,
     [("SBOM-SIGN-CONDITIONAL", ["carries an if:", "workflow_dispatch"])], []),
    ("mark the signing job continue-on-error: true",
     m_continue_on_error_job,
     [("SBOM-SIGN-CONTINUE-ON-ERROR",
       ["job 'sbom-and-sign' carries continue-on-error: true",
        "recorded as success"])], []),
    ("mark the two cosign signing steps continue-on-error: true",
     m_continue_on_error_steps,
     [("SBOM-SIGN-CONTINUE-ON-ERROR",
       ["step 'cosign keyless sign", "binaries and sha256sums",
        "carries continue-on-error: true"]),
      ("SBOM-SIGN-CONTINUE-ON-ERROR",
       ["step 'cosign keyless sign", "GHCR image by digest",
        "carries continue-on-error: true"])], []),
    ("let the publisher run on always(), defeating its needs-edge",
     m_needs_defeated_by_always,
     [("SIGN-GATE-DEFEATED",
       ["publishing job 'ghcr-publish'", "always()",
        "orders the jobs without gating them"])], []),
    ("route the publisher's needs-path through a continue-on-error job",
     m_needs_routed_through_ignored_failure,
     [("SIGN-GATE-DEFEATED",
       ["publishing job 'ghcr-publish'",
        "job 'publish-gate' carries continue-on-error: true",
        "orders the jobs without gating them"])], []),
    ("the full false-green subject: continue-on-error plus an always() publisher",
     m_false_green_subject,
     [("SBOM-SIGN-CONTINUE-ON-ERROR",
       ["job 'sbom-and-sign' carries continue-on-error: true"]),
      ("SBOM-SIGN-CONTINUE-ON-ERROR",
       ["step 'cosign keyless sign", "binaries and sha256sums"]),
      ("SBOM-SIGN-CONTINUE-ON-ERROR",
       ["step 'cosign keyless sign", "GHCR image by digest"]),
      ("SIGN-GATE-DEFEATED",
       ["publishing job 'ghcr-publish'", "always()"])], []),
    ("gate an upstream job behind an if: so signing skips with it",
     m_conditional_upstream,
     [("SBOM-SIGN-UPSTREAM-CONDITIONAL", ["depends on 'verify'"])], []),
    ("remove the push-tag trigger",
     m_no_tag_trigger,
     [("TAG-TRIGGER-MISSING", ["does not trigger on push tags"])], []),
    ("remove id-token: write from the signing job",
     m_drop_oidc_permission,
     [("OIDC-PERMISSION-MISSING", ["does not grant id-token: write"])], []),
    ("reorder needs so the image publishes before it is signed",
     m_publish_before_sign,
     [("SIGN-AFTER-PUBLISH",
       ["publishing job 'ghcr-publish'", "push: true"])], []),
    ("rename the publishing job and publish before signing",
     m_publish_before_sign_renamed,
     [("SIGN-AFTER-PUBLISH", ["publishing job 'container-push'"])], []),
    ("remove every publishing step (vacuity guard)",
     m_no_publisher,
     [("NO-PUBLISHER-DETECTED", ["would be vacuous"])], []),
    ("point a need at a job that does not exist",
     m_dangling_need,
     [("NEEDS-UNKNOWN-JOB", ["needs 'attest-and-notarise'"])], []),
    ("introduce a needs cycle through the signing job",
     m_needs_cycle,
     [("NEEDS-CYCLE", ["transitively needs itself"])], []),
]


def leg_problems(got, expect):
    """Scope each expected substring to the violation that must carry it.

    Matching the expected substrings against a JOIN of every reported message
    is the same false-green class this file probes the analyzer for: a phrase
    that has drifted into a COLLATERAL violation's message satisfies the join,
    so a leg whose OWN violation says something else — or nothing — still
    passes. Each expected violation is therefore matched against one reported
    violation carrying its code, and the number of violations carrying an
    expected code must equal the number expected, so that a superset which
    also accuses a correctly gated job fails instead of passing.
    """
    problems = []
    by_code = {}
    for code, _job, msg in got:
        by_code.setdefault(code, []).append(msg)
    wanted = {}
    for code, subs in expect:
        wanted.setdefault(code, []).append(subs)
    for code in sorted(wanted):
        msgs = by_code.get(code, [])
        subs_list = wanted[code]
        if len(msgs) != len(subs_list):
            problems.append(
                "%s: expected %d violation(s) with this code, analyzer reported "
                "%d%s" % (code, len(subs_list), len(msgs),
                          "".join("\n         reported: %s" % m for m in msgs)))
            continue
        if any(all(all(s in msgs[order[i]] for s in subs_list[i])
                   for i in range(len(subs_list)))
               for order in itertools.permutations(range(len(msgs)))):
            continue
        before = len(problems)
        for subs in subs_list:
            if not any(all(s in m for s in subs) for m in msgs):
                problems.append(
                    "%s: no violation carrying this code says %s"
                    "\n         reported: %s"
                    % (code, "; ".join(repr(s) for s in subs), " | ".join(msgs)))
        if len(problems) == before:
            problems.append(
                "%s: the expected messages cannot be matched one-to-one against "
                "the reported ones\n         reported: %s"
                % (code, " | ".join(msgs)))
    return problems


work = tempfile.mkdtemp(prefix="release-signing-redprobe.")


def cleanup():
    if KEEP:
        print("kept: %s" % work)
    else:
        shutil.rmtree(work, ignore_errors=True)


def dump(wf, name):
    path = os.path.join(work, name)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(wf, fh, sort_keys=False, width=4096)
    return path


if REF:
    # Read the subject from a named revision rather than the checkout, so the
    # verdict is attributable to a commit. A probe that silently judged an
    # edited working tree would report on something no reviewer ever sees.
    proc = subprocess.run(["git", "-C", REPO_ROOT, "show", "%s:%s" % (REF, WORKFLOW_REL)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print("NOT RUN: cannot read %s:%s — %s"
              % (REF, WORKFLOW_REL, proc.stderr.strip()), file=sys.stderr)
        sys.exit(2)
    real_text = proc.stdout
    SUBJECT = "%s:%s" % (REF, WORKFLOW_REL)
    WORKFLOW = os.path.join(tempfile.mkdtemp(prefix="release-signing-subject."),
                            "release.yml")
    with open(WORKFLOW, "w", encoding="utf-8") as fh:
        fh.write(real_text)
else:
    real_text = load_real()
    SUBJECT = "%s (working tree)" % WORKFLOW_REL

# The ledger names a workflow's identity IN THE REPOSITORY, never wherever the
# copy under test happens to sit. Under --ref the subject is a temp extraction
# of the same file, and an entry must go on matching it.
SUBJECT_KEY = WORKFLOW_REL

fail = 0
print("release-signing red-probe — subject: %s" % SUBJECT)

# State the trigger set as measured evidence, not as an assumption. It is the
# reason this gate is not, and must not become, a required PR context.
_trig = triggers_of(yaml.safe_load(real_text)) or {}
_events = sorted(str(k) for k in _trig) if isinstance(_trig, dict) else [str(_trig)]
print("     triggers: %s" % ", ".join(_events))
if "pull_request" not in _events:
    print("     no pull_request trigger, so '%s' can never run on a PR: marking it a "
          "required PR context would make it eternally green, because GitHub counts "
          "a skipped required check as passed." % SIGN_JOB)
# Name the ledger in force before any verdict, so a reader never has to guess
# which admissions this run was working under.
print("     ledger:   %s%s"
      % (LEDGER_PATH,
         (" — %d entr%s" % (len(LEDGER_ENTRIES), "y" if len(LEDGER_ENTRIES) == 1 else "ies"))
         if LEDGER_ENTRIES else " — no admitted gaps"))
print()

# --- GREEN control -----------------------------------------------------------
repaired = build_repaired(real_text)
green_path = dump(copy.deepcopy(repaired), "00-repaired-baseline.yml")
green = analyze(green_path)
if green:
    print("FAIL green control: the repaired baseline still reports violations, so the")
    print("     analyzer may be a constant-RED stub and every red leg below is vacuous.")
    render(green, prefix="     ")
    fail = 1
else:
    print("ok   green control: the repaired baseline reports zero violations")

# --- RED legs ----------------------------------------------------------------
for idx, (label, mutate, expect, also) in enumerate(MUTATIONS, start=1):
    mutated = mutate(copy.deepcopy(repaired))
    path = dump(mutated, "%02d-%s.yml" % (idx, re.sub(r"[^a-z0-9]+", "-", label.lower())[:40]))
    got = analyze(path)
    codes = {c for c, _, _ in got}
    expect_codes = []
    for code, _ in expect:
        if code not in expect_codes:
            expect_codes.append(code)
    missing = [c for c in expect_codes if c not in codes]
    unexpected = sorted(codes - set(expect_codes) - set(also))
    if missing:
        print("FAIL red leg %02d (%s): expected %s, analyzer reported %s"
              % (idx, label, ", ".join(missing), ", ".join(sorted(codes)) or "nothing"))
        print("     The property is unguarded: the pipeline could ship this and the "
              "analyzer would call it fine.")
        fail = 1
    elif unexpected:
        print("FAIL red leg %02d (%s): reddened, but ALSO on %s"
              % (idx, label, ", ".join(unexpected)))
        print("     A violation raised for an unintended reason would let a count-only "
              "self-test pass while the real property went unchecked.")
        fail = 1
    else:
        problems = leg_problems(got, expect)
        if problems:
            print("FAIL red leg %02d (%s): the right code, the wrong violation"
                  % (idx, label))
            for p in problems:
                print("     %s" % p)
            print("     The code alone does not say WHAT reddened, and a substring found "
                  "in SOME other violation's message says nothing about this one.")
            fail = 1
        else:
            tally = ", ".join(
                "%s%s" % (c, "" if n == 1 else " x%d" % n)
                for c, n in ((c, sum(1 for e, _ in expect if e == c))
                             for c in expect_codes))
            print("ok   red leg %02d: %-62s -> %s" % (idx, label, tally))

print()

# --- LEDGER legs -------------------------------------------------------------
#
# The ledger is a suppression mechanism, so it is probed exactly as the analyzer
# is: nothing about it is taken on the word of the run that uses it. The legs
# pin the SPLIT — which violations were reported, which were admitted, which
# entries went stale — as (CODE, job) pairs, not as counts, because "one
# violation reported" is satisfied equally by admitting the right gap and by
# admitting the wrong one.
#
# Two traps these legs are shaped to avoid:
#
#   * An over-broadness leg that asserts only "the other job is still reported"
#     passes VACUOUSLY while the key parser is broken: an unrecognised entry
#     suppresses nothing, so both violations are reported and the leg sees the
#     red it expected, for the wrong reason. Every leg below therefore also pins
#     the ADMITTED set, which is empty whenever the entry was not understood.
#   * The subject key is passed in explicitly rather than derived from the temp
#     file each fixture is dumped to, so a leg states which workflow identity it
#     is reasoning about instead of depending on where the fixture landed.

committed = yaml.safe_load(real_text)
ADMITTED_ENTRY = "%s%s%s" % (WORKFLOW_REL, SEPARATOR, "ghcr-image")
_ledger_idx = 0


def with_second_publisher(wf):
    """release.yml plus a second publishing job, of the kind a file-keyed entry
    would have silently swallowed on the day someone added it."""
    wf = copy.deepcopy(wf)
    wf["jobs"]["ghcr-image-arm64"] = copy.deepcopy(wf["jobs"]["ghcr-image"])
    return wf


def without_tag_trigger(wf):
    wf = copy.deepcopy(wf)
    wf.pop(True if True in wf else "on", None)
    wf["on"] = {"workflow_dispatch": None}
    return wf


def ledger_leg(label, wf, lines, want_reported, want_admitted, want_stale,
               want_errors=0, want_printed=(), subject_key=None):
    """One ledger leg: build a ledger, split one subject with it, pin the split.

    want_reported / want_admitted are (CODE, job) pairs; a violation with no job
    is spelled (CODE, None) and can never be admitted.
    """
    global fail, _ledger_idx
    _ledger_idx += 1
    key = subject_key or WORKFLOW_REL
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower())[:40]
    path = dump(wf, "L%02d-%s.yml" % (_ledger_idx, slug))
    lpath = os.path.join(work, "L%02d-%s.ledger" % (_ledger_idx, slug))
    with open(lpath, "w", encoding="utf-8") as fh:
        fh.write("".join(ln + "\n" for ln in lines))
    entries, errors = load_ledger(lpath)
    reported, admitted, stale = partition(analyze(path), key, entries)
    printed = admitted_lines(admitted, key)

    problems = []
    if len(errors) != want_errors:
        problems.append("parser raised %d malformed-entry error(s), expected %d%s"
                        % (len(errors), want_errors,
                           "".join("\n         %s" % e for e in errors)))
    for what, got, want in (
            ("reported", sorted((c, j or "") for c, j, _ in reported), sorted(want_reported)),
            ("admitted", sorted((c, j or "") for c, j, _ in admitted), sorted(want_admitted)),
            ("stale", sorted(stale), sorted(want_stale))):
        want = [(a, b or "") for a, b in want]
        if got != want:
            problems.append("%s %s, expected %s" % (what, got, want))
    if want_printed and not any(all(s in line for s in want_printed) for line in printed):
        problems.append("no printed admission line says %s\n         printed: %s"
                        % ("; ".join(repr(s) for s in want_printed),
                           " | ".join(printed) or "nothing"))

    if problems:
        print("FAIL ledger leg %02d (%s)" % (_ledger_idx, label))
        for p in problems:
            print("     %s" % p)
        fail = 1
    else:
        print("ok   ledger leg %02d: %s" % (_ledger_idx, label))


ledger_leg(
    "the named file+job is admitted, and the admission is printed",
    committed, [ADMITTED_ENTRY],
    want_reported=[],
    want_admitted=[("SIGN-AFTER-PUBLISH", "ghcr-image")],
    want_stale=[],
    want_printed=("SIGN-AFTER-PUBLISH", ADMITTED_ENTRY, "does not depend on"))

ledger_leg(
    "with the ledger emptied the same finding comes back (not a blanket)",
    committed, [],
    want_reported=[("SIGN-AFTER-PUBLISH", "ghcr-image")],
    want_admitted=[], want_stale=[])

ledger_leg(
    "a second publishing job in the same file is still reported",
    with_second_publisher(committed), [ADMITTED_ENTRY],
    want_reported=[("SIGN-AFTER-PUBLISH", "ghcr-image-arm64")],
    want_admitted=[("SIGN-AFTER-PUBLISH", "ghcr-image")],
    want_stale=[])

ledger_leg(
    "an entry naming a different job admits nothing, and is itself stale",
    committed, ["%s%s%s" % (WORKFLOW_REL, SEPARATOR, "image-scan")],
    want_reported=[("SIGN-AFTER-PUBLISH", "ghcr-image")],
    want_admitted=[],
    want_stale=[(WORKFLOW_REL, "image-scan")])

ledger_leg(
    # Deliberately paired with a WORKING entry for the other job. Asserting only
    # "the foreign entry admitted nothing" would pass just as well against a
    # parser that understood no entry at all; requiring the second entry to
    # admit proves the mechanism was running while the foreign one was ignored.
    "an entry naming a different file admits nothing here",
    with_second_publisher(committed),
    [".github/workflows/security.yml%sghcr-image" % SEPARATOR,
     "%s%sghcr-image-arm64" % (WORKFLOW_REL, SEPARATOR)],
    want_reported=[("SIGN-AFTER-PUBLISH", "ghcr-image")],
    want_admitted=[("SIGN-AFTER-PUBLISH", "ghcr-image-arm64")],
    want_stale=[])

ledger_leg(
    "an entry whose file+job no longer violates is refused as stale",
    copy.deepcopy(repaired), [ADMITTED_ENTRY],
    want_reported=[], want_admitted=[],
    want_stale=[(WORKFLOW_REL, "ghcr-image")])

ledger_leg(
    "a malformed entry is refused loudly, never skipped or read generously",
    committed,
    # A bare path is the format the reference implementation used, and is
    # refused here rather than read as "the whole file": that generous reading
    # is exactly the blanket this key exists to prevent.
    [WORKFLOW_REL,
     "%sghcr-image" % SEPARATOR,
     "%s%sghcr-image%sextra" % (WORKFLOW_REL, SEPARATOR, SEPARATOR),
     "%s%s" % (WORKFLOW_REL, SEPARATOR),
     ".github/workflows/no-such-workflow.yml%sghcr-image" % SEPARATOR],
    want_reported=[("SIGN-AFTER-PUBLISH", "ghcr-image")],
    want_admitted=[], want_stale=[], want_errors=5)

ledger_leg(
    "a violation with no job to name cannot be admitted by any entry",
    without_tag_trigger(committed), [ADMITTED_ENTRY],
    want_reported=[("TAG-TRIGGER-MISSING", None)],
    want_admitted=[("SIGN-AFTER-PUBLISH", "ghcr-image")],
    want_stale=[])

print()

# --- the committed file ------------------------------------------------------
real, admitted, stale = partition(analyze(WORKFLOW), SUBJECT_KEY, LEDGER_ENTRIES)
if admitted:
    print("ADMITTED committed workflow: %d known gap%s named in %s."
          % (len(admitted), "" if len(admitted) == 1 else "s", LEDGER_PATH))
    print("     Named, not switched off: each entry carries the condition that deletes")
    print("     it, and this probe fails the moment an entry outlives its violation.")
    for line in admitted_lines(admitted, SUBJECT_KEY):
        print("     %s" % line)
if stale:
    print("STALE ledger: %d entr%s no longer carr%s a violation."
          % (len(stale), "y" if len(stale) == 1 else "ies",
             "ies" if len(stale) == 1 else "y"))
    render_stale(stale, prefix="     ")
if real:
    print("FINDING committed workflow: %d violation(s) — the analyzer is proven "
          "two-sided above, so these are real." % len(real))
    render(real, prefix="     ")
elif admitted:
    print("ok   committed workflow: no violation beyond the admitted gap%s above"
          % ("" if len(admitted) == 1 else "s"))
else:
    print("ok   committed workflow: every release-signing assertion holds")

print()
_proven = ("Analyzer and ledger proven two-sided (1 green control, %d red legs, %d "
           "ledger legs, each pinned to its own message/split)."
           % (len(MUTATIONS), _ledger_idx))
if fail:
    print("PROBE INTEGRITY FAILURE — the analyzer or its ledger is not two-sided; the")
    print("verdict on the committed workflow means nothing until the failures above are")
    print("resolved.")
    cleanup()
    sys.exit(1)
if real:
    print(_proven)
    print("The committed release pipeline carries the violation(s) listed above.")
    cleanup()
    sys.exit(3)
if stale:
    print(_proven)
    print("The pipeline is fine; the ledger is not. Delete the stale entr%s above — a"
          % ("y" if len(stale) == 1 else "ies"))
    print("ledger that keeps entries it no longer needs stops shrinking and becomes a")
    print("permanent allow-list.")
    cleanup()
    sys.exit(4)
print(_proven)
if admitted:
    print("The committed release pipeline carries no violation beyond the %d admitted "
          "gap%s printed above." % (len(admitted), "" if len(admitted) == 1 else "s"))
else:
    print("The committed release pipeline is clean.")
cleanup()
sys.exit(0)
PYEOF
