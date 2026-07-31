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
# The analyzer reports this as SIGN-AFTER-PUBLISH, and the committed file
# therefore exits 3 (see EXIT CODES).
#
# EXIT CODES
#   0  the analyzer is proven two-sided AND the committed workflow is clean
#   1  PROBE INTEGRITY FAILURE — a mutation failed to redden, reddened with the
#      wrong message, or the green control did not come back clean. Nothing the
#      analyzer says about the committed workflow can be trusted in this state.
#   2  the probe could not run (missing python3 / PyYAML / workflow file)
#   3  the analyzer is sound, and the COMMITTED workflow carries a violation
#      (today: SIGN-AFTER-PUBLISH). Non-zero on purpose: a live finding must
#      never read as green, and it is reported separately from exit 1 so a
#      broken probe is never mistaken for a broken pipeline.
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
# Not wired into `make check`: it needs python3 + PyYAML, and its exit-3 state
# is an owner decision, not a developer's pre-push chore.
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
# ANALYZER
#
# Returns a list of (CODE, message). CODE is the pinned fragment the red-probe
# asserts on; the message carries the evidence a human needs.
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

    def bad(code, msg):
        v.append((code, msg))

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
            "job '%s' is absent from the workflow; nothing signs a release" % SIGN_JOB)
        job = {}
    else:
        job = jobs[SIGN_JOB] or {}

    for name, j in jobs.items():
        j = j or {}
        for dep in needs_of(j):
            if dep not in jobs:
                bad("NEEDS-UNKNOWN-JOB",
                    "job '%s' needs '%s', which is not defined; the graph never "
                    "runs" % (name, dep))
    if SIGN_JOB in jobs and SIGN_JOB in transitive_needs(jobs, SIGN_JOB):
        bad("NEEDS-CYCLE",
            "job '%s' transitively needs itself; the graph is unrunnable" % SIGN_JOB)

    if "if" in job:
        bad("SBOM-SIGN-CONDITIONAL",
            "job '%s' carries an if: (%s); a skipped job reports success and "
            "signs nothing" % (SIGN_JOB, job.get("if")))
    # continue-on-error is the same class as if: and just as invisible in a
    # green run — the difference is that the job DOES run, fails, and is then
    # recorded as successful. Every downstream needs-edge is satisfied by a job
    # that signed nothing, and the pipeline publishes with a green tick.
    if continue_on_error_set(job):
        bad("SBOM-SIGN-CONTINUE-ON-ERROR",
            "job '%s' carries continue-on-error: %s; the job's failure is "
            "recorded as success, so every downstream needs-edge is satisfied "
            "by a run that signed nothing"
            % (SIGN_JOB, show(job.get("continue-on-error"))))
    for step in steps_of(job):
        if is_signing_step(step) and continue_on_error_set(step):
            bad("SBOM-SIGN-CONTINUE-ON-ERROR",
                "step '%s' in job '%s' carries continue-on-error: %s; the "
                "signing step can fail while the job still reports success"
                % (step.get("name") or uses_of(step) or "<unnamed>", SIGN_JOB,
                   show(step.get("continue-on-error"))))
    for dep in sorted(transitive_needs(jobs, SIGN_JOB)):
        if "if" in (jobs.get(dep) or {}):
            bad("SBOM-SIGN-UPSTREAM-CONDITIONAL",
                "'%s' depends on '%s', which carries an if:; when the upstream "
                "skips, the signing job skips with it" % (SIGN_JOB, dep))

    perms = job.get("permissions") or {}
    if str(perms.get("id-token", "")).strip().lower() != "write":
        bad("OIDC-PERMISSION-MISSING",
            "job '%s' does not grant id-token: write; cosign keyless signing "
            "cannot obtain an OIDC token" % SIGN_JOB)
    if str(perms.get("attestations", "")).strip().lower() != "write":
        bad("ATTESTATION-PERMISSION-MISSING",
            "job '%s' does not grant attestations: write; build provenance "
            "cannot be recorded" % SIGN_JOB)

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
            "job '%s' never installs cosign; no step can sign" % SIGN_JOB)
    if not has_sbom:
        bad("SBOM-STEP-MISSING",
            "job '%s' has no SBOM generation step; the release ships without a "
            "bill of materials" % SIGN_JOB)
    if not has_blob_sign:
        bad("COSIGN-BLOB-MISSING",
            "job '%s' never runs 'cosign sign-blob'; the released binaries are "
            "unsigned" % SIGN_JOB)

    if not image_sign_refs:
        bad("COSIGN-IMAGE-SIGN-MISSING",
            "job '%s' never runs 'cosign sign' on the container image; the "
            "published image is unsigned" % SIGN_JOB)
    else:
        for line in image_sign_refs:
            # Signing by digest is the property under test. A mutable tag can be
            # repointed after signing, so a tag signature attests to whatever the
            # tag happens to resolve to at verification time.
            if "@" not in line:
                bad("COSIGN-IMAGE-BY-TAG",
                    "'cosign sign' targets a mutable tag, not a digest (%s); the "
                    "tag can be repointed after signing" % line)
            elif not re.search(r"@\s*(\$\{\{[^}]*digest[^}]*\}\}|sha256:)", line):
                bad("COSIGN-IMAGE-BY-TAG",
                    "'cosign sign' reference carries no resolvable digest (%s)" % line)

    if not attest_steps:
        bad("PROVENANCE-ATTEST-MISSING",
            "job '%s' has no actions/attest-build-provenance step; no build "
            "provenance is attested" % SIGN_JOB)
    else:
        if not any("subject-path" in w for w in attest_steps):
            bad("PROVENANCE-BINARY-MISSING",
                "no build-provenance attestation covers a released binary "
                "(no subject-path)")
        if not any("subject-digest" in w for w in attest_steps):
            bad("PROVENANCE-IMAGE-MISSING",
                "no build-provenance attestation covers the container image "
                "(no subject-digest)")

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
                "later signing failure retracts nothing" % (name, why, SIGN_JOB))
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
                % (name, why, SIGN_JOB, culprit[0], culprit[1]))
    return v


def render(violations, prefix=""):
    for code, msg in violations:
        print("%sVIOLATION %s: %s" % (prefix, code, msg))


if MODE_CHECK:
    vs = analyze(MODE_CHECK)
    render(vs)
    if not vs:
        print("ok: %s satisfies every release-signing assertion" % MODE_CHECK)
    sys.exit(1 if vs else 0)


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
    for code, msg in got:
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
    codes = {c for c, _ in got}
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

# --- the committed file ------------------------------------------------------
real = analyze(WORKFLOW)
if not real:
    print("ok   committed workflow: every release-signing assertion holds")
else:
    print("FINDING committed workflow: %d violation(s) — the analyzer is proven "
          "two-sided above, so these are real." % len(real))
    render(real, prefix="     ")

print()
if fail:
    print("PROBE INTEGRITY FAILURE — the analyzer is not two-sided; its verdict on the")
    print("committed workflow means nothing until the failures above are resolved.")
    cleanup()
    sys.exit(1)
if real:
    print("Analyzer proven two-sided (1 green control, %d red legs, each pinned to its "
          "own message)." % len(MUTATIONS))
    print("The committed release pipeline carries the violation(s) listed above.")
    cleanup()
    sys.exit(3)
print("Analyzer proven two-sided and the committed release pipeline is clean.")
cleanup()
sys.exit(0)
PYEOF
