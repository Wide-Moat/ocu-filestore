#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Config-drift guard for the storage credential custody flags (ADR-0013/0019,
# roadmap B1).
#
# The engine verifies the injected Storage-JWT only when -verify-storage-jwt is
# passed, and the flag defaults to FALSE. A deployment that omits it runs with
# custody verification OFF while every test and every code path that has the
# flag set keeps passing -- the failure is invisible from inside the binary,
# because the binary is doing exactly what it was told.
#
# That is the shape this gate exists for: a security control whose absence looks
# identical to its presence unless something reads the manifest. It asserts that
# every SHIPPED deployment manifest passes the custody flags with a verifying
# configuration, and it fails closed when it can find no manifest to read -- an
# empty scan and a clean scan are the same green otherwise.
#
# Test-only manifests are excluded BY NAME, not by pattern, so a new production
# manifest cannot join the exclusion by being named to resemble one.
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(ROOT, "deploy")

# Manifests that legitimately run without custody verification, each with the
# reason. An entry here is a deliberate exemption an operator can audit; a
# manifest absent from both this set and the scan is a bug in the scan.
EXEMPT = {
    # Drives the s3/minio conformance suite against a bare engine; it has no
    # Control plane to mint a Storage-JWT and no JWKS to verify one against.
    "docker-compose.test.yml": "conformance rig: no Control plane, no JWKS",
    # The integration rig stands up the engine alone for the component-IT suite,
    # same reason.
    "docker-compose.it.yml": "component-IT rig: no Control plane, no JWKS",
}

# The flags a verifying deployment must pass. -claims-bind is deliberately NOT
# here: it is the unverified predecessor seam, and requiring it would bless a
# configuration that binds a scope from an unverified bearer.
REQUIRED = [
    "-verify-storage-jwt",
    "-storage-jwks-path",
    "-storage-jwt-issuer",
    "-storage-jwt-audience",
]


def fail(msg):
    print(f"::error::custody-flags: {msg}", file=sys.stderr)
    sys.exit(1)


def note(msg):
    print(f"::notice::custody-flags: {msg}")


def manifests():
    if not os.path.isdir(DEPLOY):
        fail(f"{DEPLOY} does not exist; this gate cannot read the shipped manifests")
    found = sorted(f for f in os.listdir(DEPLOY) if f.startswith("docker-compose") and f.endswith(".yml"))
    if not found:
        fail("no docker-compose*.yml found under deploy/; an empty scan reports the "
             "same green as a clean one, so this is a failure rather than a pass")
    return found


# KNOWN_UNVERIFIED records manifests that do NOT yet pass the custody flags and
# the reason, so the gate ships ENFORCING without blocking on a gap it did not
# create. A manifest listed here is reported, not silently accepted, and the
# gate fails if one of them starts passing -- because then the record is stale
# and the next reader would trust a note that no longer describes the tree.
#
# This is not an exemption. An exempt manifest is one with no custody obligation;
# these have the obligation and do not meet it, which is exactly what roadmap B1
# says and what a green scan must not be able to hide.
KNOWN_UNVERIFIED = {
    "docker-compose.yml": "PENDING the deployment JWKS mount + iss/aud (roadmap B1)",
    "docker-compose.fleet.yml": "PENDING the deployment JWKS mount + iss/aud (roadmap B1)",
}


def main():
    checked = 0
    problems = []
    stale = []

    for name in manifests():
        if name in EXEMPT:
            note(f"{name}: exempt ({EXEMPT[name]})")
            continue
        path = os.path.join(DEPLOY, name)
        with open(path, encoding="utf-8") as f:
            body = f.read()

        # The engine service is the one that carries -engine; a manifest without
        # it defines no filestore and has no custody obligation.
        if "-engine" not in body:
            note(f"{name}: no engine service, nothing to check")
            continue

        checked += 1
        missing = [flag for flag in REQUIRED if flag not in body]
        if name in KNOWN_UNVERIFIED:
            if missing:
                note(f"{name}: KNOWN GAP, custody verification not wired "
                     f"({KNOWN_UNVERIFIED[name]}); missing {missing}")
            else:
                stale.append(name)
            continue
        if missing:
            problems.append(f"{name} omits {missing}")

    if checked == 0:
        fail("every manifest was exempt or engine-less, so nothing was actually "
             "checked; the exemption set has swallowed the scan")

    if stale:
        for name in stale:
            print(f"::error::custody-flags: {name} now passes the custody flags but is "
                  f"still listed as a known gap; drop its KNOWN_UNVERIFIED entry so the "
                  f"gate enforces it from here on", file=sys.stderr)
        fail("a known-gap record is stale")

    if problems:
        for p in problems:
            print(f"::error::custody-flags: {p}", file=sys.stderr)
        fail("a shipped manifest runs the engine without Storage-JWT verification. "
             "The flag defaults to false, so such a deployment accepts an unverified "
             "bearer and no test inside the binary can see it (ADR-0013/0019).")

    verified = checked - len(KNOWN_UNVERIFIED)
    note(f"{checked} manifest(s) scanned; {verified} verifying, "
         f"{len(KNOWN_UNVERIFIED)} recorded as a known gap")


if __name__ == "__main__":
    main()
