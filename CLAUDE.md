# Project Instructions — ocu-filestore

This repository is the **implementation** of the Open Computer Use storage
broker (component-04). The **architecture and specifications** are the source
of truth and live in `Wide-Moat/open-computer-use` under `docs/architecture/`.
Do not re-decide here what an ADR already decided; if a decision must change,
it changes in the architecture repo first.

This repo is **public**.

## Read before implementing

- `docs/architecture/components/04-object-store-service.md` — purpose, the one
  storage door reached by two callers, the invariants, failure modes
  (P4-mount STRIDE rows).
- `docs/architecture/adr/0010-storage-backend-pluggable-adapter.md` — engine
  seam (local-volume + S3 from day one).
- `docs/architecture/adr/0011-storage-egress-lane.md` — a network engine's
  backend leg transits the storage-dedicated lane; the bypass dial is refused.
- `contracts/storage/mount-config.schema.json`, `file-ops.schema.json`,
  `file-artifact-api.schema.json` — the frozen wire surface. Operation names,
  authorization axes, and the response envelope are pinned; per-operation
  bodies marked TBD stay TBD until the contract pins them — never invent a
  body here and code against it.
- NFR rows (in `manifesto/02-nfrs.md`): SEC-16, SEC-25, SEC-43, SEC-46,
  SEC-49, SEC-51, SEC-54, SEC-60, SEC-73, SEC-76, SEC-78 — SEC-85.

## Load-bearing rules

- One backend credential, one client: no second component speaks the
  object-store protocol (NFR-SEC-25); no direct backend dial bypassing the
  storage lane (NFR-SEC-16, network engine only).
- Three-axis authorization re-derived broker-side per request, deny-by-default;
  `downloadable` resolves at read, never stamped at write (NFR-SEC-73).
- Every file activity on either caller leg emits an OCSF File System Activity
  event committed to a local durable record before the operation is
  acknowledged (NFR-SEC-79).
- The embed-token verify, first-party session, CSRF, and CSP live in the Web UI
  (component-08), which authenticates the external data-plane client and mints
  the session; no OCU upstream secret crosses to the browser (NFR-SEC-82). This
  service is the backend storage door the Web UI reaches over the F9 host leg
  after that authentication — it mints no session and verifies no embed token.
- Ephemeral workspace: the service never takes on durable retention of customer
  bytes; long-term retention belongs to the customer's store.
- Two callers, one door: the in-guest mount client reaches the service over the
  egress hop (guest leg) and the Web UI reaches it over the F9 host leg. The
  mount path builds first; the durable `file_id`→handle store for the Web UI's
  Files-API surface is owned here (ADR-0023). The client SPA and preview-render
  are component-08's, not this service's.

## Writing discipline

- State facts in this project's own words. Specs, ADRs, and the frozen wire
  contracts are the only citable sources for behaviour; committed files never
  quote or name third-party material.
- All code, comments, commit messages, PR titles and descriptions, and docs
  are **English only**. No exceptions.

## License headers

Every new source file starts with:

```
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
```

(comment syntax per language). LICENSE = FSL-1.1-Apache-2.0; converts to
Apache-2.0 two years after each release. `LICENSE-APACHE` / `LICENSE-MIT` are
dependency reference texts, not ours.

## Git

- Identity: `developer@widemoat.ai`. Verify before committing.
- Conventional commits. End commit messages with:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Branch off `main`; one PR per logical change. No merge without an explicit
  per-PR instruction.

## Build discipline

Minimal shelf first: `trusted_operator`, local-volume engine, host-local
credential (admitted only single-tenant `trusted_operator`, NFR-SEC-60),
file-system audit sink — zero external dependencies. Tests ship in the same PR
as the code, to the verification method the component's NFR row names
(property-tests on the authz resolver and path resolution are mandatory, not
optional).

## CI gates (strict from commit 1)

Every PR must pass: secrets scan (gitleaks + trufflehog, any hit blocks),
naming denylist (lexicon job; the list is maintained outside the tree), SAST
(semgrep CRITICAL blocks), SCA (trivy CRITICAL blocks), conventional-commits.
Coverage, mutation, property, and perf gates wire in as the code lands.

Run `make check` before every push (fmt+vet+staticcheck+spdx+contract+identity+
test). Also run `make deadcode` — whole-program reachability that surfaces an
unreachable EXPORTED function `unused`/U1000 cannot see (it is package-scoped);
the tool exits 0 even on findings (golang/go#64713) so the target wraps it to
exit 1 on non-empty output.

Thresholds and gate status:
- Coverage floor: 86.0% over `./internal/...` (blocking).
- Mutation (gremlins): advisory, with a blocking ratchet planned.
- deadcode: advisory this round (CI `continue-on-error`); a blocking flip is a
  later ratchet. Not wired into `make check`.

This is a Go repo — tool→language map. Add ONLY Go tooling. Forbidden:
never add a JS/TS toolchain (`tsc`, `eslint`), Rust (`clippy`), or Python
(`ruff`, `mypy`, `pylint`) linter — wrong language, they would scan an empty
tree. Do NOT add a second coverage, mutation, SAST/semgrep, or lint gate; the
gates above are the single source for each axis.

No-bypass: never weaken or skip a gate to make it pass. Do not lower the
coverage floor to absorb new code, do not `// nolint` or `continue-on-error` a
blocking gate, and do not delete a finding's test to silence it. Fix the
underlying issue or, for an advisory finding, record it for an owner decision.
