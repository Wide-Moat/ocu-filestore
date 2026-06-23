<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# ROADMAP — ocu-filestore

The tracked phase tracker for the storage service. Every row is cross-checked
against `git log` on the branch it lands on; nothing is marked DONE that the
history does not show. The architecture repo's ADRs are the source of truth for
any BLOCKED row — a blocked phase unblocks only when its ADR leaves
`status: proposed`. This file restates delivery state in this project's own
words; it does not re-decide anything an ADR already pinned.

Status vocabulary: **DONE** (landed + ratified), **BLOCKED** (gated on a named
ADR still `proposed`), **TBD** (contract surface not yet pinned),
**FROZEN** (wire surface pinned, no further change without a contract bump),
**DEFERRED-VERIFICATION** (built; final proof deferred to a named rig).

---

## Phases

| Phase | Scope | Status | Gate / anchor | Evidence |
| ----- | ----- | ------ | ------------- | -------- |
| REST pivot | Retire the broker north/south-face + fixed-proxy lane; object-store service over HTTPS / REST-JSON / JWT; delete dead Connect/unix/peer-cred/STS/lane, add the TLS server | **DONE** | component-04 + ADR-0014 transport model | `69907e6` (delete dead transport + TLS server, wave 5), `ec57b64` (README/docs/CHANGELOG synced, pivot phase-end), `8c6f9ca` (e2e-linux rewritten to REST/TLS) |
| Files-API handle-store | Durable file_id handle store: store interface + record + sentinels, fsync'd durable-append store, scope-bound tombstone Delete + last-write-wins replay, scope-binding resolver Get (keystone), List opaque-cursor paging, `--handle-store` daemon wiring | **DONE** (ratified, store + keystone + Delete + List + cursor + daemon + 3 follow-ups) | ADR-0023 | `a32b5d1` (store iface + sentinels), `19e3e61` (durable-append store), `ef48e24` (tombstone Delete), `1c3d023` (keystone resolver Get, anti-enumeration), `6744d48` (List cursor paging), `7c6d2b0` (`--handle-store` flag + flock + compose + readyz); follow-ups `365e4f7`, `53130bc`, `e1632ae` |
| A5-credscope | Service receives only the edge-injected real credential on `Authorization: Bearer`, forwards unmodified; scope check at the service/route layer, engine keyed on the scope string (no JWKS verify of the guest JWT) | **BLOCKED** (GATE-2) | ADR-0019 (`status: proposed`) | Ledger id `A5-credscope` in `docs/pending-phase7.md`; `PENDING-PHASE-7(A5-credscope)` markers stay in tree (no marker flipped) |
| engine-leg-egress | Whether the S3 engine's OWN backend leg retains an egress proxy (ADR-0011-vs-new-model reconciliation); interim engine backend client is a plain strict-TLS dial, never `http.ProxyFromEnvironment` | **BLOCKED** (GATE-3) | ADR-0021 (`status: proposed`) | Ledger id `engine-leg-egress` in `docs/pending-phase7.md`; `PENDING-PHASE-7(engine-leg-egress)` markers stay in tree (no marker flipped) |
| Message bodies | Per-operation request/response body shapes beyond the five frozen wire ids | **TBD** | `x-ocu-tbd-bodies` (awaiting field-level pin in the frozen contract) | Bodies marked TBD in the vendored contract stay TBD until the contract pins them — never invented here |
| Wire shape (5 ids) | The five wire-shape ids (`A1-route`, `A2-multipart`, `A2-octet`, `A3-deny`, `A4-fsid-toplevel`) | **FROZEN** @ `a030b7be914b` (#292) | #292 merged; A4 contradiction resolved | `7ddac98` (freeze the 5 wire-shape ids @ `a030b7be914b`, #292 merged) |
| Container-leg e2e | Live REST/TLS end-to-end over a real container runtime | **DEFERRED-VERIFICATION** (Lima) | — | REST/TLS e2e harness present (`8c6f9ca`); the container-leg run is deferred to the Lima rig on this host |

---

## Follow-ups (tracked, not yet scheduled)

- **Arm the mutation gate.** `.gremlins.yaml` coverpkg now includes the
  `credscope.go` and `pathresolver.go` guards, but the gate stays advisory:
  on the pinned Go 1.26 toolchain gremlins v0.6.0 reports every mutant as
  "Not covered" (0 killed / 0 lived) across all in-scope packages despite
  their mandatory property-tests, so there is no real efficacy figure to
  ratchet against. When gremlins (a fixed release, or a different mutation
  tool) produces a stable, correct efficacy figure on the pinned toolchain,
  set `threshold.efficacy` / `threshold.mutant-coverage` to `floor(baseline)`
  in `.gremlins.yaml` and drop `continue-on-error` in
  `.github/workflows/mutation.yml`. See the rationale block in `.gremlins.yaml`.
- **Handle-store hardening debt.** Two open issues track follow-up work on the
  keystone resolver path (Files-API handle-store, above): #19 (auditgate
  fail-open alignment) and #20 (defense-in-depth hardening). Both are scheduled
  against the north Files-API binding, not this phase.
