<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# CONSTITUTION — ocu-filestore

The storage service's load-bearing invariants. These eleven never-rules are the
architect's mandate: each is tied to its NFR row, the component invariant it
upholds, and the ADR that decided it. Every one names where the code enforces
it. A change here changes in the architecture repo first; this file only
restates what the canon already pins, in this project's own words.

Each rule is absolute. Violating one is a defect, not a trade-off.

---

## 1. Never a signing key on the service

The service mints and signs nothing. The edge injects the real backend
credential; the service forwards it unmodified, and the engine enforces the
credential's `filesystem_id` scope. One credential, one client — no second path
speaks the object-store protocol.

- ADR-0013 / ADR-0019, invariant 3 (NFR-SEC-25)
- Enforced: `internal/southface/credscope.go:deriveCredScope` — the scope source
  is the edge-injected request context, never a service-held key.

## 2. Never a path outside the host-attested `filesystem_id` prefix

Every caller-supplied object path is canonicalized at STAGE-1b and then opened
through an `os.Root`/`openat` containment root, so no resolution — symlink or
`..` — escapes the attested scope prefix. Path resolution carries mandatory
property-tests.

- Invariant 1 (NFR-SEC-25)
- Enforced: `internal/objectstore/pathresolver.go:ValidatePath` (STAGE-1b
  canonicalization + `filepath.IsLocal` containment) opened through
  `internal/objectstore/pathresolver.go:OpenScopeRoot`, whose `os.OpenRoot`
  resolves each path component with `O_NOFOLLOW` from the scope-root fd — the
  symlink-containment seam.

## 3. Never audit/ack without fail-closed atomicity

An OCSF File System Activity event is durably written and fsynced before any
2xx is returned. A failed sync denies the operation; a torn tail from a write
whose record was never acked is dropped on restart. Audit failure is denial,
never a silent pass.

- Invariant 7 (NFR-SEC-79)
- Enforced: `internal/auditgate/auditgate.go:Guard.Mandate` →
  `internal/auditgate/filesink.go:FileSink.Mandate` (write + `Sync`), returning
  `ErrAuditUnavailable` to deny.

## 4. Never a stream without a per-frame deadline

Inbound and outbound transfers carry a per-frame deadline (30s default),
re-armed on each body read and each flush. A slow-but-progressing transfer
keeps extending; a stalled peer times out and is dropped — it never
forever-holds the connection.

- NFR-SEC-46
- Enforced: `internal/southface/tlsserver.go:newTLSServer` deadlines, re-armed
  per-iteration via `http.NewResponseController` in the upload/download
  handlers.

## 5. Never authz on wire-supplied identity

The identity is the credential-bound scope established after edge injection,
not any request-supplied value. The wire `filesystem_id` is a hint; it is
cross-checked against the attested scope before authorization runs, and a
mismatch denies.

- Invariant 2 (NFR-SEC-43)
- Enforced: `internal/authz/resolver.go:policyResolver.Resolve` —
  `CallerEvidence.Scope` (host-attested) is authoritative; empty scope
  authorizes nothing, `ErrScopeMismatch` on disagreement.

## 6. Never over-deny a read of a non-downloadable object

A non-downloadable object is still readable in-session; the `downloadable` flag
gates only whether an egress artifact may be produced. It resolves at read from
the deployment's prefix set — never stamped at write.

- Invariant 5 (NFR-SEC-73)
- Enforced: `internal/broker/downloadable.go:NewPrefixDownloadablePolicy` — a
  false tag yields `Grant{Downloadable: false}` (read allowed), not a read
  denial.

## 7. Never a provisioned scope without a teardown partner

If session compose fails after the scope is provisioned, the scope is torn down
before the error returns. No half-provisioned scope ever leaks past startup.

- NFR-SEC-54
- Enforced: `cmd/ocu-filestored/main.go:compose` — a post-`ProvisionScope`
  construction error runs `TeardownScope` before returning `nil, err`.

## 8. Never let one session exhaust shared resources

Per-session ceilings — declared inbound size, ops rate, in-flight bytes, file
descriptors — fail closed. An over-ceiling request is rejected before a byte is
read; it never starves other sessions.

- NFR-SEC-46, LIM-01 / LIM-02
- Enforced: `internal/ceilings/ceilings.go` — `CheckDeclaredSize`,
  `Session.TryConsumeOp`, `Session.AcquireBytes`, `Session.TryAcquireFD`,
  keyed per `SessionKey` via `Registry.Session`.

## 9. Never a `file_id` that is a capability

A `file_id` carries no authority on its own. The resolver always takes the
scope from the host-attested channel — never a request-supplied value — and
asserts the stored record's scope byte-matches that attested scope before the
handle resolves. A cross-scope `file_id`, an unknown `file_id`, and an empty
attested scope are all indistinguishable from non-existence: each returns the
same `not_found` sentinel, never a `forbidden`, so a probe cannot enumerate
another scope's handles or confirm that any handle exists (anti-enumeration).

- ADR-0023 (Files-API north contract), invariant 5 (recut to scope-bound
  `file_id` resolution) — NFR-SEC-73 / NFR-SEC-25
- Enforced: `internal/handlestore/disk.go:DiskStore.Get` and
  `internal/handlestore/delete.go:DiskStore.Delete` reject an empty attested
  scope before the map lookup and return the byte-identical `ErrNotFound`
  sentinel for both the cross-scope and the absent case. The north Files-API
  listener now binds this live path: `internal/filesapi/route.go:writeNotFound`
  is the single not_found token on the wire — an unknown path, an unknown
  `file_id`, and a cross-scope `file_id` all collapse to one header-less 404,
  never a 403, so the wire layer cannot leak a scope or existence distinction.
  The route layer derives the host-attested scope ONCE per request from the
  attested F9 channel and resolves the durable handle-store; the keystone is
  mutation-proven through the HTTP layer. (The ephemeral within-session
  `internal/southface/objectid.go:objectIDStore` continues to back the south
  mount RPC, distinct from this durable north path.)

## 10. Never north and south on one listener, router, or resolver

The north face (the no-credential F9 Files-API, bound on `--north-bind`) and the
south face (the edge-dialed mount RPC, bound on `--south-bind`) never share a
listener, a router, or a resolver. They are two physically distinct binds with
two distinct request paths; the north package may borrow the south face's seam
TYPES (the resolver/guard/engine shapes and error sentinels) but never its
request-routing surface. That physical separation is what makes the
confused-deputy impossible — neither face can be steered onto the other's router
to launder authority across the trust boundary.

- ADR-0015 (north client/host-leg split) / ADR-0023 (Files-API north contract)
  — invariant 8 (NFR-SEC-82 / NFR-SEC-25)
- Enforced: `internal/filesapi/importboundary_test.go` is the import-graph guard
  that reds if the north package ever references the south request-routing
  surface (the router, the dispatcher, or their per-op stage entrypoints); it
  parses every non-test source file and fails on any forbidden `southface`
  selector. `cmd/ocu-filestored/dualserver.go` fans the two faces onto SEPARATE
  binds with separate servers. `internal/northface/mountb.go:NewMountB` reuses
  only the south face's certificate paths for Mount B, never its router — the
  shared input is the cert material, not the request path.

## 11. Never serve an op whose wire body the canon has not pinned

This service never serves a frozen-named operation whose per-operation
request/response body the canon contract has not yet pinned. It returns 501
(unimplemented) rather than invent a wire body and code against it. Inventing a
TBD body and building on it is the forbidden shortcut — the corner cut under
ship-pressure — and it is forbidden for every verb, present and future, not just
the one fenced today.

The current application is `POST /v1/files` (createFile): its upload body is
marked `x-ocu-tbd-bodies` in the frozen contract pending #304 / ADR-0025, so it
serves a clean 501. When #304 pins the upload body, createFile LEAVES the fenced
set and the write path lands; #11 itself still stands, guarding the next
frozen-named verb whose body the canon has not yet pinned. What resolves at #304
is createFile's membership in the fenced set, not the rule.

- Frozen-wire-contract discipline: the contract's `x-ocu-tbd-bodies` marker and
  CLAUDE.md's "never invent a body" rule — ADR-0023 (north contract) / ADR-0025
  (F9 scope-field transport, the upload-body pin)
- Enforced: `internal/filesapi/create_fenced.go:serveCreate` returns the
  `Unimplemented` deny (501) and touches no store and no engine while the upload
  body is unpinned. The guard is `internal/filesapi/create_fenced_test.go:TestCreateIsFenced501`
  — it asserts `POST /v1/files` returns 501 AND that the fenced create touched
  nothing (no store, no engine) while the body is `x-ocu-tbd`.
