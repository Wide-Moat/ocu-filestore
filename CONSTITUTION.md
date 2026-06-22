<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# CONSTITUTION — ocu-filestore

The storage service's load-bearing invariants. These eight never-rules are the
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
