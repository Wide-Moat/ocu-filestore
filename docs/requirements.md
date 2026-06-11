<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Requirements and defaults

Distilled from the architecture canon (component-04 spec, ADR-0010/0011, the
three storage contracts, and the NFR rows they cite) for the team building
this repo. The canon wins on any conflict; this file is a working index, not a
second source of truth.

## Invariants (build targets, each falsifiable)

| # | Rule | Source | Verification |
|---|---|---|---|
| 1 | No path or object handle resolves outside the request's host-attested `filesystem_id` prefix; traversal/symlink/absolute/URL-shaped handles rejected before any backend call | NFR-SEC-25 | property-test |
| 2 | No caller names a backend object directly; the broker maps verb/intent to a request signed with its own credential; caller-supplied session/tenant id is a hint cross-checked against host-attested identity | NFR-SEC-43 | property-test |
| 3 | `downloadable` resolved broker-side at read on both faces; `intent=preview` is read-only and non-downloadable regardless of stored tag | NFR-SEC-73 | property-test |
| 4 | Three-axis authz (scope × intent × downloadable) re-derived per request, deny-by-default | NFR-SEC-49 | property-test |
| 5 | Over-ceiling inbound body rejected pre-buffer, never partially staged; archives validated pre-extraction; content classified on ingest before mount-visibility | NFR-SEC-78/80/81 | schema + property-test |
| 6 | North face: signature-valid, in-audience, unexpired embed token before any session state; 401 with no anonymous fallback; CSRF on every mutating call; `CSP: frame-ancestors` from per-deployment allowlist | NFR-SEC-82/83/84 | schema-validation |
| 7 | No OCU upstream secret crosses to the browser; backend credential never leaves the object-store client | NFR-SEC-82/25 | unit + property-test |
| 8 | Every file activity emits an OCSF File System Activity event before the operation is acknowledged; audit-write failure denies the operation (fail-closed) | NFR-SEC-79 | unit-test |
| 9 | Multi-tenant: one broker principal per tenant filesystem scope; multiplexed broker only on single-tenant `trusted_operator` | NFR-SEC-76 | IaC-policy assertion |
| 10 | Long-lived host-local backend credential admitted only single-tenant `trusted_operator`; otherwise STS-scoped-per-session | NFR-SEC-60 | per-profile admission test |

## Defaults (NFR-derived, configurable, not frozen)

| Knob | Default | Source |
|---|---|---|
| Inbound request body ceiling | 50 MiB, reject pre-buffer | NFR-SEC-78 |
| Archive uncompressed total | 1 GiB, halt mid-extract at ceiling | NFR-SEC-80 |
| Archive entry count | 100 000 | NFR-SEC-80 |
| Embed-token lifetime ceiling | `exp − iat ≤ 120 s` | NFR-SEC-82 |
| First-party cookie | `SameSite=None; Secure; HttpOnly` | NFR-SEC-84 |
| `frame-ancestors` | `'none'` until allowlisted; minimal shelf `'self'` | NFR-SEC-83 |
| Content classification | classify-and-record; policy-deny opt-in per scope | NFR-SEC-81 |
| Backend engines | `local-volume` (solo reference) + `s3`, both day one | ADR-0010 |

## Deliberately out of scope

- Durable retention of customer bytes — ephemeral workspace; long-term
  retention belongs to the customer's store. The audit record is what
  persists.
- Live-view (browser/terminal) surfaces — v2, tracked in the architecture
  repo; do not design them out of the north face, do not build them.
- Share-by-link capability URLs, list pagination, resumable upload, opaque
  object ids — unsourced for this surface; adding any of them is a contract
  change in the architecture repo first.
- Kill-switch and denylist authority — Control plane owns them; the broker
  only enforces session validity it is told about.

## Open questions (tracked in the architecture repo)

Broker cardinality per deployment vs per host (#175); embed-token
replay-binding (#217); preview-render parser isolation (#218); per-action
authz granularity (#187).
