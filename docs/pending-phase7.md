<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# PENDING-PHASE-7 ledger

The south-face transport and credential model pivot from a Connect-over-unix-socket
session channel to REST-JSON over an edge-injected-credential HTTPS service. Five
wire-surface assumptions drive that pivot. Each is **sibling-proven** — a shipped
peer client already speaks exactly this surface, so the shapes are settled in
practice — and each is **frozen pending the #292 canon merge**: once the
component-04 canon revision merges, these stop being assumptions and become
contract.

This ledger enumerates the five, and defines the grep-able code-marker
convention that ties every line of code touching one of them back to this
ledger.

## The marker convention

Every code site that depends on one of the assumptions below carries a comment
marker of exactly this form:

```
// PENDING-PHASE-7(<id>): <one-line statement of the assumption>
```

where `<id>` is one of the six ids in the table below. The marker is grep-able:

```
grep -rn "PENDING-PHASE-7(" internal/ docs/
```

surfaces every dependency in one pass. When the #292 canon revision merges,
each marker flips in place to:

```
// PENDING-PHASE-7(<id>): frozen @ canon-rev <sha>
```

so a later reader can confirm the assumption was ratified and at which revision,
and the same grep keeps working as the audit trail.

## The ledger

| id                 | assumption (sibling-proven, frozen pending #292)                                                                                                                                                                                  |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `A1-route`         | Every operation is `POST <service_url>/v1/filestore/fs/<operation>`; the operation name is the trailing path segment; the method is always POST. Transport is REST-JSON over HTTP/2 for the unary ops.                            |
| `A2-multipart`     | `fileUpload` is `multipart/form-data`: a `params` form field carrying the upload-params JSON (with `declared_size_bytes` REQUIRED and `overwrite_existing` omitempty), then a `file` form file streaming the raw object bytes.    |
| `A2-octet`         | `fileDownload` request is REST-JSON (uuid-axis, optional range); the response is a chunked `application/octet-stream` of the raw object bytes, with no JSON envelope and no per-chunk framing.                                     |
| `A3-deny`          | A deny is the HTTP status (authoritative) plus a `BoundedReason {reason_code, message}` diagnostic body. Status map: 401/403 to permission, 404 to not_found, 409 to already_exists, 400/422 to invalid, 429/503 to retryable, else permanent. |
| `A4-fsid-toplevel` | `filesystem_id` is a TOP-LEVEL request field, a sibling of `authorization_metadata`, never nested inside it. `authorization_metadata` carries exactly `{intent, downloadable}`.                                                   |
| `A5-credscope`     | The service receives ONLY the edge-injected real credential on `Authorization: Bearer` (never the guest weak JWT), forwards it to the engine unmodified, and the engine enforces `filesystem_id` scope on it (403 foreign, 401 missing/expired) WITHOUT JWKS-verifying it. |
| `engine-leg-egress` | The guest-path storage lane (the ADR-0011 fixed-proxy transport that carried the guest data path) is RETIRED: the guest path is now guest → edge → service direct HTTPS. Whether the s3 engine's OWN backend leg retains an egress proxy is a separate ADR-0011-vs-new-model reconciliation, not yet frozen; the interim engine backend client is a plain strict-TLS dial (never `http.ProxyFromEnvironment`). NFR-SEC-25 is preserved — the engine is still the single object-store-protocol speaker. |

### Notes on the deny diagnostic body (`A3-deny`)

`BoundedReason.reason_code` is a **pattern-validated open string**, not a closed
enum: it must match `^[A-Z][A-Z0-9_]{1,63}$`. The default vocabulary
(`SCOPE_MISMATCH`, `INTENT_DENIED`, `NOT_DOWNLOADABLE`, `LEASE_EXPIRED`,
`SIZE_EXCEEDED`, `NOT_FOUND`) is preferred for log consistency but is not
enforced — any pattern-valid code is legal. `BoundedReason.message` is bounded
to 256 characters. The diagnostic body never drives client behaviour; the HTTP
status is authoritative. A `429` may carry a `Retry-After` header.

### Notes on the credential model (`A5-credscope`)

The scope check sits at the service/route layer feeding a thin engine (the
open-question resolution selected option (c)). The edge validates and strips the
guest weak JWT and injects the real credential; the service and engine never see
the weak JWT, and the broker mints and signs nothing (invariant 3).

### Notes on the engine backend leg (`engine-leg-egress`)

The guest-path storage-lane transport (`NewLaneTransport`/`NewDevDirectTransport`)
is deleted: the guest no longer transits a storage lane to reach the service; it
dials the service directly over HTTPS through the Egress edge. The DISTINCT
question of whether the s3 engine's own backend dial keeps an egress proxy is a
separate ADR-0011-vs-new-model reconciliation that must be confirmed in the canon
freeze before any engine-leg proxy capability is removed wholesale. The interim
engine backend client (`newBackendTLSClient` in `cmd/ocu-filestored`) is a plain
strict-TLS dial with `http.Transport.Proxy` left nil (no environment proxy can
redirect or bypass it, NFR-SEC-16/85). Markers carry `PENDING-PHASE-7(engine-leg-egress)`
in `internal/objectstore/objectstore.go` and `cmd/ocu-filestored/main.go`.

## The parity oracle

`internal/southface/restparity_fixtures_test.go` transcribes all of the above as
Go fixtures and asserts them against themselves (`TestRESTParityFixtures`). This
wave the fixtures pin a fixed target; later waves drive a live server against the
same fixtures, so the server's emitted wire is checked against this pinned target
rather than against itself. Each fixture group carries the matching
`PENDING-PHASE-7(<id>)` marker, so the grep above also surfaces the oracle.
