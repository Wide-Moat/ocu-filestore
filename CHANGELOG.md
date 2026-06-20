# Changelog

All notable changes to `ocu-filestore` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a v1.0
is cut.

## [Unreleased]

### Changed — south-face transport pivot (BREAKING)

The south face is recut from a Connect-RPC channel over a per-session Unix
socket to a **TLS HTTPS/HTTP-2 REST-JSON listener** that the guest reaches
**outbound through the Egress trust-edge** (guest → edge → service direct
HTTPS). This is a breaking change to the on-the-wire transport and to the
operator flag surface.

- Every operation is now `POST <service_url>/v1/filestore/fs/<operation>`; the
  operation name is the trailing path segment and the method is always `POST`.
  `fileUpload` is `multipart/form-data` (a `params` JSON field plus a streamed
  `file`); `fileDownload` returns a chunked `application/octet-stream` body.
- A deny is carried by the HTTP status (authoritative) plus a
  `BoundedReason {reason_code, message}` diagnostic body.
- The host Unix socket, the `SO_PEERCRED` peer-credential accept gate, and the
  Connect-RPC channel are removed. The transport is now **platform neutral** —
  it depends on no Linux-only socket option, so the daemon is no longer
  Linux-only for the south face.

### Changed — credential custody

The service no longer holds or mints the guest's storage credential. The
Control plane mints a weak session JWT (the guest's concern); the **Egress edge
validates and strips that JWT, exchanges it (RFC 8693) for the real filestore
credential, and injects the real credential** on the request's
`Authorization: Bearer` header.

- The service receives only the injected real credential, forwards it to the
  engine unmodified, and **mints and signs nothing** (invariant 3).
- The **engine** enforces `filesystem_id` scope on the injected credential: a
  foreign scope is `403`, a missing or expired credential is `401`. The service
  does not JWKS-verify the bearer — the edge owns weak-JWT validation.
- The engine's own backend credential (the static host-local key, NFR-SEC-25)
  is unchanged and remains distinct from the guest's edge-injected credential.

### Added

- `-tls-cert` / `-tls-key` (env `OCU_FILESTORE_TLS_CERT` /
  `OCU_FILESTORE_TLS_KEY`) — **required** south-face TLS server certificate and
  private-key PEM paths.
- `-south-bind` (env `OCU_FILESTORE_SOUTH_BIND`, default `127.0.0.1:7443`) — the
  south-face TLS HTTPS bind address; the `service_url` the guest dials outbound
  through the Egress edge.

### Removed

- `-south-socket-dir` — there is no per-session Unix socket directory.
- `-storage-lane` and `-storage-lane-dev-direct` — the ADR-0011 storage egress
  lane that carried the guest data path is retired; the guest path is now
  guest → edge → service direct HTTPS. The engine dials its own backing store
  directly over strict TLS, and stays the single object-store-protocol speaker
  (NFR-SEC-25).
- `-ca-bundle` — it appended an inspecting storage-lane proxy CA to the trust
  pool; with the lane gone there is no proxy CA to trust.
- `-s3-sts-role-arn` and `-s3-sts-endpoint` — the per-session `AssumeRole`
  credential-minting path is retired together with the broker-signs model. The
  service mints/signs nothing; per-session scoping of the guest credential is
  the edge's RFC 8693 exchange, and `filesystem_id` enforcement is the engine's.

### Notes

- Both backend engines remain real and executed: **local-volume** (host
  filesystem, no network leg) and **s3** (network engine, MinIO/Ceph RGW
  compatible).
- The route, deny shape (`A3-deny`), and credential-custody axis (`A5-credscope`)
  are sibling-proven and frozen pending the #292 canon merge; see
  [docs/pending-phase7.md](docs/pending-phase7.md) for the full ledger and the
  open `engine-leg-egress` (ADR-0011-vs-new-model) reconciliation.
