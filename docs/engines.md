# Engine selection guide — ocu-filestored

`ocu-filestored` supports two backend engines selected by `-engine`. Both are
real and operational. This document describes when to use each, what each
requires from the deployment, and the security constraints that apply to the S3
engine.

Related documents: [docs/operations.md](operations.md) (full flag reference,
signal contract, audit-latch runbook).

Questions or issues: developer@widemoat.ai

---

## Choosing an engine

| | `-engine local-volume` | `-engine s3` |
|---|---|---|
| **Backend** | Host filesystem directory | S3-compatible object store |
| **Network leg** | None — reads and writes go to a local directory | Yes — the engine dials the backing store directly over strict TLS |
| **Single-host only?** | Yes — the directory must be on the local volume | No — the bucket is remote |
| **Backend credential** | Host filesystem permission (daemon's uid) | Static host-local access key (the engine's own backend credential, NFR-SEC-25) |
| **Versioned bucket** | n/a | Versioned buckets are supported; unversioned are the simpler path |
| **Scope erase (NFR-SEC-54, no trigger yet)** | Recursive directory removal | Object deletion (+ version sweep if bucket is versioned) |
| **Typical use** | Solo deployment, development, single-host container | Multi-host, managed object storage, cloud |

---

## local-volume engine

### Required flags

| Flag | Env var | Notes |
|------|---------|-------|
| `-engine-root` | `OCU_FILESTORE_ENGINE_ROOT` | Directory that must be readable and writable by the daemon's uid |

### How it works

The local-volume engine roots every scope under `-engine-root`. The scope key
(the session's `-filesystem-id`) becomes a subdirectory; path operations are
contained by the Go `os.Root` API — traversal, symlink escape, and
absolute-path handles are rejected before any syscall. No network connection is
opened.

**Scope erase:** `TeardownScope` recursively removes the scope directory and
all its contents, then recreates it empty. After it returns, no byte written
under that scope is readable. Nothing in the product calls it — see
[the erase verb and its missing trigger](#the-erase-verb-and-its-missing-trigger).

**Provision:** `ProvisionScope` ensures the scaffold exists — it creates the
scope directory when absent and sweeps only the guest-invisible staging
sub-directory, discarding partial writes a crashed daemon left behind. Owner
data at the scope root is never removed, so a restart re-serves exactly what
the previous run stored.

### The staging area

Writes are staged in a guest-invisible `.ocu-staging/` subdirectory inside the
scope and promoted atomically. A partial write is never visible at the
destination path. `TeardownScope` removes the staging area along with the rest
of the scope.

---

## s3 engine

### Required flags

| Flag | Env var | Notes |
|------|---------|-------|
| `-s3-bucket` | `OCU_FILESTORE_S3_BUCKET` | The single bucket all scopes live under |
| `-s3-endpoint` | `OCU_FILESTORE_S3_ENDPOINT` | Backend endpoint URL; required even for AWS (use the regional endpoint) |
| `-s3-region` | `OCU_FILESTORE_S3_REGION` | Signing region; default `us-east-1` if unset but always required |

### Path-style addressing — MinIO and Ceph RGW

Most single-host S3-compatible backends (MinIO, Ceph RGW) require
**path-style** addressing, where the bucket name appears in the URL path rather
than the hostname:

```
path-style:  http://127.0.0.1:9000/my-bucket/prefix/key
vhost-style: http://my-bucket.127.0.0.1:9000/prefix/key  ← does not work on most single-host rigs
```

Set `-s3-path-style` (or `OCU_FILESTORE_S3_PATH_STYLE=true`) when the backend
is MinIO, Ceph RGW, or any single-host backend that does not support virtual-
host-style addressing.

AWS S3 supports both styles; path-style is deprecated for AWS but continues to
work. Leave `-s3-path-style` unset (default `false`) when targeting AWS S3.

### Checksum behaviour on custom endpoints

When `-s3-endpoint` is set (any non-empty value), the engine switches the AWS
SDK's request and response checksum mode to `WhenRequired`. The default checksum
trailers that the SDK appends for AWS can confuse S3-compatible backends and
cause request failures that look like data corruption. This switch is applied
automatically; no operator action is needed.

### Versioned buckets and the scope erase

An S3 bucket may be versioned (object versions retained on delete) or
unversioned (deletes remove the object immediately).

**Unversioned bucket:** `TeardownScope` lists and deletes all current objects
under the scope prefix. After teardown, no prior-session bytes remain in the
bucket.

**Versioned bucket:** a plain delete creates a delete marker; the prior version
bytes remain billable and readable by anyone with `s3:GetObjectVersion`.
`TeardownScope` detects versioning via `GetBucketVersioning`, then sweeps all
versions (including delete markers) with `DeleteObjects`. This completely
removes every version of every object in the scope.

**Refused versioned bucket:** if the bucket is versioned but the credential's
IAM policy does not allow `ListBucketVersions`, the version sweep refuses
rather than reporting clean while bytes remain:

```
objectstore: bucket is versioned but version listing is denied; erase refused (bytes would remain)
```

This is fail-closed behaviour (NFR-SEC-54): the engine never reports a
successful erase when it cannot verify that bytes are gone. Grant
`s3:ListBucketVersions` on the bucket before an erase is expected to succeed.

### Backend dial (NFR-SEC-25)

The S3 engine is the single component that speaks the object-store protocol
(NFR-SEC-25). It dials the backing store directly with a plain strict-TLS HTTP
client: `MinVersion` TLS 1.2, HTTP/2 attempted, and it never consults
`HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY` from the process environment.

**TLS is strict fail-closed:** there is no `InsecureSkipVerify` path. The
backend endpoint must present a certificate the system trust store can verify.

> The guest data path no longer transits a storage egress lane. The guest
> reaches the south-face TLS REST listener outbound through the Egress edge
> (guest → edge → service direct HTTPS); the retired ADR-0011 fixed-proxy lane
> carried that guest path and is gone. Whether the engine's own backend leg
> later reintroduces an egress proxy is an open ADR-0011-vs-new-model
> reconciliation tracked in [docs/pending-phase7.md](pending-phase7.md)
> (`engine-leg-egress`), not a current flag.

### Credential intake

Backend credentials never arrive as flag values — flag values are visible in
`/proc` argument listings.

**Two authorized intake paths (in precedence order):**

1. **`-s3-credential-file` flag** (path to a credential file):
   The file must be a regular file (not a symlink), mode exactly `0600`, owned
   by the daemon's uid, holding:
   ```
   access_key_id=AKIAEXAMPLE
   secret_access_key=wJalrXUtnFEMI/K7MDENG
   ```
   Any defect refuses startup; there is no fall-through to the environment.

2. **Environment variables** (when no credential file is named):
   `OCU_S3_ACCESS_KEY_ID` and `OCU_S3_SECRET_ACCESS_KEY`. Both must be
   non-empty.

These env vars are **not** part of the generic `OCU_FILESTORE_*` fallback map.

The static credential is the **engine's own backend credential** (NFR-SEC-25):
the key the single object-store client uses to reach the backing store. It is
distinct from the **guest's filestore credential**, which the service never
holds. The Egress trust-edge validates and strips the guest's weak session JWT,
exchanges it (RFC 8693) for the real filestore credential, and injects that on
the request's `Authorization: Bearer` header. The service forwards the injected
credential to the engine unmodified and **mints/signs nothing** (invariant 3);
the engine enforces `filesystem_id` scope on it — a foreign scope is `403`, a
missing or expired credential is `401`. The per-session `AssumeRole`
credential-minting the service once performed is retired along with the
broker-signs model.

### IAM policy requirements for the static credential

The engine's static backend credential's IAM policy must allow:

**Object operations on the scope prefix:**
- `s3:GetObject`, `s3:GetObjectVersion`, `s3:GetObjectTagging`
- `s3:PutObject`, `s3:PutObjectTagging`
- `s3:DeleteObject`, `s3:DeleteObjectVersion`
- `s3:AbortMultipartUpload`, `s3:ListMultipartUploadParts`

**Bucket listing:**
- `s3:ListBucket`, `s3:ListBucketVersions` (conditioned on the scope prefix)

**Bucket-wide (for the MPU orphan sweep and versioning probe):**
- `s3:ListBucketMultipartUploads` — no prefix condition; the engine filters
  client-side (a prefix condition on this API is not honored by every backend)
- `s3:GetBucketVersioning`

**Scope the policy to the minimum prefix.** The static credential's base policy
is the outer bound on what the engine can ever touch in the backing store.

### Multipart uploads and memory bounds

The S3 engine never buffers a whole object in memory. Writes above
`s3DefaultSinglePutCutoff` (16 MiB by default) use multipart uploads with
reused 16 MiB part buffers. On any error path (including context cancellation),
all in-progress multipart uploads are aborted so orphaned parts do not
accumulate in the bucket. `TeardownScope` also sweeps any remaining orphaned
multipart uploads before reporting clean.

---

## The erase verb and its missing trigger

Both engines implement a scope erase. `TeardownScope` removes every byte under
the scope — a recursive directory removal on the local-volume engine, a
paginated object sweep on S3 that also clears every non-current version, every
delete marker, and every orphaned multipart upload. It refuses rather than
reporting clean when it cannot prove the bytes are gone. After it returns, no
path written under that scope is readable.

**Nothing in the product calls it.** There is no flag, no administrative route
and no signal path that reaches the verb; the two whole-filesystem operations
that could carry one (`removeFilesystem`, `migrateFilesystem`) are unimplemented
because the frozen wire contract leaves their bodies unspecified. Today the verb
is exercised only by tests.

That is half deliberate and half a gap, and the two halves are worth separating.

The deliberate half: **erase is keyed to a change of owner, never to the process
lifecycle.** Once it was keyed to the process — erase at boot, erase at SIGTERM —
and an ordinary restart destroyed every object a live owner held. Provision is
now ensure-scaffold-if-absent and shutdown touches nothing on disk, so a restart
is safe. An operator can stop, upgrade and start this daemon without losing a
byte, and that property is guarded by a test.

The gap: **no owner-change trigger was ever built to take the verb's other end.**
This service cannot invent one. The architecture canon re-homes erase-before-reuse
to the session-sandbox component, states that erase and residue-drop are that
component's invariants rather than this service's, and gives this service no
erase or scope-lifecycle invariant of its own. It also names no event on any
surface this service can observe that would mean "the owner has changed". Until
canon names such an event and the surface it arrives on, building a trigger here
would be inventing a security behaviour, so the verb stays wired to nothing and
this document says so rather than describing a sweep that does not run.

**The consequence to hold in mind:** a scope outlives every process that served
it. Bytes are removed when a caller deletes them and at no other time. On the
local-volume engine that is disk that never reclaims itself; on S3 it is storage
that keeps billing. An operator who needs a scope gone must remove it out of
band — `rm -rf` the scope directory, or delete the prefix with the backend's own
tooling — while the daemon for that `filesystem_id` is stopped.

**Open question for the owner.** See
[§3.5 of the lifecycle document](architecture/05-lifecycle.md#35-open-question--the-erase-trigger)
for the trigger shapes on the table.

When the trigger does land, the erase runs under a bounded context (10 minutes
for the s3 engine, 1 minute for the local-volume engine) so a hung backend
cannot wedge the caller indefinitely.
