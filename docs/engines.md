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
| **Network leg** | None — reads and writes go to a local directory | Yes — every verb transits the storage egress lane |
| **Single-host only?** | Yes — the directory must be on the local volume | No — the bucket is remote |
| **Credential** | Host filesystem permission (daemon's uid) | Access key + optional STS per-session |
| **Storage lane required** | No | **Yes** in production; dev override available |
| **Versioned bucket** | n/a | Versioned buckets are supported; unversioned are the simpler path |
| **Erase-before-reuse (NFR-SEC-54)** | Recursive directory removal | Object deletion (+ version sweep if bucket is versioned) |
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

**Erase-before-reuse:** on `TeardownScope` (which runs unconditionally on every
clean or signalled stop — see the signal contract in
[docs/operations.md](operations.md)) the engine recursively removes the scope
directory and all its contents. After teardown, no bytes from the prior session
are readable under that scope.

**Crash sweep:** on `ProvisionScope`, if the scope directory already exists from
a prior crashed session, the engine removes it first and creates a fresh
directory. This is the erase-at-provision path: a crashed predecessor never
leaves bytes visible to the next session.

### Erase-before-reuse and the staging area

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
| `-storage-lane` | `OCU_FILESTORE_STORAGE_LANE` | Storage egress lane proxy URL (ADR-0011); required unless `-storage-lane-dev-direct` is set |

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

### Versioned buckets and erase-before-reuse

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
successful erase when it cannot verify that bytes are gone. Fix the IAM policy
to include `s3:ListBucketVersions` on the bucket, then restart.

### Storage egress lane (ADR-0011)

The S3 engine's backend leg **must** transit a dedicated storage egress lane.
A direct backend dial that bypasses the lane is refused (NFR-SEC-16, NFR-SEC-85):

```
ocu-filestored: -engine s3 requires -storage-lane (ADR-0011 …)
```

The lane is a fixed HTTP/HTTPS proxy supplied via `-storage-lane`. The engine
builds the HTTP transport with `http.ProxyURL(laneURL)` and never consults
`HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY` from the process environment — those
environment variables cannot redirect or bypass the lane.

**TLS is strict fail-closed:** there is no `InsecureSkipVerify` path. If the
storage lane proxy performs TLS inspection, provide the proxy's CA certificate
via `-ca-bundle` (a PEM file appended to the system cert pool). A missing or
unparseable CA bundle refuses startup; it does not silently fall back.

**Dev rigs:** set `-storage-lane-dev-direct` to skip the lane requirement and
dial the backend directly. This flag is mutually exclusive with `-storage-lane`.
Never set it in production.

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

### STS-per-session credential (optional)

Set `-s3-sts-role-arn` to enable STS-per-session credentials. The daemon calls
`AssumeRole` using the static credential above as the parent, producing a
short-lived session credential. The session credential is confined by an
**inline IAM session policy** scoped to the tenant's key prefix:

```json
{
  "Statement": [
    {
      "Sid": "ScopeObjects",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "…"],
      "Resource": "arn:aws:s3:::BUCKET/SCOPE/*"
    },
    {
      "Sid": "ScopeList",
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
      "Resource": "arn:aws:s3:::BUCKET",
      "Condition": {"StringLike": {"s3:prefix": "SCOPE/*"}}
    }
  ]
}
```

Even if the session credential leaks, it can touch only the tenant's own prefix
cell. The static parent credential never leaves the daemon.

Optionally override the STS endpoint (for self-hosted S3-compatible stacks) via
`-s3-sts-endpoint`; requires `-s3-sts-role-arn`.

### IAM policy requirements for the static credential

Whether using the static credential directly or as the STS parent, the
credential's IAM policy must allow:

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

**Scope the policy to the minimum prefix.** The STS session policy narrows it
further per session, but the static credential's base policy is the outer bound.

### Multipart uploads and memory bounds

The S3 engine never buffers a whole object in memory. Writes above
`s3DefaultSinglePutCutoff` (16 MiB by default) use multipart uploads with
reused 16 MiB part buffers. On any error path (including context cancellation),
all in-progress multipart uploads are aborted so orphaned parts do not
accumulate in the bucket. `TeardownScope` also sweeps any remaining orphaned
multipart uploads before reporting clean.

---

## Erase-before-reuse guarantee (NFR-SEC-54)

Both engines implement the erase-before-reuse guarantee: `TeardownScope` runs
unconditionally on every clean shutdown (SIGTERM/SIGINT → bounded drain →
teardown), and on crash recovery (`ProvisionScope` erases an existing scope
before creating a fresh one). After `TeardownScope` returns, no byte from the
prior session is readable under that scope.

The teardown runs under a bounded context (10-minute timeout for the s3 engine,
1-minute for the local-volume engine) so a hung backend cannot wedge teardown
indefinitely.
