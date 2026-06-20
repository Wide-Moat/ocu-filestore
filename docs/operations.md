# Operator runbook — ocu-filestored

This document is the operator reference for the `ocu-filestored` storage-broker
daemon. It covers the complete flag and environment-variable surface, startup
admission rules, the signal/shutdown contract, the audit-latch recovery
procedure, the hash-chain log-rotation rule, and the health and metrics
endpoints.

Questions or issues: developer@widemoat.ai

Related documents: [docs/engines.md](engines.md) (engine selection),
[docs/configuration.md](configuration.md) (flag → env-var table),
[docs/testing.md](testing.md) (test suite and CI gates).

---

## Flag and environment-variable reference

Every flag (except credential-bearing flags — see below) has a corresponding
`OCU_FILESTORE_*` environment variable. Precedence:

> **Explicit flag on the command line** > **`OCU_FILESTORE_*` env var** > **built-in default**

An env-var value that fails to parse produces the same typed error as a
malformed flag. Credential-bearing flags are excluded from the generic env map
and have dedicated intake paths (see [Credential intake](#credential-intake)).

### Complete flag/env table

| Flag | Env var | Type | Default | Required | Description |
|------|---------|------|---------|----------|-------------|
| `-audit-sink` | `OCU_FILESTORE_AUDIT_SINK` | string | — | **Yes** | Path to the append-only OCSF JSONL audit sink; an audit-write failure denies the operation (NFR-SEC-79) |
| `-broker-max-file-size` | `OCU_FILESTORE_BROKER_MAX_FILE_SIZE` | int64 | — | **Yes** (> 0) | Whole-object upload ceiling in bytes; requests above this are rejected before buffering (NFR-SEC-46/78) |
| `-downloadable-prefixes` | `OCU_FILESTORE_DOWNLOADABLE_PREFIXES` | string | `` | No | Comma-separated broker-side prefixes that resolve `downloadable`; empty means nothing is downloadable (deny-by-default, NFR-SEC-73) |
| `-engine` | `OCU_FILESTORE_ENGINE` | string | `local-volume` | No | Backend engine: `local-volume` or `s3` (ADR-0010) |
| `-engine-root` | `OCU_FILESTORE_ENGINE_ROOT` | string | — | **Yes** (local-volume only) | Local-volume engine root directory (the host filesystem workspace) |
| `-filesystem-id` | `OCU_FILESTORE_FILESYSTEM_ID` | string | — | **Yes** | Host-attested session scope identifier; the engine enforces it against the edge-injected credential per request (foreign → 403) |
| `-granted-intents` | `OCU_FILESTORE_GRANTED_INTENTS` | string | `read,write` | No | Comma-separated session intent grant set; valid tokens: `read`, `write`, `preview` |
| `-health-check` | `OCU_FILESTORE_HEALTH_CHECK` | bool | `false` | No | Self-probe mode: dial `-ops-listen /healthz` and exit 0 (alive) or non-zero (unreachable); used by container HEALTHCHECK |
| `-log-level` | `OCU_FILESTORE_LOG_LEVEL` | string | `info` | No | Structured JSON log level: `debug`, `info`, `warn`, `error`; unknown values refuse startup |
| `-max-request-bytes` | `OCU_FILESTORE_MAX_REQUEST_BYTES` | int64 | `52428800` (50 MiB) | No | Per-RPC-message inbound body ceiling; requests above this are rejected before buffering (NFR-SEC-78) |
| `-north-listen` | `OCU_FILESTORE_NORTH_LISTEN` | string | `127.0.0.1:7080` | No | North-face bind address; **parsed but inert** — binds nothing in the current release (north face deferred) |
| `-ops-burst` | `OCU_FILESTORE_OPS_BURST` | float64 | `200` | No | Per-session ops token-bucket capacity in tokens (>= 1); a session starts with a full bucket |
| `-ops-listen` | `OCU_FILESTORE_OPS_LISTEN` | string | `127.0.0.1:9464` | No | Loopback-only bind address for the ops listener (`/metrics`, `/healthz`, `/readyz`); empty disables; non-loopback refused pre-bind |
| `-ops-per-second` | `OCU_FILESTORE_OPS_PER_SECOND` | float64 | `100` | No | Per-session file-ops token-bucket refill rate in ops/s (> 0); the throttle ceiling (NFR-SEC-46) |
| `-profile` | `OCU_FILESTORE_PROFILE` | string | `trusted_operator` | No | Admission profile: `trusted_operator`, `internal_workforce`, `untrusted` |
| `-s3-bucket` | `OCU_FILESTORE_S3_BUCKET` | string | — | **Yes** (s3 only) | Backend S3 bucket; all session scopes live under this bucket |
| `-s3-endpoint` | `OCU_FILESTORE_S3_ENDPOINT` | string | — | **Yes** (s3 only) | Backend endpoint URL; any non-empty value is a custom endpoint and switches checksums to `WhenRequired` |
| `-s3-path-style` | `OCU_FILESTORE_S3_PATH_STYLE` | bool | `false` | No | Path-style S3 addressing; required for most single-host S3-compatible backends (MinIO, Ceph RGW) |
| `-s3-region` | `OCU_FILESTORE_S3_REGION` | string | `us-east-1` | **Yes** (s3 only) | S3 engine signing region |
| `-south-bind` | `OCU_FILESTORE_SOUTH_BIND` | string | `127.0.0.1:7443` | No | South-face TLS HTTPS bind address; the `service_url` the guest dials outbound through the Egress edge |
| `-tenancy` | `OCU_FILESTORE_TENANCY` | string | `single-tenant` | No | Tenancy mode: `single-tenant`, `multi-tenant` |
| `-tls-cert` | `OCU_FILESTORE_TLS_CERT` | string | — | **Yes** | South-face TLS server certificate PEM path |
| `-tls-key` | `OCU_FILESTORE_TLS_KEY` | string | — | **Yes** | South-face TLS server private-key PEM path |
| `-version` | `OCU_FILESTORE_VERSION` | bool | `false` | No | Print the build identity (tag, VCS revision, Go toolchain) and exit 0; does not require serving flags |

**Credential-bearing flags excluded from the generic env map:**

| Flag | Authorized intake |
|------|-------------------|
| `-s3-credential-file` | Set via flag directly (the path is not a secret); credential bytes via `OCU_S3_ACCESS_KEY_ID` / `OCU_S3_SECRET_ACCESS_KEY` (handled by `internal/objectstore`) |

See [Credential intake](#credential-intake) for details.

---

## South-face transport and credential custody

The south face is a TLS HTTPS/HTTP-2 REST-JSON listener bound at `-south-bind`
and presenting the certificate/key from `-tls-cert` / `-tls-key`. The guest
does not connect to a host Unix socket; it reaches the listener **outbound
through the Egress trust-edge** (guest → edge → service direct HTTPS). The
transport is **platform neutral** — it depends on no Linux-only socket option,
so the broker runs on Linux, macOS, or any platform Go's `crypto/tls` supports.

Every operation is `POST <service_url>/v1/filestore/fs/<operation>` (the
operation name is the trailing path segment). A deny is carried by the HTTP
status (authoritative) plus a `BoundedReason {reason_code, message}` diagnostic
body.

**Credential custody.** The Egress edge validates and strips the guest's weak
session JWT, exchanges it (RFC 8693) for the real filestore credential, and
injects that on the request's `Authorization: Bearer` header. The service
receives only the injected credential, forwards it to the engine unmodified,
and **mints/signs nothing** (invariant 3). The engine enforces `filesystem_id`
scope on it: a foreign scope is `403`, a missing or expired credential is `401`.
The service does **not** JWKS-verify the bearer — the edge owns weak-JWT
validation. The engine's own backend credential (NFR-SEC-25) is separate and
configured via the s3 credential intake (see [Credential intake](#credential-intake)).

The route, deny shape, and credential-custody axes are sibling-proven and
frozen pending the #292 canon merge; see
[docs/pending-phase7.md](pending-phase7.md).

---

## Startup admission and exit behaviour

The daemon runs the full admission and validation gate **before** binding any
socket (NFR-SEC-60). A refused startup always emits the error to stderr and
exits with code 1. Common refusal causes:

| Cause | Error message pattern |
|-------|-----------------------|
| Missing required flag | `required flag missing or invalid: -<flag-name>` |
| `-broker-max-file-size` is zero or negative | `required flag missing or invalid: -broker-max-file-size must be > 0` |
| Unknown `-log-level` | `observ: unknown log level …` |
| Unknown `-engine` | `objectstore: unknown backend engine …` |
| Unknown `-profile` or `-tenancy` | `ocu-filestored: unknown admission profile …` |
| Unknown token in `-granted-intents` | `ocu-filestored: unknown granted intent …` |
| Non-loopback `-ops-listen` | `ocu-filestored: -ops-listen … ops listener bind address is not a loopback address` |
| Missing `-tls-cert` | `required flag missing or invalid: -tls-cert is required (the south-face TLS server certificate)` |
| Missing `-tls-key` | `required flag missing or invalid: -tls-key is required (the south-face TLS server private key)` |
| `-engine s3` without required s3 flags | `required flag missing or invalid: -s3-bucket …` |
| S3-only flags with `-engine local-volume` | `required flag missing or invalid: -s3-bucket is only valid with -engine s3` |
| `-engine-root` with `-engine s3` | `required flag missing or invalid: -engine-root is not valid for the s3 engine` |
| Credential file mode not exactly 0600 | `objectstore: credential file refused …` |
| No backend credential for s3 | `objectstore: no backend credential …` |
| Admission table refusal (triple not in table) | `admission: …` |

The `-version` and `-health-check` flags short-circuit before validation: both
work without any serving flags.

---

## Signal and shutdown contract

The daemon registers `SIGTERM` and `SIGINT`. On either signal:

1. The daemon logs `signal received; starting bounded drain` at INFO.
2. Sends `STOPPING=1` to systemd via `NOTIFY_SOCKET` (no-op if unset).
3. Begins a **bounded 25-second graceful drain**: in-flight operations are
   allowed to finish. Operations still open after 25 seconds are
   force-closed.
4. `TeardownScope` runs **unconditionally** regardless of drain outcome —
   the erase-before-reuse (NFR-SEC-54) is never skipped by a clean stop.
5. The south-face TLS listener shuts down.
6. The ops listener shuts down.
7. The daemon exits; both the serve error and the teardown error (if any)
   are joined and written to stderr.

**A second signal during shutdown** (while the drain is running) kills the
process immediately with the OS default disposition (hard kill). The
first signal releases the signal intercept so the second one reaches the
runtime directly.

**Relationship to systemd `TimeoutStopSec`:** the contrib unit sets
`TimeoutStopSec=35s` — 10 seconds above the 25-second drain bound — so a
clean stop always has time to drain, force-close stragglers, AND run
erase-before-reuse before systemd sends `SIGKILL`.

---

## Audit-latch recovery runbook

The audit sink is fail-closed: **if any write or sync to the JSONL sink file
fails, the sink latches permanently for the lifetime of the process.** After a
latch:

- Every subsequent file operation is denied (`ErrAuditUnavailable`); no bytes
  are served or written.
- The `audit_sink_latched` metric gauge flips to `1`.
- `/readyz` returns `503` with body `audit_latch`.
- The daemon logs an ERROR line: `audit sink latched; broker serving 100%
  denies until restart`.

**The latch is permanent.** It does not reset on its own; recovery requires a
daemon restart after the underlying cause is fixed.

### Recovery procedure

1. **Identify the cause.** Check:
   - Disk space on the volume hosting `-audit-sink`.
   - File system errors (`dmesg`, `journalctl -k`).
   - Permissions on the sink directory (the daemon must be able to `open`,
     `write`, and `fsync` the file).
2. **Fix the underlying problem** (free disk space, repair the filesystem,
   correct permissions).
3. **Restart the daemon:**
   ```sh
   systemctl restart ocu-filestored
   ```
   On restart, `NewFileSink` re-opens the sink file and re-scans the hash chain
   from genesis. If the chain is intact, serving resumes. If the chain is broken
   (tampered or corrupted), the daemon refuses to start — see
   [Hash-chain verification](#hash-chain-verification) below.
4. **Verify recovery:** `audit_sink_latched` should return to `0`; `/readyz`
   should return `200`.

**Do not attempt to reset the latch without restarting.** The latch exists
because the in-memory chain state and the file may have diverged after a
partial write; acking further records into an unverifiable chain would silently
lose audit data. A restart re-scans and re-establishes a known-good chain head.

---

## Hash-chain log rotation — NEVER use `copytruncate`

The OCSF audit JSONL file is a **hash-chained** append log: each record's
`prev_hash` field is the SHA-256 of the exact bytes of the immediately preceding
line (including its trailing newline). This chain is what lets `auditgate.Verify`
detect tampering or truncation.

**`copytruncate` breaks the chain.** logrotate's `copytruncate` directive copies
the live file, then truncates it in place. Between the copy and the truncate,
new records appended by the daemon go into the original (now truncated) file;
those records are lost, and the copy ends at a point that is no longer the
actual chain head. The daemon's in-memory `prevLineHash` still refers to the
last record it wrote (which landed after the copy), so the next record's
`prev_hash` will not match the copy's tail — the chain is broken.

**Correct rotation procedure:**

```sh
# 1. Stop the daemon (drains in-flight ops, runs erase-before-reuse).
systemctl stop ocu-filestored

# 2. Rotate the file (move/rename while the daemon is not running).
mv /var/log/ocu-filestore/audit.ocsf.jsonl \
   /var/log/ocu-filestore/audit.ocsf.jsonl.$(date +%Y%m%d)

# 3. Restart the daemon (NewFileSink creates a fresh chain from genesis).
systemctl start ocu-filestored
```

Or with logrotate (use `create` not `copytruncate`, with `prerotate`/`postrotate`):

```
/var/log/ocu-filestore/audit.ocsf.jsonl {
    daily
    rotate 90
    compress
    missingok
    notifempty
    create 0600 ocufilestore ocufilestore
    prerotate
        systemctl stop ocu-filestored
    endscript
    postrotate
        systemctl start ocu-filestored
    endscript
}
```

**Never use `copytruncate`** for this sink. The chain is what makes the audit
verifiable.

---

## Hash-chain verification

The `auditgate.Verify` function (available as a library call, not exposed as a
CLI flag in the current release) walks the JSONL file and recomputes the hash
chain from genesis. It returns:

- `nil` for a missing or empty file.
- `nil` for an intact chain (every `prev_hash` matches).
- An error naming the broken line number on any tamper or truncation.

The offline-scope limitation: the most recent record is not protected by the
chain alone (no successor records its hash). Removing or mutating the final
complete line is undetectable by `Verify` alone. Closing that window requires
anchoring the chain head externally; that is full-shelf scope.

---

## Health and metrics endpoints

The ops listener (default `127.0.0.1:9464`, controlled by `-ops-listen`) serves
three endpoints. Only GET and HEAD are accepted; any other method returns 405.

### `/healthz` — liveness

Returns `200 ok` whenever the process is serving, regardless of the audit-latch
state or engine health. A process that responds to `/healthz` is alive; it may
or may not be ready to serve operations.

Use `/healthz` for container liveness probes (detecting a dead process) and
`/readyz` for traffic-gating (detecting an operationally degraded process).

### `/readyz` — readiness

Returns `200 ok` only when all readiness probes pass. If any probe fails,
returns `503` with a plain-text body listing the failing probe names (one per
line).

Registered probes:

| Probe name | Failure condition |
|---|---|
| `audit_latch` | The audit sink has latched (permanent write failure) |
| `engine_root` | The local-volume engine root directory is unlistable |

A `503` on `/readyz` means the broker is running but 100% of file operations
will be denied until the underlying problem is resolved.

### `/metrics` — Prometheus text exposition

Returns the metric set in Prometheus text format (content-type
`text/plain; version=0.0.4`). Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `ops_total{op,outcome,deny_class}` | Counter | File operations dispatched, by operation name, outcome (`allow`/`deny`), and deny class |
| `stage_latency_seconds{stage}` | Histogram | Latency of the three dispatch stages: `audit_mandate`, `engine`, `authz` |
| `peer_accepted_total` | Counter | Connections admitted through the peer-cred accept gate |
| `peer_dropped_total` | Counter | Connections rejected at the peer-cred accept gate |
| `ceilings_in_flight_bytes` | Gauge | Current in-flight bytes for the active session |
| `ceilings_fd_in_use` | Gauge | Current open file descriptor count for the active session |
| `ceilings_ops_tokens` | Gauge | Current ops token-bucket level |
| `audit_sink_latched` | Gauge | `1` when the audit sink is latched (broker in 100%-deny mode); `0` when healthy |
| `build_info{version}` | Gauge (always 1) | Build identity |

### Kubernetes probe configuration example

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9464
    host: 127.0.0.1
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /readyz
    port: 9464
    host: 127.0.0.1
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Self-probe healthcheck (container / systemd)

The binary itself implements a self-probe mode via `-health-check`. It dials
`-ops-listen /healthz` and exits 0 (alive) or non-zero (unreachable). The
Dockerfile and `deploy/docker-compose.yml` use this mode because the
distroless image has no shell or `curl`:

```
HEALTHCHECK CMD ["/usr/local/bin/ocu-filestored", "-health-check"]
```

---

## sd_notify integration

When `NOTIFY_SOCKET` is set (i.e., managed by systemd with `Type=notify`), the
daemon sends:

- `READY=1` — after the south face begins accepting connections.
- `STOPPING=1` — immediately on receiving `SIGTERM`/`SIGINT`, before the drain.

If `NOTIFY_SOCKET` is not set the calls are no-ops; the daemon does not fail on
a missing notify socket. Use `Type=notify` in the systemd unit
(`contrib/systemd/ocu-filestored.service`) to take advantage of this.

---

## Structured logging

The daemon writes JSON lines to **stderr** via `log/slog`. Key log fields:

| Field | Values / notes |
|-------|---------------|
| `level` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `msg` | Human-readable event description |
| `scope` | The session `filesystem_id` |
| `reason` | Machine-readable deny or warning class |
| `err` | Error string (never a credential byte or payload) |

Log level is controlled by `-log-level` (default `info`). Set `debug` for
verbose operation (paths appear at `debug` level only; payloads are never
logged at any level).

**Credential redaction:** credential bytes are never emitted in any log line.
The S3 credential file *path* may appear at INFO in the startup echo; the file
contents never do.

---

## Credential intake

Backend credentials for the S3 engine are ingested through one of two
authorized paths — **never as a flag value** (flag values appear in `/proc`
command-line listings):

1. **Credential file** (`-s3-credential-file`): a regular file with mode
   exactly `0600`, owned by the daemon's uid, holding two lines:
   ```
   access_key_id=AKIAEXAMPLE
   secret_access_key=wJalrXUtnFEMI/K7MDENG
   ```
   Any defect (wrong mode, symbolic link, wrong owner, malformed content)
   refuses startup with a typed error; there is no fall-through to the
   environment.

2. **Environment variables** (when no credential file is set):
   `OCU_S3_ACCESS_KEY_ID` and `OCU_S3_SECRET_ACCESS_KEY`. Both must be
   non-empty; if either is absent, startup refuses.

These two env vars are **not** in the generic `OCU_FILESTORE_*` fallback map;
they are handled directly by `internal/objectstore`.

This static credential is the **engine's own backend credential** (NFR-SEC-25),
distinct from the guest's filestore credential. The guest credential is minted
by the Control plane, validated/stripped/exchanged (RFC 8693) and injected by
the Egress edge, and arrives on the request's `Authorization: Bearer` header;
the service forwards it to the engine unmodified and signs nothing (invariant 3),
and the engine enforces `filesystem_id` scope on it. See
[docs/engines.md](engines.md) for details.
