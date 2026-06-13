<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# ocu-filestored configuration reference

`ocu-filestored` reads its configuration from command-line flags.
Every flag (except credential-bearing ones — see below) also accepts a
corresponding `OCU_FILESTORE_*` environment variable as a fallback when the
flag is absent from the command line.

## Precedence rule

> **Explicit flag > environment variable > built-in default**

When a flag is provided on the command line it always wins, regardless of any
environment variable. The environment variable is consulted only when the flag
was not passed. A malformed environment-variable value produces the same typed
error as a malformed flag value.

## Flag → environment-variable mapping

| Flag | Environment variable | Type | Default | Description |
|------|---------------------|------|---------|-------------|
| `-audit-sink` | `OCU_FILESTORE_AUDIT_SINK` | string | _(required)_ | Fail-closed audit gate file-sink path (NFR-SEC-79) |
| `-broker-max-file-size` | `OCU_FILESTORE_BROKER_MAX_FILE_SIZE` | int64 | _(required)_ | Whole-object upload ceiling in bytes (> 0) |
| `-ca-bundle` | `OCU_FILESTORE_CA_BUNDLE` | string | `` | PEM bundle appended to the system cert pool for the storage-lane proxy CA (requires `-storage-lane`) |
| `-downloadable-prefixes` | `OCU_FILESTORE_DOWNLOADABLE_PREFIXES` | string | `` | Comma-separated broker-side downloadable prefixes (NFR-SEC-73) |
| `-engine` | `OCU_FILESTORE_ENGINE` | string | `local-volume` | Backend object-store engine: `local-volume` or `s3` (ADR-0010) |
| `-engine-root` | `OCU_FILESTORE_ENGINE_ROOT` | string | _(required for local-volume)_ | Local-volume engine root directory |
| `-filesystem-id` | `OCU_FILESTORE_FILESYSTEM_ID` | string | _(required)_ | Host-attested filesystem scope ID |
| `-granted-intents` | `OCU_FILESTORE_GRANTED_INTENTS` | string | `read,write` | Comma-separated session intent grant set: `read`, `write`, `preview` |
| `-health-check` | `OCU_FILESTORE_HEALTH_CHECK` | bool | `false` | Self-probe mode: dial `-ops-listen /healthz` and exit 0 (alive) or non-zero |
| `-log-level` | `OCU_FILESTORE_LOG_LEVEL` | string | `info` | Structured log level: `debug`, `info`, `warn`, `error` |
| `-max-request-bytes` | `OCU_FILESTORE_MAX_REQUEST_BYTES` | int64 | `52428800` | Per-RPC-message inbound body ceiling in bytes (NFR-SEC-78); default 50 MiB |
| `-north-listen` | `OCU_FILESTORE_NORTH_LISTEN` | string | `127.0.0.1:7080` | North-face file/UI ingress bind address (parsed but inert in this release) |
| `-ops-burst` | `OCU_FILESTORE_OPS_BURST` | float64 | `200` | Per-session ops token-bucket capacity in tokens (>= 1) |
| `-ops-listen` | `OCU_FILESTORE_OPS_LISTEN` | string | `127.0.0.1:9464` | Loopback-only bind address for the ops listener (`/metrics`); empty disables |
| `-ops-per-second` | `OCU_FILESTORE_OPS_PER_SECOND` | float64 | `100` | Per-session ops token-bucket refill rate in ops/s (> 0) |
| `-profile` | `OCU_FILESTORE_PROFILE` | string | `trusted_operator` | Admission profile: `trusted_operator`, `internal_workforce`, `untrusted` |
| `-s3-bucket` | `OCU_FILESTORE_S3_BUCKET` | string | _(required for s3)_ | Backend S3 bucket |
| `-s3-endpoint` | `OCU_FILESTORE_S3_ENDPOINT` | string | _(required for s3)_ | Backend S3 endpoint URL |
| `-s3-path-style` | `OCU_FILESTORE_S3_PATH_STYLE` | bool | `false` | Path-style S3 addressing (required by most single-host S3-compatible backends) |
| `-s3-region` | `OCU_FILESTORE_S3_REGION` | string | `us-east-1` | S3 engine signing region |
| `-s3-sts-endpoint` | `OCU_FILESTORE_S3_STS_ENDPOINT` | string | `` | STS endpoint override for S3-compatible rigs (requires `-s3-sts-role-arn`) |
| `-s3-sts-role-arn` | `OCU_FILESTORE_S3_STS_ROLE_ARN` | string | `` | IAM role ARN for STS-per-session credential kind |
| `-south-socket-dir` | `OCU_FILESTORE_SOUTH_SOCKET_DIR` | string | `/run/ocu-filestore/sessions` | Host-owned 0700 directory for per-session unix sockets |
| `-storage-lane` | `OCU_FILESTORE_STORAGE_LANE` | string | `` | Storage egress lane proxy URL (ADR-0011, NFR-SEC-16/85); required for `-engine s3` in production |
| `-storage-lane-dev-direct` | `OCU_FILESTORE_STORAGE_LANE_DEV_DIRECT` | bool | `false` | **Dev rigs only** — dial the S3 backend without the storage lane; never set in production |
| `-tenancy` | `OCU_FILESTORE_TENANCY` | string | `single-tenant` | Tenancy mode: `single-tenant`, `multi-tenant` |
| `-version` | `OCU_FILESTORE_VERSION` | bool | `false` | Print the build identity and exit 0 |

## Credential-bearing flags — excluded from the generic env map

The following flags are **excluded** from the `OCU_FILESTORE_*` generic
environment-variable mapping. Each has a dedicated, security-audited intake
path that must remain the only route for credential material:

| Flag | Why excluded | Authorized intake |
|------|-------------|-------------------|
| `-s3-credential-file` | Carries the path to a 0600-permission daemon-owned credential file. A generic env alias could be confused with the per-value credential env vars (`OCU_S3_ACCESS_KEY_ID` / `OCU_S3_SECRET_ACCESS_KEY`) and would create a second, less-audited path to the same secrets. | Set the file path via the flag directly, or supply credential bytes via `OCU_S3_ACCESS_KEY_ID` and `OCU_S3_SECRET_ACCESS_KEY` (handled inside `internal/objectstore`). |

The raw S3 access-key-id and secret-access-key travel only through the
`internal/objectstore` package's dedicated `OCU_S3_ACCESS_KEY_ID` /
`OCU_S3_SECRET_ACCESS_KEY` env vars — never through flags or the generic
`OCU_FILESTORE_*` map. Credential values are never logged (only the
credential file *path* may appear in logs at INFO level).

## Example: systemd drop-in using env vars

```ini
# /etc/systemd/system/ocu-filestored.service.d/site.conf
[Service]
Environment=OCU_FILESTORE_ENGINE=local-volume
Environment=OCU_FILESTORE_ENGINE_ROOT=/var/lib/ocu-filestore/data
Environment=OCU_FILESTORE_AUDIT_SINK=/var/log/ocu-filestore/audit.jsonl
Environment=OCU_FILESTORE_FILESYSTEM_ID=fs-prod-01
Environment=OCU_FILESTORE_BROKER_MAX_FILE_SIZE=5368709120
Environment=OCU_FILESTORE_SOUTH_SOCKET_DIR=/run/ocu-filestore/sessions
Environment=OCU_FILESTORE_LOG_LEVEL=info
Environment=OCU_FILESTORE_OPS_LISTEN=127.0.0.1:9464
```

Flags on the `ExecStart=` line take precedence over any `Environment=` line,
so a site-wide drop-in can be selectively overridden per instance.

## Contact

Questions or security reports: developer@widemoat.ai
