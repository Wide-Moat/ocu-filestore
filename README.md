<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# ocu-filestore

The storage broker of Open Computer Use (component-04): the host-side daemon
that custodies the backend object-store credential and resolves file
authorization for the guest session mount — so neither the guest nor any
upstream component ever holds a backend key.

Architecture and specifications live in
[`Wide-Moat/open-computer-use`](https://github.com/Wide-Moat/open-computer-use):
the component spec (`docs/architecture/components/04-storage-broker.md`),
storage ADRs 0010 (pluggable backend engine) and 0011 (storage egress lane),
and the three frozen wire contracts under `contracts/storage/`. This repo
implements them.

## Status

**Pre-release — south-face-first, single-tenant shelf. Not yet v1.0.**

What is complete and operational:

- South face: per-session Unix-socket server with `SO_PEERCRED` peer-credential
  enforcement (Linux only; see [Platform notes](#platform-notes)).
- Two backend engines: **local-volume** (host filesystem, no network leg) and
  **S3** (network engine, storage-lane enforced, MinIO/Ceph RGW compatible).
- Three-axis authorization resolver: scope × intent × `downloadable`,
  deny-by-default, re-derived per request.
- Fail-closed hash-chained audit sink (OCSF File System Activity): an
  audit-write failure permanently latches the broker into 100%-deny until
  restart.
- Graceful shutdown: `SIGTERM`/`SIGINT` → bounded 25s drain →
  erase-before-reuse teardown (`NFR-SEC-54`) → socket removal.
- Structured JSON logging (`slog`, to stderr), ops listener
  (`127.0.0.1:9464`) with `/metrics`, `/healthz`, `/readyz`, `sd_notify`
  (`READY=1`/`STOPPING=1`), and `x-request-id` correlation.
- Container packaging: multi-arch Dockerfile (distroless/nonroot), one-click
  `deploy/docker-compose.yml` solo deployment.
- Full CI gate: secrets scan, naming denylist, SAST, SCA, race detector,
  conventional-commits, 86 % coverage floor.
- Supply chain: SHA-pinned actions, SBOM, keyless `cosign` signing and SLSA
  build provenance on tagged releases, Dependabot, `govulncheck`.

What is not yet in scope:

- **North face** (data-plane HTTP API, SPA, preview): parsed but inert; not
  bound in any release. Deferred per the roadmap.
- Multi-tenant admission: the current shelf admits `trusted_operator` /
  `single-tenant` / `host_local_long_lived` or `sts_per_session` only.
- Kubernetes deployment examples and a shipped seccomp profile.
- First tagged release: the signing/SBOM/provenance jobs are wired but run on
  the first `v*` tag, not yet cut.

## Shape

One process, two faces, one credential:

| Face | Caller | Contract |
|---|---|---|
| South | Session sandbox (guest mount, via [`ocu-rclone-filestore`](https://github.com/Wide-Moat/ocu-rclone-filestore)) | `file-ops.schema.json` + `mount-config.schema.json` |
| North | External data-plane client (file/artifact HTTP API) | `file-artifact-api.schema.json` — **deferred** |

Both faces share one three-axis authorization resolver and one object-store
client — the only component that speaks the backend protocol. The platform is
an ephemeral workspace: after a session ends the bytes live in the customer's
own store; OCU keeps the audit record, not the files.

## Platform notes

The south face's peer-credential gate uses `SO_PEERCRED`, a **Linux-only**
socket option. On macOS (darwin) the Unix-socket tests skip with an explicit
message; use `make e2e-linux` to run the full slice in a container. See
[docs/testing.md](docs/testing.md) for details.

## Quick start — one-click solo (local-volume engine)

```sh
# Clone the repo, then from the repo root:
docker compose -f deploy/docker-compose.yml up -d --build
```

The compose file starts the broker on the local-volume engine with conservative
defaults. Tune the required per-session values via environment variables before
starting:

```sh
OCU_FILESYSTEM_ID=my-session-001      # required: host-attested scope ID
OCU_BROKER_MAX_FILE_SIZE=1073741824   # required: max file size in bytes (1 GiB default)
OCU_GRANTED_INTENTS=read,write        # default; add "preview" if needed
docker compose -f deploy/docker-compose.yml up -d --build
```

Stop cleanly (drains in-flight ops, erases the workspace):

```sh
docker compose -f deploy/docker-compose.yml stop
```

`stop_grace_period` is 30 s — above the daemon's 25 s drain bound — so
`docker compose stop` always lets erase-before-reuse complete before SIGKILL.

## Building locally

```sh
go build ./...                          # compile check
make check                              # full local gate (fmt, vet, test, ...)
CGO_ENABLED=0 go build -trimpath \
    -o ocu-filestored ./cmd/ocu-filestored
```

See the [Makefile](Makefile) for all targets and [docs/testing.md](docs/testing.md)
for the full test guide including the MinIO rig and the darwin escape hatch.

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture/README.md](docs/architecture/README.md) | Architecture entry point: the broker as component-04, the 10 invariants, the whole-system diagram, and the reading order over the 7 area design docs |
| [docs/operations.md](docs/operations.md) | Operator runbook: full flag/env table, exit codes, signal contract, audit-latch recovery, log-rotation rules |
| [docs/engines.md](docs/engines.md) | Local-volume vs S3 engine selection, IAM policy, MinIO/RGW path-style, storage-lane requirement |
| [docs/configuration.md](docs/configuration.md) | Flag → environment variable reference (complete mapping table) |
| [docs/testing.md](docs/testing.md) | Test suite guide, MinIO rig, darwin escape hatch, coverage floor |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure, in-scope classes, response SLAs |
| [contrib/systemd/ocu-filestored.service](contrib/systemd/ocu-filestored.service) | Hardened systemd unit (Type=notify, ProtectSystem=strict, …) |

## Sibling repos

- [`ocu-sandbox`](https://github.com/Wide-Moat/ocu-sandbox) — sandbox executor + control plane
- [`ocu-rclone-filestore`](https://github.com/Wide-Moat/ocu-rclone-filestore) — guest-side mount binary (rclone-based)

## License

FSL-1.1-Apache-2.0 — see [LICENSE](./LICENSE). Each release converts to
Apache-2.0 two years after publication. `LICENSE-APACHE` / `LICENSE-MIT` are
dependency reference texts, not the license of this Software.
