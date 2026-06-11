<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# ocu-filestore

The storage broker of Open Computer Use: the host-side service that custodies
the backend object-store credential and resolves file authorization for two
callers — the guest mount and an external data-plane client — so neither ever
holds a backend key.

The architecture and specifications are the source of truth and live in
[`Wide-Moat/open-computer-use`](https://github.com/Wide-Moat/open-computer-use):
the component spec (`docs/architecture/components/04-storage-broker.md`), the
storage ADRs (0010 pluggable backend engine, 0011 storage egress lane), and the
three frozen contracts under `contracts/storage/`. This repo implements them.

## Shape

One process, two faces, one credential:

| Face | Caller | Contract |
|---|---|---|
| South | Session sandbox (guest mount, via [`ocu-rclone-filestore`](https://github.com/Wide-Moat/ocu-rclone-filestore)) | `file-ops.schema.json` + `mount-config.schema.json` |
| North | External data-plane client (file/artifact HTTP API + embeddable SPA + preview) | `file-artifact-api.schema.json` |

Both faces call one three-axis authorization resolver (scope `filesystem_id` ×
intent `read`/`write`/`preview` × `downloadable`, resolved per request,
deny-by-default) and one object-store client — the only component that speaks
the backend protocol and signs every backend request. The backend engine is a
pluggable adapter: a local-volume engine (the solo reference, no network leg)
and an S3 engine, both present from day one.

The platform is an ephemeral workspace, not a durable customer-data store:
after a session ends the bytes live in the customer's own store; OCU keeps the
audit record (OCSF File System Activity, fail-closed), not the files.

## Status

Scaffold: typed seams, sentinels, and doc contracts — no business logic yet.
The build order follows the implementation roadmap in the architecture repo.

## Sibling repos

- [`ocu-sandbox`](https://github.com/Wide-Moat/ocu-sandbox) — sandbox executor + control plane
- [`ocu-rclone-filestore`](https://github.com/Wide-Moat/ocu-rclone-filestore) — guest-side mount binary (rclone-based)

## License

FSL-1.1-Apache-2.0 — see [LICENSE](./LICENSE). Each release converts to
Apache-2.0 two years after publication. `LICENSE-APACHE` / `LICENSE-MIT` are
dependency reference texts, not the license of this Software.
