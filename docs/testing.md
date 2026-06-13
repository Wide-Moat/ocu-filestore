# Testing guide — ocu-filestore

This document explains how to run the test suite locally, which tests skip on
darwin and why, how to use the containerised Linux e2e escape hatch, and the
coverage floor policy.

Questions or issues: developer@widemoat.ai

---

## Quick start

```sh
make check   # full local gate: fmt + vet + staticcheck + spdx + contract + identity + test
```

`make check` mirrors every gate the CI `go` workflow runs on a pull request.
It loud-skips the gated legs (live-S3, real-binary e2e) if the required
environment variables are absent — the skip messages name the missing
variable so you know exactly what to set.

---

## Platform notes — which tests skip on darwin

### SO_PEERCRED (Linux only)

The broker enforces peer-credential authentication on its Unix domain socket
using the `SO_PEERCRED` socket option.  `SO_PEERCRED` is a Linux-only
syscall; it is not available on darwin (macOS) or BSDs.

Any test in the `Integration` or `E2E` slice that exercises the real Unix
socket path calls `t.Skip` on darwin with the message:

```
skip: SO_PEERCRED is Linux-only — run make e2e-linux for the full slice
```

These tests gate merges in CI (Linux runners) and must pass there before any
PR is merged.  Running them on darwin requires the containerised escape hatch
described below.

### Live-S3 leg

The S3 conformance and live e2e tests (`S3Live`, `E2ES3*`) require a real
object-store endpoint.  Without the rig environment variables they call
`t.Skip` with:

```
skip: OCU_S3_TEST_ENDPOINT not set — start the MinIO rig with `make s3-rig-up`
```

---

## Running the full suite locally

### Step 1 — start the MinIO rig (live-S3 leg)

```sh
make s3-rig-up
```

This runs `deploy/docker-compose.test.yml` which starts a local MinIO
instance and creates the required buckets.

### Step 2 — build the broker binary (e2e leg)

```sh
CGO_ENABLED=0 go build -trimpath -o ocu-filestored ./cmd/ocu-filestored
```

### Step 3 — export the rig environment variables

```sh
export OCU_S3_TEST_ENDPOINT=http://127.0.0.1:9000
export OCU_S3_TEST_BUCKET=ocu-conformance
export OCU_S3_TEST_VERSIONED_BUCKET=ocu-conformance-versioned
export OCU_S3_TEST_ACCESS_KEY=ocu-test-root
export OCU_S3_TEST_SECRET_KEY=ocu-test-secret-key   # keep out of shell history
export OCU_BROKER_BIN=$PWD/ocu-filestored
```

### Step 4 — run the suite

```sh
make test        # go test ./...  — all legs, rig env vars forwarded
make test-race   # same under the race detector
make cover       # coverage report + floor assertion (see below)
```

### Tear down the rig

```sh
make s3-rig-down
```

---

## `make e2e-linux` — darwin escape hatch for the SO_PEERCRED slice

Contributors on darwin can run the Linux-only e2e leg without a VM using the
containerised escape hatch:

```sh
make e2e-linux
```

This runs `docker run golang:1.25.0` with the source tree bind-mounted.
Inside the container the build system:

1. Copies the source tree to a writable workspace (the bind-mount is
   read-only so module cache writes succeed).
2. Builds the static daemon binary (`CGO_ENABLED=0 go build -trimpath`) for
   Linux/amd64 inside the container.
3. Sets `OCU_BROKER_BIN` to the freshly-built binary path.
4. Runs `go test -run 'Integration|E2E' ./... -v -timeout 600s`.

The container uses `--network host` so a MinIO rig started with
`make s3-rig-up` is visible inside the container (the S3 env vars are
forwarded when present).  To include the live-S3 e2e leg:

```sh
make s3-rig-up
export OCU_S3_TEST_ENDPOINT=http://127.0.0.1:9000
export OCU_S3_TEST_BUCKET=ocu-conformance
export OCU_S3_TEST_VERSIONED_BUCKET=ocu-conformance-versioned
export OCU_S3_TEST_ACCESS_KEY=ocu-test-root
export OCU_S3_TEST_SECRET_KEY=ocu-test-secret-key
make e2e-linux
```

`--network host` is Linux-native behaviour.  On Docker Desktop for Mac the
host network mode is emulated and `127.0.0.1` inside the container resolves
to the VM loopback, not the Mac's loopback.  If the S3 rig is reachable only
on the Mac's loopback, start it with the host-gateway address exposed, or use
`docker.for.mac.localhost` as the S3 endpoint hostname.

---

## Individual make targets

| Target | Command mirrored from CI | When to use |
|---|---|---|
| `make build` | `CGO_ENABLED=0 go build ./...` | Verify the package compiles |
| `make fmt` | `gofmt -l .` (fail if non-empty) | Before committing |
| `make vet` | `go vet ./...` | Before committing |
| `make staticcheck` | `staticcheck ./...` @ `2026.1` | Before committing |
| `make spdx` | `bash scripts/check-spdx.sh` | After adding a new source file |
| `make contract` | `bash scripts/check-contract-identity.sh` | After touching `contracts/` |
| `make identity` | `bash scripts/check-doc-identity.sh` | After editing docs |
| `make test` | `go test ./...` | Full suite (with rig for live legs) |
| `make test-race` | `go test -race ./... -timeout 600s` | Race detector run |
| `make cover` | `go test -coverpkg=./internal/... -coverprofile=cover.out …` | Coverage measurement |
| `make check` | All of the above combined | Pre-push gate |
| `make e2e-linux` | Containerised `Integration\|E2E` slice | Linux-only e2e on darwin |
| `make s3-rig-up` | `docker compose … up minio + bucket-init` | Start MinIO rig |
| `make s3-rig-down` | `docker compose … down -v` | Stop and clean MinIO rig |

Install `staticcheck` once:

```sh
go install honnef.co/go/tools/cmd/staticcheck@2026.1
```

---

## Coverage floor

The CI `coverage` job collects coverage over the `./internal/...` packages
(the broker's real logic; `cmd/` is a thin wiring shim and is excluded).  The
floor is **86.0%**.

The floor was ratcheted to 86.0 in the daemon-wiring + e2e PR (measured 87.7%
on Linux CI where the live-socket e2e cases run).  It is computed as
`floor(measured) - 1` — one point of headroom, never above measured.

When adding new code:

- Ship tests in the same PR (CLAUDE.md build discipline).
- `make cover` enforces the floor locally so you know before CI runs.
- Do not lower the floor; raise it when coverage improves.

The MinIO rig must be running for the live-S3 tests to count toward the
coverage total, matching CI behaviour.  Without the rig the S3 leg loud-skips
and the measured total will be lower than CI's measurement.

---

## CI workflow mapping

| CI job | Local equivalent |
|---|---|
| `go / gofmt` | `make fmt` |
| `go / vet` | `make vet` |
| `go / staticcheck` | `make staticcheck` |
| `go / test` | `make test` |
| `go / race` | `make test-race` |
| `go / coverage` | `make cover` (with rig running) |
| `go / checks / SPDX header presence` | `make spdx` |
| `go / checks / maintainer identity` | `make identity` |
| `go / checks / vendored contract identity` | `make contract` |
| `e2e / e2e` (Linux Integration\|E2E) | `make e2e-linux` on darwin; native on Linux |
| `e2e / e2e-s3` (S3 leg) | `make s3-rig-up && make e2e-linux` with S3 env vars |

The Makefile mirrors CI commands verbatim; no target invents a command that CI
does not run.
