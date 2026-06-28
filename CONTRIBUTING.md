# Contributing to ocu-filestore

Thank you for your interest in contributing. This document describes the
real gates every contribution must clear, the workflow to follow, and the
local commands that mirror CI exactly.

Questions or help: **developer@widemoat.ai**

---

## Quick orientation

`ocu-filestore` is the storage broker of Open Computer Use (component-04):
the host-side daemon that custodies the backend object-store credential and
enforces file authorization for the guest session. Architecture decisions
live in [`Wide-Moat/open-computer-use`](https://github.com/Wide-Moat/open-computer-use)
under `docs/architecture/`. If a decision must change, it changes there
first — never by unilateral code change here.

---

## License

This project is licensed under **FSL-1.1-Apache-2.0**. Two years after each
release the license converts automatically to Apache-2.0. See [LICENSE](./LICENSE).

### Required SPDX header on every new source file

Every new source file must begin with a two-line SPDX header, using the
comment syntax of the language:

```
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
```

For Go files use `//` comments; for shell scripts and Make use `#`; for
HTML/XML use `<!-- -->`. The CI `checks / SPDX header presence` job
(`scripts/check-spdx.sh`) fails the PR if the header is absent from any
in-scope file. Run `make spdx` locally to verify before pushing.

---

## Workflow

1. **Branch off `main`** — create a focused branch for your change.
2. **One PR per logical change** — do not bundle unrelated work.
3. **Tests in the same PR** — new code ships with tests; the coverage floor
   is a ratchet (see [Coverage floor](#coverage-floor-ratchet)). PRs that
   lower coverage are rejected.
4. **No merge without review** — a maintainer must approve before merge.
5. **No force-push to `main`** — the branch is protected.

---

## Commit format

This project uses [Conventional Commits](https://www.conventionalcommits.org/).
The CI `security / conventional-commits` job checks every PR title against
the spec (types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`,
`perf`, `style`).

Every commit message must end with the Co-Authored-By trailer exactly as
shown:

```
feat(authz): add three-axis resolver cache

Short prose body explaining why, not what.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
```

Include the `Co-Authored-By` line when the commit was produced with AI
assistance. If it was not, omit it.

---

## Writing discipline

- **English only** — all code, comments, commit messages, PR titles and
  descriptions, and documentation. No exceptions.
- **Documentation standard** — prose docs (package READMEs, architecture
  pages, wire references) follow [docs/documentation-standard.md](docs/documentation-standard.md):
  name code by identifier rather than line coordinate, let structure earn its
  shape, and state each fact once.
- **Project's own words** — state facts as this project knows them. Do not
  name any third-party system or upstream project as the origin of a
  behaviour, design choice, or implementation detail. Cite public open-source
  repositories by their public GitHub URL when relevant; do not attribute
  design provenance to proprietary or unpublished sources.
- **Naming denylist** — the CI `security / lexicon` job greps the committed
  tree against a maintained denylist of terms that must not appear. The
  denylist itself is kept outside the public tree (it is a repository secret).
  If your PR fails the lexicon gate, the CI output will show the file and
  line number but not the denied term itself — contact a maintainer for
  guidance.

---

## Running the gates locally

`make check` is the one-command pre-push gate. It mirrors every job the CI
`go` workflow runs on a pull request:

```sh
make check
# runs: fmt + vet + staticcheck + lint + spdx + contract + identity + test
```

Individual targets:

| Target | What it runs | CI job |
|---|---|---|
| `make fmt` | `gofmt -l .` (fails if unformatted) | `go / gofmt` |
| `make vet` | `go vet ./...` | `go / vet` |
| `make staticcheck` | `staticcheck ./...` @ `2026.1` | `go / staticcheck` |
| `make lint` | `golangci-lint run` (`.golangci.yml`) | `go / golangci` |
| `make mutation` | go-gremlins mutation test (advisory) on the pure-logic packages | `mutation / gremlins` |
| `make test` | `go test ./...` | `go / test` |
| `make test-race` | `go test -race ./... -timeout 600s` | `go / race` |
| `make cover` | Coverage over `./internal/...`, floor enforced | `go / coverage` |
| `make spdx` | SPDX header check | `go / checks / SPDX header presence` |
| `make contract` | Vendored contract identity check | `go / checks / vendored contract identity` |
| `make identity` | Maintainer identity check | `go / checks / maintainer identity` |
| `make e2e-linux` | Linux-only e2e in a container (darwin escape hatch) | `e2e / e2e` |
| `make s3-rig-up` | Start MinIO test rig | needed for live-S3 legs |

Prerequisites: Go >= 1.26 (match `go.mod`), GNU make, Docker (for
`e2e-linux` and the MinIO rig).

Install the two pinned linters once:

```sh
go install honnef.co/go/tools/cmd/staticcheck@2026.1
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
```

`golangci-lint` (`.golangci.yml`) is the structural meta-linter: beyond the
single-purpose `go / vet` and `go / staticcheck` gates it runs the security and
correctness set this daemon needs — `gosec`, `errorlint`, `bodyclose`, and
peers. Its config-level exclusions are scoped and commented; do not add bare
`//nolint` to source.

### Gated legs that loud-skip without extra setup

Two test legs skip with an explicit message if their prerequisites are absent
— no silent pass, no silent failure:

**Live-S3 leg** — requires a real object-store endpoint. Start the MinIO rig
first:

```sh
make s3-rig-up
export OCU_S3_TEST_ENDPOINT=http://127.0.0.1:9000
export OCU_S3_TEST_BUCKET=ocu-conformance
export OCU_S3_TEST_VERSIONED_BUCKET=ocu-conformance-versioned
export OCU_S3_TEST_ACCESS_KEY=ocu-test-root
export OCU_S3_TEST_SECRET_KEY=ocu-test-secret-key   # keep out of shell history
```

**Real-binary e2e leg** — requires `OCU_BROKER_BIN` to point to a built
daemon binary:

```sh
CGO_ENABLED=0 go build -trimpath -o ocu-filestored ./cmd/ocu-filestored
export OCU_BROKER_BIN=$PWD/ocu-filestored
```

### Platform notes — darwin contributors

The Integration and E2E slices exercise `SO_PEERCRED` peer-credential
enforcement, which is a Linux-only socket option. On darwin those tests
skip with a clear message. Use the containerised escape hatch to run the
full slice:

```sh
make e2e-linux
```

See [docs/testing.md](docs/testing.md) for the full guide, including how to
combine `make e2e-linux` with the MinIO rig.

---

## Coverage floor ratchet

The CI `go / coverage` job measures line coverage over `./internal/...` (the
broker's real logic; `cmd/` is a thin wiring shim and is excluded). The
current floor is **86.0%**.

The floor is a ratchet: it is never lowered. New code ships with tests in
the same PR. When a PR raises measured coverage, the floor in `go.yml` is
raised to `floor(new_measured) - 1`. Do not open a PR that lowers the floor.

Run `make cover` locally to measure coverage and enforce the floor before
pushing. The MinIO rig must be running for the live-S3 leg to count toward
the total, matching CI behaviour.

Property tests on the authz resolver and path containment are mandatory where
the relevant NFR rows name them — not optional extras.

---

## Contract vendoring discipline

The three frozen wire contracts (`contracts/storage/mount-config.schema.json`,
`file-ops.schema.json`, `file-artifact-api.schema.json`) are vendored copies
of the canonical contracts in `Wide-Moat/open-computer-use`. They must be
byte-identical to the canon.

The CI `go / checks / vendored contract identity` job (`scripts/check-contract-identity.sh`)
checks this parity on every PR. Do not hand-edit the vendored contracts. If
the canon changes, update the vendored copies to match exactly and verify
with `make contract`.

Operation names, authorization axes, and the response envelope in these
contracts are pinned. Per-operation bodies marked TBD in the canon stay TBD
here too — never invent a body and code against it.

---

## CI gates summary

Every PR must clear all of the following CI jobs before merge:

| Gate | Workflow / job | Blocks on |
|---|---|---|
| Format | `go / gofmt` | Any unformatted Go file |
| Vet | `go / vet` | `go vet` findings |
| Static analysis | `go / staticcheck` | `staticcheck` findings |
| Meta-linter | `go / golangci` | `golangci-lint` findings (`.golangci.yml`) |
| Unit tests | `go / test` | Any test failure |
| Race detector | `go / race` | Data race detected |
| Coverage floor | `go / coverage` | Coverage below 86.0% over `./internal/...` |
| SPDX header | `go / checks / SPDX header presence` | Missing header on any in-scope source file |
| Maintainer identity | `go / checks / maintainer identity` | Stale address in tracked files |
| Vendored contract | `go / checks / vendored contract identity` | Contract not byte-identical to canon |
| Naming denylist | `security / lexicon` | Denied term found in tree |
| Secrets scan | `security / secrets-gitleaks` | Any secret detected by gitleaks |
| Secrets scan | `security / secrets-trufflehog` | Any secret detected by trufflehog |
| SAST | `security / sast-semgrep` | CRITICAL semgrep finding |
| Dataflow analysis | `codeql / analyze` | CodeQL `security-and-quality` finding on Go |
| SCA | `security / sca-trivy-fs` | CRITICAL trivy finding |
| Conventional commits | `security / conventional-commits` | PR title not in Conventional Commits format |
| Real-binary e2e | `e2e / e2e` | Daemon smoke or Integration/E2E failure |

Additionally, `govulncheck` (`go / govulncheck`) runs on every PR and fails
on known-exploitable vulnerabilities reachable from this module.

The `mutation / gremlins` job (go-gremlins) runs on every PR and on a weekly
cron, scoped to the pure-logic leaf packages (`internal/authz`,
`internal/denyclass`, `internal/ceilings`). It measures assertion strength —
it rewrites covered source and re-runs the suite, so a surviving mutant marks a
line the tests execute but do not assert on, a gap line coverage cannot see. It
is **advisory** (`continue-on-error`): it surfaces the efficacy summary in the
job log but does not block merge yet. The scope lives in `.gremlins.yaml`. Run
`make mutation` locally to reproduce it. The ratchet plan (a threshold floor,
then dropping the advisory flag) is recorded in `.github/workflows/mutation.yml`.

Security workflow jobs also run on a weekly cron schedule against `main`.

---

## Reporting security vulnerabilities

Do not open a public issue for a suspected vulnerability. Use the private
reporting channel described in [SECURITY.md](./SECURITY.md).

---

## Contact

Maintainer: **developer@widemoat.ai**
