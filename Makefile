# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Local development gate — mirrors CI verbatim.
#
# Every target runs the same commands that .github/workflows/go.yml and e2e.yml
# run; `make check` is the one-command pre-push gate.  Where CI uses
# actions/setup-go the equivalent is the host Go toolchain, so the Go version
# must match go.mod — which is why GO_VERSION below is READ FROM go.mod rather
# than hardcoded (no number to drift out of sync).
#
# Prerequisites: Go >= 1.26, GNU make (or compatible POSIX make), Docker
# (required only for make e2e-linux and make s3-rig-up).

# Go version — derived from the `go` directive in go.mod so it can never drift
# from the single source of truth. `:=` evaluates the shell once at parse time.
# The `goversion-guard` target (wired into `check`) re-asserts this equality as
# a backstop in case someone re-hardcodes a literal here later.
GO_VERSION := $(shell awk '/^go /{print $$2; exit}' go.mod)

# Staticcheck version pinned in CI (go.yml install step).
STATICCHECK_VERSION := 2026.1

# Coverage floor (matches the awk assertion in go.yml).
COVERAGE_FLOOR := 86.0

# Container runtime for make e2e-linux.  Default runc; set RUNTIME=runsc to run
# the same slice on the gVisor sandbox runtime (the second real-substrate leg).
RUNTIME ?= runc

.PHONY: help build bin test test-race cover spdx contract identity vet fmt \
        staticcheck goversion-guard check e2e-linux s3-rig-up s3-rig-down

# ── help ────────────────────────────────────────────────────────────────────

help: ## Print this target list
	@printf '\nUsage:  make <target>\n\n'
	@printf '  %-20s  %s\n' build       "CGO_ENABLED=0 go build ./..."
	@printf '  %-20s  %s\n' bin         "Build the daemon into build/ocu-filestored (gitignored)"
	@printf '  %-20s  %s\n' test        "go test ./...  (live-S3/e2e legs loud-skip without rig env vars)"
	@printf '  %-20s  %s\n' test-race   "go test -race ./..."
	@printf '  %-20s  %s\n' cover       "Coverage floor ($(COVERAGE_FLOOR)%%) over ./internal/..."
	@printf '  %-20s  %s\n' fmt         "gofmt -l . (fails if any file is unformatted)"
	@printf '  %-20s  %s\n' vet         "go vet ./..."
	@printf '  %-20s  %s\n' staticcheck "staticcheck ./..."
	@printf '  %-20s  %s\n' spdx        "scripts/check-spdx.sh"
	@printf '  %-20s  %s\n' contract    "scripts/check-contract-identity.sh"
	@printf '  %-20s  %s\n' identity    "scripts/check-doc-identity.sh"
	@printf '  %-20s  %s\n' check       "Full local gate: fmt+vet+staticcheck+spdx+contract+identity+test"
	@printf '  %-20s  %s\n' e2e-linux   "REST/TLS live e2e in a Linux container (RUNTIME=runc|runsc)"
	@printf '  %-20s  %s\n' s3-rig-up   "Bring up the MinIO test rig (docker-compose.test.yml)"
	@printf '  %-20s  %s\n' s3-rig-down "Tear down the MinIO test rig"
	@echo

# ── build ───────────────────────────────────────────────────────────────────

build: ## Build all packages (static, no cgo) — mirrors e2e.yml build-broker step
	CGO_ENABLED=0 go build ./...

bin: ## Build the daemon into build/ocu-filestored (gitignored — never the repo root)
	mkdir -p build
	CGO_ENABLED=0 go build -trimpath -o build/ocu-filestored ./cmd/ocu-filestored

# ── test ────────────────────────────────────────────────────────────────────
#
# Live-S3 leg: without the rig env vars the S3 conformance and live e2e legs
# loud-skip (t.Skip with a message naming the missing variable).  Set:
#
#   OCU_S3_TEST_ENDPOINT         e.g. http://127.0.0.1:9000
#   OCU_S3_TEST_BUCKET           e.g. ocu-conformance
#   OCU_S3_TEST_VERSIONED_BUCKET e.g. ocu-conformance-versioned
#   OCU_S3_TEST_ACCESS_KEY       e.g. ocu-test-root
#   OCU_S3_TEST_SECRET_KEY       (keep out of shell history; export from a file)
#
# E2e leg: OCU_BROKER_BIN must point to the static daemon binary.  Build it
# first with `make bin`, which writes build/ocu-filestored (a gitignored dir),
# then export OCU_BROKER_BIN=$(PWD)/build/ocu-filestored.  Building into build/
# keeps the daemon out of the repo root so a local build never litters the tree.
# Without OCU_BROKER_BIN the Integration|E2E slice loud-skips.
#
# Use `make s3-rig-up` to bring up the MinIO test rig, then run `make test`.

test: ## go test ./... (live legs loud-skip without rig env vars / OCU_BROKER_BIN)
	go test ./...

test-race: ## go test -race ./... — mirrors go.yml race job
	go test -race ./... -timeout 600s

# ── cover ───────────────────────────────────────────────────────────────────
#
# Mirrors go.yml coverage job exactly.  Set the S3 rig env vars (above) to
# include the live-S3 leg in the coverage measurement, matching CI behaviour.
# The floor is $(COVERAGE_FLOOR)%.

cover: ## Collect coverage over ./internal/... and enforce the floor
	go test -coverpkg=./internal/... -coverprofile=cover.out ./internal/... -timeout 600s -count=1
	@go tool cover -func=cover.out | awk '/^total:/ {gsub(/%/,"",$3); t=$$3} \
	  END { \
	    f=$(COVERAGE_FLOOR)+0; \
	    if (t+0 < f) { \
	      printf "FAIL: go internal coverage %.1f%% below floor %.1f%%\n", t, f; exit 1 \
	    } \
	    printf "OK:   go internal coverage %.1f%% >= floor %.1f%%\n", t, f \
	  }'

# ── linters ─────────────────────────────────────────────────────────────────

fmt: ## gofmt -l . — fails if any file is unformatted (mirrors go.yml gofmt job)
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
	  echo "gofmt found unformatted files:"; \
	  echo "$$unformatted"; \
	  exit 1; \
	fi; \
	echo "gofmt clean"

vet: ## go vet ./... — mirrors go.yml vet job
	go vet ./...

staticcheck: ## staticcheck ./... — pinned to $(STATICCHECK_VERSION), matching CI
	@if ! command -v staticcheck >/dev/null 2>&1; then \
	  echo "staticcheck not found — install with:"; \
	  echo "  go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)"; \
	  exit 1; \
	fi
	staticcheck ./...

# ── checks ───────────────────────────────────────────────────────────────────

spdx: ## Assert SPDX FSL-1.1-Apache-2.0 header on all in-scope source files
	bash scripts/check-spdx.sh

contract: ## Assert vendored contract is byte-identical to the canon (skips if canon absent)
	bash scripts/check-contract-identity.sh

identity: ## Assert no retired maintainer address in tracked files
	bash scripts/check-doc-identity.sh

# ── check (one-command pre-push gate) ────────────────────────────────────────
#
# Runs every gate that CI runs on a PR, in dependency order.
# Notable exclusions (because they need external services or elevated perms):
#   - live-S3 leg (needs rig env vars — run `make s3-rig-up` first)
#   - e2e binary slice (needs OCU_BROKER_BIN)
#   - gitleaks / trufflehog / semgrep / trivy (CI-side tools)
# Those exclusions match CI's own gating model: the plain `test` job also
# loud-skips the gated legs.

check: goversion-guard fmt vet staticcheck spdx contract identity test ## Full local gate (pre-push)

# ── go version drift guard ───────────────────────────────────────────────────
#
# Cross-check the TWO independent copies of the Go toolchain version that live
# in the tree: the `go` directive in go.mod (canonical for the host/CI build)
# and the `golang:<tag>` builder image pinned in the Dockerfile (the container
# build). go.mod's value is also what GO_VERSION derives from, so comparing
# GO_VERSION against go.mod would be vacuous (both sides are the same read).
# This target instead reads each file independently and fails loudly if the two
# disagree — so bumping go.mod without bumping the Dockerfile base (or vice
# versa) exits 1. Wired into `check` and into CI (.github/workflows/go.yml) so
# the drift cannot reach a merge.
goversion-guard: ## Cross-check the go.mod `go` directive against the Dockerfile golang tag
	@gomod=$$(awk '/^go /{print $$2; exit}' go.mod); \
	docker=$$(sed -nE 's/.*golang:([0-9]+\.[0-9]+(\.[0-9]+)?)@sha256:.*/\1/p' Dockerfile | head -n1); \
	if [ -z "$$gomod" ]; then \
	  echo "::error::goversion-guard: could not read the 'go' directive from go.mod"; \
	  exit 1; \
	fi; \
	if [ -z "$$docker" ]; then \
	  echo "::error::goversion-guard: could not read the golang:<tag> base image from Dockerfile"; \
	  exit 1; \
	fi; \
	if [ "$$gomod" != "$$docker" ]; then \
	  echo "::error::Go version drift: go.mod has $$gomod but Dockerfile pins golang:$$docker"; \
	  exit 1; \
	fi; \
	echo "goversion-guard ok: go.mod and Dockerfile both pin Go $$gomod"

# ── containerised REST/TLS e2e ───────────────────────────────────────────────
#
# The broker E2E live slice drives the REAL ocu-filestored daemon over its
# production TLS HTTPS/HTTP-2 REST listener (no unix socket, no peer-credential
# syscall).  The test self-provisions a throwaway loopback TLS certificate
# in-process and hands it to the daemon via -tls-cert/-tls-key, so this target
# only builds the binary and points OCU_BROKER_BIN at it — it provides no certs.
#
# Running it inside a Linux container builds a matching ELF and exercises the
# daemon under a real container runtime.  The container copies the source tree
# (bind-mounted read-only), builds the static daemon binary, sets OCU_BROKER_BIN,
# then runs `go test -run E2E ./internal/broker/`.  The S3 env vars are forwarded
# when present so the S3 conformance leg also runs if the MinIO rig is up
# (rig reachable over --network host on a Linux substrate).
#
# RUNTIME selects the container runtime: runc (default) or runsc (gVisor).  The
# target passes --runtime=$(RUNTIME) and honors the ambient docker context, so
# it works through `limactl shell` or a Lima docker-context without a hardcoded
# path.  The two real-substrate legs are:
#
#   limactl shell ocu-linux -- make e2e-linux                # runc
#   limactl shell ocu-linux -- make e2e-linux RUNTIME=runsc  # gVisor (runsc)
#
# Usage:
#   make e2e-linux
#   make e2e-linux RUNTIME=runsc
#   make s3-rig-up && make e2e-linux   # includes the live S3 leg

e2e-linux: ## Run the REST/TLS live e2e in a Linux container (RUNTIME=runc|runsc)
	@echo "--- building the broker binary inside the Linux container ---"
	docker run --rm \
	  --runtime=$(RUNTIME) \
	  --network host \
	  --volume "$(CURDIR):/src:ro" \
	  --workdir /workspace \
	  $(if $(OCU_S3_TEST_ENDPOINT),--env OCU_S3_TEST_ENDPOINT=$(OCU_S3_TEST_ENDPOINT),) \
	  $(if $(OCU_S3_TEST_BUCKET),--env OCU_S3_TEST_BUCKET=$(OCU_S3_TEST_BUCKET),) \
	  $(if $(OCU_S3_TEST_VERSIONED_BUCKET),--env OCU_S3_TEST_VERSIONED_BUCKET=$(OCU_S3_TEST_VERSIONED_BUCKET),) \
	  $(if $(OCU_S3_TEST_ACCESS_KEY),--env OCU_S3_TEST_ACCESS_KEY=$(OCU_S3_TEST_ACCESS_KEY),) \
	  $(if $(OCU_S3_TEST_SECRET_KEY),--env OCU_S3_TEST_SECRET_KEY=$(OCU_S3_TEST_SECRET_KEY),) \
	  $(if $(OCU_E2E_ENGINE),--env OCU_E2E_ENGINE=$(OCU_E2E_ENGINE),) \
	  golang:$(GO_VERSION) \
	  sh -euc '\
	    cp -a /src /workspace/repo && \
	    cd /workspace/repo && \
	    CGO_ENABLED=0 go build -trimpath -o /workspace/ocu-filestored ./cmd/ocu-filestored && \
	    OCU_BROKER_BIN=/workspace/ocu-filestored \
	      go test -run E2E ./internal/broker/ -v -timeout 600s \
	  '

# ── MinIO rig helpers ─────────────────────────────────────────────────────────

s3-rig-up: ## Bring up the MinIO test rig (deploy/docker-compose.test.yml)
	docker compose -f deploy/docker-compose.test.yml up -d --wait minio
	docker compose -f deploy/docker-compose.test.yml run --rm bucket-init

s3-rig-down: ## Tear down the MinIO test rig
	docker compose -f deploy/docker-compose.test.yml down -v
