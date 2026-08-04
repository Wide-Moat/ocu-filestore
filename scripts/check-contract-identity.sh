# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Assert every vendored contract copy has not drifted from the canonical
# architecture-repo source. The canonical contracts live in the
# Wide-Moat/open-computer-use repository under contracts/ (storage/ schemas and
# openapi/ specs); this repo vendors byte-identical copies so the Go parity test
# (and any future embed) always builds against the pinned wire surface.
#
# The comparison side is the canon COMMIT pinned by the canon checkout step in
# .github/workflows/go.yml (the single source of truth), never whatever branch
# a canon working copy happens to have checked out. The vendored contracts
# track the canon next/v1 line, which a canon checkout sitting on its main
# line does not carry, so a loose-file read against such a checkout would
# false-negative every entry. Therefore a git canon MUST contain the pinned
# commit (fetch the canon next/v1 line if it does not) and is read with
# git show at that commit; loose-file reads serve only a non-git canon export.
#
# The canon is a SEPARATE repository, so this check runs wherever a checkout
# is reachable (set OCU_CANON_DIR, default ../open-computer-use) and skips
# with a notice where it is not (developer machine without the sibling
# checkout). The in-repo gate that always runs is the Go contract-parity test;
# this script is the sync alarm for the vendored copies themselves.
set -euo pipefail

cd "$(dirname "$0")/.."

readonly CANON_DIR="${OCU_CANON_DIR:-../open-computer-use}"
readonly PIN_FILE=".github/workflows/go.yml"

# The declared set of vendored contracts, by path RELATIVE TO contracts/ on both
# sides (the subdir is part of the entry, so storage/ schemas and openapi/ specs
# both fit one list). Add an entry here when a contract is vendored; the loop
# below fails loud if a declared path is missing from EITHER the canon or this
# repo, so the set cannot silently fall out of sync with what is actually
# vendored.
readonly -a CONTRACTS=(
  'storage/file-ops.schema.json'
  'storage/file-artifact-api.schema.json'
  'openapi/files-api.openapi.yaml'
)

# Locate the canon pin: exactly one full-SHA `ref:` line must exist in the CI
# canon checkout step. Zero or several is a loud failure, never a silent
# fall-through to a branch-dependent worktree read.
pin_count=$(grep -cE '^[[:space:]]*ref:[[:space:]]*[0-9a-f]{40}[[:space:]]*$' "$PIN_FILE" || true)
if [ "$pin_count" -ne 1 ]; then
  echo "::error::cannot locate canon pin: want exactly one full-SHA 'ref:' line in $PIN_FILE, found $pin_count"
  exit 1
fi
CANON_SHA=$(grep -E '^[[:space:]]*ref:[[:space:]]*[0-9a-f]{40}[[:space:]]*$' "$PIN_FILE" | grep -oE '[0-9a-f]{40}')
readonly CANON_SHA

# Resolve the canon side. Absent entirely: an explicitly named canon dir is an
# error (CI checks the canon out and must never skip-pass); only the implicit
# local default may be absent (developer machine without the sibling checkout).
if [ ! -e "$CANON_DIR" ]; then
  if [ -n "${OCU_CANON_DIR:-}" ]; then
    echo "::error::OCU_CANON_DIR is set but $CANON_DIR does not exist"
    exit 1
  fi
  echo "::notice::canon checkout not present ($CANON_DIR); skipping identity check"
  exit 0
fi

if git -C "$CANON_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  # Git canon: compare against the pinned commit's tree, immune to whichever
  # branch the working copy has checked out. A git canon that LACKS the pinned
  # commit is a hard failure, never a fall-through to loose files: a main-only
  # clone falling through to its worktree is exactly the branch-dependent
  # false negative this pinned read exists to kill.
  if ! git -C "$CANON_DIR" cat-file -e "${CANON_SHA}^{commit}" 2>/dev/null; then
    echo "::error::canon checkout $CANON_DIR lacks pinned contracts commit $CANON_SHA -- fetch the canon next/v1 line"
    exit 1
  fi
  canon_mode="git"
else
  canon_mode="worktree"
  if [ ! -f "$CANON_DIR/contracts/${CONTRACTS[0]}" ]; then
    if [ -n "${OCU_CANON_DIR:-}" ]; then
      echo "::error::OCU_CANON_DIR is set but $CANON_DIR/contracts/${CONTRACTS[0]} is missing"
      exit 1
    fi
    echo "::notice::canon contracts not present ($CANON_DIR); skipping identity check"
    exit 0
  fi
fi

canon_has() {
  if [ "$canon_mode" = git ]; then
    git -C "$CANON_DIR" cat-file -e "$CANON_SHA:contracts/$1" 2>/dev/null
  else
    [ -f "$CANON_DIR/contracts/$1" ]
  fi
}

canon_read() {
  if [ "$canon_mode" = git ]; then
    git -C "$CANON_DIR" show "$CANON_SHA:contracts/$1"
  else
    cat "$CANON_DIR/contracts/$1"
  fi
}

drift=0
for name in "${CONTRACTS[@]}"; do
  vendored="contracts/$name"
  if ! canon_has "$name"; then
    echo "::error::declared contract '$name' is missing from the canon ($CANON_DIR, $canon_mode read at ${CANON_SHA})"
    drift=1
    continue
  fi
  if [ ! -f "$vendored" ]; then
    echo "::error::declared contract '$name' is not vendored in this repo ($vendored)"
    drift=1
    continue
  fi
  if ! canon_read "$name" | cmp -- - "$vendored"; then
    echo "::error::vendored contract drifted: $vendored != canon contracts/$name"
    drift=1
  fi
done

if [ "$drift" -ne 0 ]; then
  echo "Re-vendor the canonical schema; the contract changes in the architecture repo first." >&2
  exit 1
fi

if [ "$canon_mode" = git ]; then
  echo "all vendored contracts are byte-identical to the canon at pinned $CANON_SHA"
else
  echo "all vendored contracts are byte-identical to the canon worktree"
fi
