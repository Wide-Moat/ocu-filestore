# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Assert every vendored contract copy has not drifted from the canonical
# architecture-repo source. The canonical contracts live in the
# Wide-Moat/open-computer-use repository under contracts/ (storage/ schemas and
# openapi/ specs); this repo vendors byte-identical copies so the Go parity test
# (and any future embed) always builds against the pinned wire surface.
#
# The canon is a SEPARATE repository, so this check runs wherever a checkout
# is reachable (set OCU_CANON_DIR, default ../open-computer-use) and skips
# with a notice where it is not (CI without the sibling checkout). The
# in-repo gate that always runs is the Go contract-parity test; this script
# is the sync alarm for the vendored copies themselves.
set -euo pipefail

cd "$(dirname "$0")/.."

readonly CANON_DIR="${OCU_CANON_DIR:-../open-computer-use}"

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

# Resolve the canon side once: probe the first declared contract to decide
# whether a canon checkout is present at all.
readonly CANON_PROBE="$CANON_DIR/contracts/${CONTRACTS[0]}"
if [ ! -f "$CANON_PROBE" ]; then
  # An explicitly named canon dir that lacks the schema is an error (CI
  # checks the canon out and must never skip-pass); only the implicit
  # local-default path may be absent (developer machine without the
  # sibling checkout).
  if [ -n "${OCU_CANON_DIR:-}" ]; then
    echo "::error::OCU_CANON_DIR is set but $CANON_PROBE is missing"
    exit 1
  fi
  echo "::notice::canon checkout not present ($CANON_PROBE); skipping identity check"
  exit 0
fi

drift=0
for name in "${CONTRACTS[@]}"; do
  canon="$CANON_DIR/contracts/$name"
  vendored="contracts/$name"
  if [ ! -f "$canon" ]; then
    echo "::error::declared contract '$name' is missing from the canon ($canon)"
    drift=1
    continue
  fi
  if [ ! -f "$vendored" ]; then
    echo "::error::declared contract '$name' is not vendored in this repo ($vendored)"
    drift=1
    continue
  fi
  if ! cmp -- "$canon" "$vendored"; then
    echo "::error::vendored contract drifted: $vendored != $canon"
    drift=1
  fi
done

if [ "$drift" -ne 0 ]; then
  echo "Re-vendor the canonical schema; the contract changes in the architecture repo first." >&2
  exit 1
fi

echo "all vendored contracts are byte-identical to the canon"
