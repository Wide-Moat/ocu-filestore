# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Assert the vendored contract copy has not drifted from the canonical
# architecture-repo source. The canonical file-ops contract lives in the
# Wide-Moat/open-computer-use repository under contracts/storage/; this repo
# vendors a byte-identical copy so the Go parity test (and any future embed)
# always builds against the pinned wire surface.
#
# The canon is a SEPARATE repository, so this check runs wherever a checkout
# is reachable (set OCU_CANON_DIR, default ../open-computer-use) and skips
# with a notice where it is not (CI without the sibling checkout). The
# in-repo gate that always runs is the Go contract-parity test; this script
# is the sync alarm for the vendored copy itself.
set -euo pipefail

cd "$(dirname "$0")/.."

readonly CANON_DIR="${OCU_CANON_DIR:-../open-computer-use}"
readonly CANON_SCHEMA="$CANON_DIR/contracts/storage/file-ops.schema.json"
readonly VENDORED_SCHEMA='contracts/storage/file-ops.schema.json'

if [ ! -f "$CANON_SCHEMA" ]; then
  # An explicitly named canon dir that lacks the schema is an error (CI
  # checks the canon out and must never skip-pass); only the implicit
  # local-default path may be absent (developer machine without the
  # sibling checkout).
  if [ -n "${OCU_CANON_DIR:-}" ]; then
    echo "::error::OCU_CANON_DIR is set but $CANON_SCHEMA is missing"
    exit 1
  fi
  echo "::notice::canon checkout not present ($CANON_SCHEMA); skipping identity check"
  exit 0
fi

if ! cmp -- "$CANON_SCHEMA" "$VENDORED_SCHEMA"; then
  echo "::error::vendored contract drifted: $VENDORED_SCHEMA != $CANON_SCHEMA"
  echo "Re-vendor the canonical schema; the contract changes in the architecture repo first." >&2
  exit 1
fi

echo "vendored contract is byte-identical to the canon"
