# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Assert BIDIRECTIONAL consistency between the PENDING-PHASE-7 code markers and
# the docs/pending-phase7.md ledger:
#
#   1. every PENDING-PHASE-7(<id>) marker in a git-tracked Go source file names
#      an <id> that has a matching row in the ledger (no UNDOCUMENTED
#      assumption — a marker against an id the ledger never defined);
#   2. every <id> the ledger defines is referenced by at least one code marker
#      (no ORPHAN ledger row — an assumption that no code actually depends on).
#
# These five-plus assumptions are sibling-proven and frozen pending the #292
# canon merge; the marker convention (docs/pending-phase7.md) is the audit trail
# that ties each line of code touching one of them back to its ledger row. This
# gate keeps that trail honest: a marker can never drift away from the ledger,
# and the ledger can never carry a row no code exercises.
#
# The ledger ids are extracted from the ledger's id-table rows ONLY (a row of the
# form `| `<id>` | ... |`), so prose backtick-spans (vocabulary tokens, code
# symbols, status codes) are never mistaken for ids. The code markers are
# extracted from git-tracked *.go files so an untracked/ignored build tree is
# never scanned.
#
# Exit non-zero on any mismatch (an undocumented marker OR an orphan ledger row).
set -euo pipefail

cd "$(dirname "$0")/.."

readonly LEDGER='docs/pending-phase7.md'

if [ ! -f "$LEDGER" ]; then
  echo "::error::pending-phase-7 ledger not found: $LEDGER" >&2
  exit 1
fi

# --- ledger ids: the leading backtick token of each id-table row ---------------
# An id-table row looks like:  | `A1-route`         | <assumption text> |
# Match only rows whose FIRST cell is a single backtick-wrapped id; this excludes
# every prose backtick-span elsewhere in the doc.
ledger_ids="$(
  grep -oE '^\| *`[A-Za-z0-9_-]+` *\|' "$LEDGER" \
    | grep -oE '`[A-Za-z0-9_-]+`' \
    | tr -d '`' \
    | sort -u
)"

if [ -z "$ledger_ids" ]; then
  echo "::error::no PENDING-PHASE-7 ids found in the ledger id table ($LEDGER)" >&2
  exit 1
fi

# --- code marker ids: PENDING-PHASE-7(<id>) in git-tracked Go source -----------
# The data-plane handlers, the router, the deny writer, the credscope source, and
# the fixtures/live oracle all carry markers; scanning git-tracked *.go files
# covers production AND the parity oracle without touching ignored trees.
marker_ids="$(
  git ls-files '*.go' \
    | xargs grep -hoE 'PENDING-PHASE-7\([A-Za-z0-9_-]+\)' 2>/dev/null \
    | sed -E 's/^PENDING-PHASE-7\(([A-Za-z0-9_-]+)\)$/\1/' \
    | sort -u
)"

if [ -z "$marker_ids" ]; then
  echo "::error::no PENDING-PHASE-7(<id>) markers found in any git-tracked Go source" >&2
  exit 1
fi

# --- bidirectional comparison --------------------------------------------------
# undocumented: a code marker id with NO ledger row.
undocumented="$(comm -23 <(printf '%s\n' "$marker_ids") <(printf '%s\n' "$ledger_ids"))"
# orphan: a ledger id NO code marker references.
orphan="$(comm -13 <(printf '%s\n' "$marker_ids") <(printf '%s\n' "$ledger_ids"))"

status=0

if [ -n "$undocumented" ]; then
  status=1
  while IFS= read -r id; do
    [ -z "$id" ] && continue
    printf '::error::undocumented PENDING-PHASE-7 marker: %s has no row in %s\n' "$id" "$LEDGER"
    # Name the file(s) carrying the offending marker so the fix is one grep away.
    git ls-files '*.go' \
      | xargs grep -lE "PENDING-PHASE-7\\(${id}\\)" 2>/dev/null \
      | sed 's/^/    marker in: /' >&2 || true
  done <<< "$undocumented"
fi

if [ -n "$orphan" ]; then
  status=1
  while IFS= read -r id; do
    [ -z "$id" ] && continue
    printf '::error::orphan PENDING-PHASE-7 ledger row: %s is defined in %s but no code marker references it\n' "$id" "$LEDGER"
  done <<< "$orphan"
fi

if [ "$status" -ne 0 ]; then
  echo "PENDING-PHASE-7 markers and the ledger have drifted (see errors above)." >&2
  echo "Every marker must have a ledger row, and every ledger row must have a marker." >&2
  exit 1
fi

count="$(printf '%s\n' "$ledger_ids" | grep -c .)"
echo "PENDING-PHASE-7 markers and ledger are consistent: ${count} ids, bidirectionally matched"
