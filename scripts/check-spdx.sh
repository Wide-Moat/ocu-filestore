# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Assert every in-scope source file carries the SPDX FSL-1.1-Apache-2.0 header
# within its first three lines.
#
# Scope is the set of git-tracked files (so untracked/ignored build trees are
# never scanned). In scope by extension: .go, .sh, and .yml under
# .github/workflows/. The contracts/ JSON carries its own $comment SPDX and is
# checked by the contract-identity script, not here.
#
# The SPDX token is matched as a fixed string; comment lines are never
# bare-counted.
set -euo pipefail

cd "$(dirname "$0")/.."

readonly TOKEN='SPDX-License-Identifier: FSL-1.1-Apache-2.0'

misses=()

while IFS= read -r file; do
  if ! head -n 3 "$file" | grep -qF -- "$TOKEN"; then
    misses+=("$file")
  fi
done < <(git ls-files '*.go' '*.sh' '.github/workflows/*.yml')

if [ "${#misses[@]}" -gt 0 ]; then
  printf '::error::missing SPDX header (%s): %s\n' "$TOKEN" "${misses[@]}"
  echo "Add the SPDX FSL-1.1-Apache-2.0 header to the files above (see CLAUDE.md)." >&2
  exit 1
fi

echo "SPDX header present on all in-scope source files"
