#!/usr/bin/env bash
# Fail if any tracked text file contains an em dash (U+2014) or en dash (U+2013).
#
# Why: the repo's style forbids em dashes in prose, comments, and user-facing strings (see CLAUDE.md). Use ": " or " - "
# (a spaced ASCII hyphen) instead. This gate keeps them from creeping back into docs, Go/Swift/TS source, rule Doc()
# strings (which render on the UI rule pages and in docs/detection-rules.md), and CI/workflow prose.
#
# The dash characters are built with printf from their UTF-8 bytes so this script's own source stays ASCII and does not
# trip the check. Run via `task lint:dashes`; the CI gate lives in .github/workflows/no-emdash.yml.
set -euo pipefail

EM_DASH=$(printf '\xe2\x80\x94') # U+2014
EN_DASH=$(printf '\xe2\x80\x93') # U+2013
PATTERN="${EM_DASH}|${EN_DASH}"

# Tracked files only. gitignored paths (node_modules, dist, tmp/, ai/) are absent from git ls-files already. grep -I drops
# binary files. This script is skipped explicitly (defensive; it is ASCII-only, but never scan the scanner). NUL-delimited
# (ls-files -z + read -d '') so filenames with spaces, quotes, or non-ASCII bytes are read verbatim, not Git-quoted.
found=0
while IFS= read -r -d '' f; do
  case "$f" in
    # Never scan the scanner (defensive; it is ASCII-only). .claude/** is AI-tool-installed config we do not author
    # (markdownlint ignores it for the same reason), so it is out of scope for this gate.
    tools/lint-no-emdash.sh | .claude/*) continue ;;
  esac
  if grep -HInE "$PATTERN" -- "$f" 2>/dev/null; then
    found=1
  fi
done < <(git ls-files -z)

if [ "$found" -ne 0 ]; then
  echo "::error::Em dash (U+2014) or en dash (U+2013) found above. Replace with ': ' or ' - ' (a spaced ASCII hyphen)." >&2
  exit 1
fi

echo "no em/en dashes in tracked files"
