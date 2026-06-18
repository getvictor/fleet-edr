#!/usr/bin/env bash
# Fail if any tracked text file contains an em dash (U+2014) or en dash (U+2013).
#
# Why: the repo's style forbids em dashes in prose, comments, and user-facing strings (see CLAUDE.md). Reword the sentence
# (prefer shorter sentences) or use a colon instead; the spaced ASCII hyphen " - " is also banned (tools/dash-lint catches
# that one). This gate keeps the dash characters from creeping back into docs, Go/Swift/TS source, rule Doc() strings (which
# render on the UI rule pages and in docs/detection-rules.md), and CI/workflow prose.
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

# scan_file greps one file, setting found=1 on a hit. Skips the scanner itself (defensive; it is ASCII-only) and
# .claude/** (AI-tool-installed config we do not author; markdownlint ignores it for the same reason). grep -I drops
# binary files so a staged PNG passed by the pre-commit hook is a no-op rather than a false match.
scan_file() {
  local file="$1"
  case "$file" in
    tools/lint-no-emdash.sh | .claude/*) return 0 ;;
    *) ;; # every other path is scanned below
  esac
  if grep -HInE "$PATTERN" -- "$file" 2>/dev/null; then
    found=1
  fi
}

# With file arguments, scan exactly those: the lefthook pre-commit hook passes the staged file list so a commit is gated
# without rescanning the whole tree. With no arguments, scan every tracked text file: the behaviour the CI gate and
# `task lint:dashes` rely on. NUL-delimited read of git ls-files so filenames with spaces are handled verbatim.
if [[ "$#" -gt 0 ]]; then
  for f in "$@"; do
    [[ -f "$f" ]] || continue # staged deletions / non-regular paths
    scan_file "$f"
  done
else
  while IFS= read -r -d '' f; do
    scan_file "$f"
  done < <(git ls-files -z)
fi

if [[ "$found" -ne 0 ]]; then
  echo "::error::Em dash (U+2014) or en dash (U+2013) found above. Reword the sentence (prefer shorter sentences) or use ':'. The spaced hyphen ' - ' is also banned (see tools/dash-lint)." >&2
  exit 1
fi

echo "no em/en dashes found"
