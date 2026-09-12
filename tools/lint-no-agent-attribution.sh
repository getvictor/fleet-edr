#!/usr/bin/env bash
# Fail if a commit message credits an AI agent as an author or carries an agent's session marker.
#
# Why: this repo's commits are authored by the people who own them. An agent that helped write a change is a tool, like an editor
# or a compiler, and tools do not take authorship credit. A `Co-Authored-By:` trailer naming an agent also pollutes GitHub's
# contributor graph and `git shortlog`, which are read as statements about who maintains the project.
#
# This is NOT a ban on the Co-Authored-By trailer. Real co-authors are legitimate and dependabot's own merges carry one, so only
# trailers naming an agent are refused.
#
# Two entry points, because the two ways a commit reaches main need different checks:
#   msg <file>    a single commit-message file, for the local commit-msg hook
#   range <base>..<head>   every commit in a range, for CI
#
# The range form is the one that matters most: the offending commits this gate was written for were SQUASH MERGES composed by
# GitHub from a PR body, which never pass through a local hook at all.
set -euo pipefail

# Patterns are built so this script's own source does not match them, which would make the scanner unable to live in the repo it
# scans. Each is assembled from fragments rather than written out whole.
CO_AUTHOR="Co-[Aa]uthored-[Bb]y:.*(""Claude""|""Anthropic""|noreply@anthropic\.com)"
SESSION="^""Claude""-Session:"
GENERATED="Generated with \[""Claude"" Code\]"
PATTERN="${CO_AUTHOR}|${SESSION}|${GENERATED}"

fail() {
  echo "error: commit message credits an AI agent" >&2
  echo >&2
  printf '%s\n' "$1" | sed 's/^/    /' >&2
  echo >&2
  echo "This repo does not list agents as authors. Remove the trailer and commit again." >&2
  echo "If Claude Code is adding it automatically, set \"includeCoAuthoredBy\": false in .claude/settings.json." >&2
  exit 1
}

case "${1:-}" in
  msg)
    file="${2:?usage: $0 msg <commit-message-file>}"
    # Strip the comment block git appends to the template; it is not part of the message.
    body=$(grep -v '^#' "$file" || true)
    offending=$(printf '%s\n' "$body" | grep -nE "$PATTERN" || true)
    # An `if` rather than `[ ... ] && fail`: as the last statement in the branch, a false test would be the script's exit status
    # under `set -e`, so a CLEAN message would report failure. That inversion is exactly the bug a gate must not have.
    if [ -n "$offending" ]; then
      fail "$offending"
    fi
    ;;
  range)
    range="${2:?usage: $0 range <base>..<head>}"
    found=0
    while read -r sha; do
      [ -z "$sha" ] && continue
      offending=$(git log -1 --format='%B' "$sha" | grep -nE "$PATTERN" || true)
      if [ -n "$offending" ]; then
        found=1
        echo "  $(git log -1 --format='%h %s' "$sha")" >&2
        printf '%s\n' "$offending" | sed 's/^/      /' >&2
      fi
    done < <(git rev-list "$range")
    if [ "$found" -ne 0 ]; then
      echo >&2
      echo "error: the commits above credit an AI agent; this repo does not list agents as authors" >&2
      exit 1
    fi
    ;;
  *)
    echo "usage: $0 msg <commit-message-file> | $0 range <base>..<head>" >&2
    exit 2
    ;;
esac
