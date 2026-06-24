#!/usr/bin/env bash
# Bump (or verify) the pinned release tag in the operator deploy docs.
#
# Usage:
#   tools/bump-doc-versions.sh vX.Y.Z            rewrite the pinned tag in place, printing every change
#   tools/bump-doc-versions.sh --check vX.Y.Z    exit nonzero if any file still differs from vX.Y.Z
#
# The files below carry a pinned, copy-paste deploy tag and must reference ONLY the current release. Historical or
# upgrade-path version mentions belong in CHANGELOG.md, not here, because this script rewrites every vMAJOR.MINOR.PATCH
# token in these files wholesale. README.md is intentionally absent: it is the evergreen landing page and stays
# version-free. The demo (docker-compose.demo.yml) floats to :latest and is never bumped. See docs/doc-versioning.md.
set -euo pipefail

FILES=(
  docs/quickstart-vm.md
  docs/install-server.md
  docs/install-agent-manual.md
  docs/mdm-deployment.md
  docs/fleet-deployment.md
  bootstrap.sh
)

CHECK=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK=1
  shift
fi

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
  echo "usage: $0 [--check] vX.Y.Z" >&2
  exit 2
fi
if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: tag must be a stable release of the form vX.Y.Z (got '$TAG')" >&2
  exit 2
fi

# A pinned version token: vMAJOR.MINOR.PATCH with an optional -prerelease suffix. The optional suffix is anchored to a
# leading hyphen so it matches v1.2.3-rc.1 (normalizing it to the stable TAG) without eating a trailing .pkg / .json
# extension on filenames like fleet-edr-v1.2.3.pkg. The literal placeholder vX.Y.Z (in bootstrap.sh's warning) is not
# matched, and TAG itself is validated as a stable release above, so no suffix is ever written into the docs.
VERSION_RE='v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?'

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

# Each target's temp file is created alongside the target itself, so the final mv is an atomic same-filesystem rename.
# A trap cleans up the in-flight temp on any exit, including an early `set -e` abort mid-loop.
tmp=""
trap 'rm -f "$tmp" || true' EXIT

rc=0
for f in "${FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "error: missing $f" >&2
    exit 2
  fi
  tmp=$(mktemp "$f.bump.XXXXXX")
  sed -E "s|${VERSION_RE}|${TAG}|g" "$f" >"$tmp"
  if cmp -s "$f" "$tmp"; then
    rm -f "$tmp"; tmp=""
    continue
  fi
  if [[ "$CHECK" == 1 ]]; then
    echo "::error::$f pins a release tag other than $TAG:"
    diff "$f" "$tmp" || true
    rm -f "$tmp"; tmp=""
    rc=1
  else
    diff "$f" "$tmp" | grep -E '^[<>]' || true
    # Match the destination's mode on the temp, then atomically rename over it: this preserves bootstrap.sh's executable
    # bit (a bare mv imposes the temp's default mode) and avoids a non-atomic truncate-then-write that an interrupt
    # could leave half-written. GNU stat uses -c; BSD/macOS stat uses -f.
    chmod "$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f")" "$tmp"
    mv "$tmp" "$f"; tmp=""
    echo "bumped $f"
  fi
done

if [[ "$CHECK" == 1 && "$rc" -ne 0 ]]; then
  echo "Run tools/bump-doc-versions.sh $TAG to fix." >&2
fi
exit "$rc"
