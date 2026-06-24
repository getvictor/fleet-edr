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

# A pinned stable version token. The literal placeholder vX.Y.Z (in bootstrap.sh's warning) is not matched, and an rc
# suffix is never written into the docs because TAG is validated as stable above.
VERSION_RE='v[0-9]+\.[0-9]+\.[0-9]+'

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

rc=0
for f in "${FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "error: missing $f" >&2
    exit 2
  fi
  tmp=$(mktemp)
  sed -E "s|${VERSION_RE}|${TAG}|g" "$f" >"$tmp"
  if cmp -s "$f" "$tmp"; then
    rm -f "$tmp"
    continue
  fi
  if [[ "$CHECK" == 1 ]]; then
    echo "::error::$f pins a release tag other than $TAG:"
    diff "$f" "$tmp" || true
    rm -f "$tmp"
    rc=1
  else
    diff "$f" "$tmp" | grep -E '^[<>]' || true
    mv "$tmp" "$f"
    echo "bumped $f"
  fi
done

if [[ "$CHECK" == 1 && "$rc" -ne 0 ]]; then
  echo "Run tools/bump-doc-versions.sh $TAG to fix." >&2
fi
exit "$rc"
