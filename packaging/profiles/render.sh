#!/bin/sh
# Substitute __TEAM_ID__ in each .mobileconfig.tmpl and lint the result.
#
# The rendered profiles ship UNSIGNED on purpose. The system-extension and TCC
# payloads are MDM-only, every supported MDM channel (Fleet, Jamf, Kandji,
# Intune, mosyle) signs profiles itself at delivery time, and Fleet rejects a
# pre-signed upload outright. Download authenticity is covered by the cosign
# signatures the release workflow attaches to every artifact, not by a CMS
# wrapper on the profile.
#
# spec:release-packaging/mobile-configuration-profiles-ship-alongside-the-package/profiles-are-rendered-unsigned
#
# Outputs:
#   dist/edr-system-extension.mobileconfig
#   dist/edr-tcc-fda.mobileconfig
#
# Required env:
#   APPLE_TEAM_ID    bake into the template

set -eu

: "${APPLE_TEAM_ID:?missing}"

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DIST="$ROOT/dist"
TEMPLATES="$ROOT/packaging/profiles"
mkdir -p "$DIST"

for tmpl in edr-system-extension edr-tcc-fda; do
    SRC="$TEMPLATES/$tmpl.mobileconfig.tmpl"
    OUT="$DIST/$tmpl.mobileconfig"

    echo "==> rendering $tmpl"
    # Escape sed-replacement metacharacters so an unexpected APPLE_TEAM_ID
    # value (containing /, &, or \) fails loudly at plutil -lint instead of
    # silently emitting corrupted XML.
    escaped_team_id=$(printf '%s' "$APPLE_TEAM_ID" | sed 's/[&/\\]/\\&/g')
    sed "s/__TEAM_ID__/$escaped_team_id/g" "$SRC" > "$OUT"
    plutil -lint "$OUT"
done

ls -la "$DIST"/*.mobileconfig
