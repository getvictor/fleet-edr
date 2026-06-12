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

# Apple Team IDs are exactly 10 characters of A-Z / 0-9. Reject anything else
# before rendering: a malformed value can pass plutil -lint (it only checks
# XML validity) yet embed a team id that never matches in the payload's
# AllowedSystemExtensions keys and CodeRequirement strings, producing a
# profile that installs but silently approves nothing.
if ! printf '%s' "$APPLE_TEAM_ID" | grep -qE '^[A-Z0-9]{10}$'; then
    echo "error: APPLE_TEAM_ID must be a 10-character Apple Team ID (A-Z, 0-9); got '$APPLE_TEAM_ID'" >&2
    exit 1
fi

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DIST="$ROOT/dist"
TEMPLATES="$ROOT/packaging/profiles"
mkdir -p "$DIST"

for tmpl in edr-system-extension edr-tcc-fda; do
    SRC="$TEMPLATES/$tmpl.mobileconfig.tmpl"
    OUT="$DIST/$tmpl.mobileconfig"

    echo "==> rendering $tmpl"
    # Defense-in-depth behind the format guard above: escape sed-replacement
    # metacharacters so even a future loosening of the guard cannot emit
    # corrupted XML.
    escaped_team_id=$(printf '%s' "$APPLE_TEAM_ID" | sed 's/[&/\\]/\\&/g')
    sed "s/__TEAM_ID__/$escaped_team_id/g" "$SRC" > "$OUT"
    plutil -lint "$OUT"
done

ls -la "$DIST"/*.mobileconfig
