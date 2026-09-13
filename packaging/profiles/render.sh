#!/bin/sh
# Substitute __TEAM_ID__ in each .mobileconfig.tmpl and lint the result.
#
# The rendered profiles ship UNSIGNED on purpose. The system-extension, TCC and
# managed login items payloads are MDM-only, every supported MDM channel (Fleet, Jamf, Kandji,
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
#   dist/edr-login-items.mobileconfig
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

for tmpl in edr-system-extension edr-tcc-fda edr-login-items; do
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

# spec:release-packaging/mobile-configuration-profiles-ship-alongside-the-package/the-background-items-profile-manages-the-team-s-items
#
# The background items profile manages items by ONE TeamIdentifier rule for the team. plutil -lint accepts a profile whose rule
# names another type or team, and that profile would install and manage nothing, so the rule is read back from the rendered file.
LOGIN_ITEMS="$DIST/edr-login-items.mobileconfig"
rule_type=$(plutil -extract PayloadContent.0.Rules.0.RuleType raw -o - "$LOGIN_ITEMS")
rule_value=$(plutil -extract PayloadContent.0.Rules.0.RuleValue raw -o - "$LOGIN_ITEMS")
rule_count=$(plutil -extract PayloadContent.0.Rules raw -o - "$LOGIN_ITEMS")
if [ "$rule_type" != "TeamIdentifier" ] || [ "$rule_value" != "$APPLE_TEAM_ID" ] || [ "$rule_count" != "1" ]; then
    echo "error: $LOGIN_ITEMS must carry exactly one TeamIdentifier rule for $APPLE_TEAM_ID;" \
        "got $rule_count rule(s), first $rule_type $rule_value" >&2
    exit 1
fi

ls -la "$DIST"/*.mobileconfig
