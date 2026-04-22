#!/bin/sh
# Substitute __TEAM_ID__ in each .mobileconfig.tmpl, then sign the resulting
# .mobileconfig with the Developer ID Installer cert so MDM and `profiles
# install` don't flag them as unsigned.
#
# Outputs:
#   dist/edr-system-extension.mobileconfig
#   dist/edr-tcc-fda.mobileconfig
#
# Required env:
#   APPLE_TEAM_ID                   bake into the template
# Required for signing (skip signing via --dry-run to just render):
#   CI_KEYCHAIN                     temp keychain with the installer cert

set -eu

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
fi

: "${APPLE_TEAM_ID:?missing}"

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DIST="$ROOT/dist"
TEMPLATES="$ROOT/packaging/profiles"
mkdir -p "$DIST"

INSTALLER_IDENTITY="Developer ID Installer: VICTOR LYUBOSLAVSKY ($APPLE_TEAM_ID)"
KEYCHAIN_ARG=""
if [ -n "${CI_KEYCHAIN:-}" ]; then
    KEYCHAIN_ARG="$CI_KEYCHAIN"
fi

for tmpl in edr-system-extension edr-tcc-fda; do
    SRC="$TEMPLATES/$tmpl.mobileconfig.tmpl"
    RENDERED="$DIST/$tmpl.rendered.mobileconfig"
    OUT="$DIST/$tmpl.mobileconfig"

    echo "==> rendering $tmpl"
    sed "s/__TEAM_ID__/$APPLE_TEAM_ID/g" "$SRC" > "$RENDERED"
    plutil -lint "$RENDERED"

    if [ "$DRY_RUN" -eq 1 ]; then
        mv "$RENDERED" "$OUT"
        echo "   dry-run: $OUT (unsigned)"
        continue
    fi

    echo "==> signing $tmpl"
    if [ -n "$KEYCHAIN_ARG" ]; then
        /usr/bin/security cms -S -N "$INSTALLER_IDENTITY" \
            -k "$KEYCHAIN_ARG" \
            -i "$RENDERED" \
            -o "$OUT"
    else
        /usr/bin/security cms -S -N "$INSTALLER_IDENTITY" \
            -i "$RENDERED" \
            -o "$OUT"
    fi
    rm -f "$RENDERED"

    echo "==> verifying $OUT"
    /usr/bin/security cms -D -i "$OUT" > /dev/null
done

ls -la "$DIST"/*.mobileconfig
