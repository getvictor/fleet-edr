#!/bin/sh
# shellcheck disable=SC2086
# Build, sign, notarize, and staple the Fleet EDR .pkg.
#
# KEYCHAIN_ARG is deliberately unquoted in invocations so that an empty value
# expands to zero CLI args (when CI_KEYCHAIN is unset). Quoting would pass an
# empty-string arg that most tools misread as a positional.
#
# Usage:
#   packaging/pkg/build.sh <version-tag> [--dry-run]
#
# --dry-run skips real codesign + notarytool steps and uses ad-hoc signing
# (CODE_SIGN_IDENTITY="-"). This lets PR CI on macos-14 runners exercise the
# whole script without the Developer ID secrets; a successful dry-run
# verifies distribution.xml + pkgbuild invocations are syntactically correct
# before a real tag runs the same script with secrets.
#
# Required env for a real build (set via the `release-signing` GitHub
# environment; see packaging/pkg/ci-setup.sh):
#   CI_KEYCHAIN                   path to the ephemeral keychain
#   APPLE_NOTARY_APPLE_ID         Apple ID email
#   APPLE_TEAM_ID                 10-character team ID
#   APPLE_NOTARY_APP_PASSWORD     app-specific password
#
# Artifacts land in dist/:
#   dist/fleet-edr-<tag>.pkg       signed + notarized + stapled

set -eu

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "usage: $0 <version-tag> [--dry-run]" >&2
    exit 2
fi
DRY_RUN=0
if [ "${2:-}" = "--dry-run" ]; then
    DRY_RUN=1
fi

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

TEAM_ID="${APPLE_TEAM_ID:-FDG8Q7N4CC}"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

APP_IDENTITY="Developer ID Application: VICTOR LYUBOSLAVSKY ($TEAM_ID)"
INSTALLER_IDENTITY="Developer ID Installer: VICTOR LYUBOSLAVSKY ($TEAM_ID)"
CODESIGN_FLAGS="--options runtime --timestamp --force"

KEYCHAIN_ARG=""
if [ -n "${CI_KEYCHAIN:-}" ]; then
    KEYCHAIN_ARG="--keychain $CI_KEYCHAIN"
fi

if [ "$DRY_RUN" -eq 1 ]; then
    APP_IDENTITY="-"
    # Ad-hoc signing rejects --options runtime + --timestamp; drop them.
    CODESIGN_FLAGS="--force"
fi

# sign_pkg wraps pkgbuild + productbuild to skip --sign in dry-run mode.
# pkg signing requires a real Developer ID Installer cert; ad-hoc is not
# accepted. `$@` is the tool + its args minus the signing pair; we append
# --sign / --keychain only for real builds.
sign_pkg() {
    tool="$1"; shift
    if [ "$DRY_RUN" -eq 1 ]; then
        "$tool" "$@"
    elif [ -n "$KEYCHAIN_ARG" ]; then
        # shellcheck disable=SC2086
        "$tool" "$@" --sign "$INSTALLER_IDENTITY" $KEYCHAIN_ARG
    else
        "$tool" "$@" --sign "$INSTALLER_IDENTITY"
    fi
}

DIST="$ROOT/dist"
STAGE="$ROOT/dist/stage"
rm -rf "$DIST" "$STAGE"
mkdir -p "$DIST" "$STAGE"

echo "==> building fleet-edr-agent ($VERSION, $COMMIT)"
AGENT_ROOT="$STAGE/agent-root"
mkdir -p "$AGENT_ROOT/usr/local/bin" "$AGENT_ROOT/Library/LaunchDaemons"
(
    cd "$ROOT/agent"
    CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build \
        -trimpath \
        -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildTime=$BUILD_TIME" \
        -o "$AGENT_ROOT/usr/local/bin/fleet-edr-agent" \
        ./cmd/fleet-edr-agent
)
cp "$ROOT/agent/com.fleetdm.edr.agent.plist" \
    "$AGENT_ROOT/Library/LaunchDaemons/com.fleetdm.edr.agent.plist"

echo "==> codesigning fleet-edr-agent"
# shellcheck disable=SC2086  # intentional word-split on CODESIGN_FLAGS + KEYCHAIN_ARG
codesign $CODESIGN_FLAGS --sign "$APP_IDENTITY" $KEYCHAIN_ARG "$AGENT_ROOT/usr/local/bin/fleet-edr-agent"

echo "==> packaging agent component pkg"
sign_pkg pkgbuild \
    --identifier com.fleetdm.edr.agent \
    --version "$VERSION" \
    --root "$AGENT_ROOT" \
    --install-location / \
    "$STAGE/agent.pkg"

# ---------------------------------------------------------------
# Host app + sysext: Xcode build.
# ---------------------------------------------------------------
echo "==> building host app + sysext via xcodebuild"
XCODE_BUILD="$STAGE/xcode-build"
mkdir -p "$XCODE_BUILD"

if [ "$DRY_RUN" -eq 1 ]; then
    # Dry-run shortcut: use the existing ad-hoc debug build output if present.
    # The pkgbuild step below still runs against whatever bundle exists, so
    # script shape gets exercised even when the Xcode project hasn't been
    # rebuilt for the current commit.
    SRC_APP="$ROOT/extension/edr/build/Debug/edr.app"
    if [ ! -d "$SRC_APP" ]; then
        echo "dry-run: $SRC_APP missing; run the Xcode Debug build once to seed" >&2
        exit 3
    fi
    mkdir -p "$STAGE/app-root/Applications"
    cp -R "$SRC_APP" "$STAGE/app-root/Applications/Fleet EDR.app"
else
    # Release build path: Developer ID-signed host app + sysext with provisioning
    # profile embedded. Expects packaging/provisioning/*.provisionprofile to be
    # checked in.
    PROFILE_SYSEXT="$ROOT/packaging/provisioning/securityextension.provisionprofile"
    if [ ! -f "$PROFILE_SYSEXT" ]; then
        echo "missing $PROFILE_SYSEXT" >&2
        exit 4
    fi

    # Scheme `edr` builds the host app with both extensions embedded. Scheme
    # `extension` is sysext-only and its archive lacks the host app, which
    # breaks the pkg build (pkgbuild wraps Fleet EDR.app).
    xcodebuild \
        -project "$ROOT/extension/edr/edr.xcodeproj" \
        -scheme edr \
        -configuration Release \
        -derivedDataPath "$XCODE_BUILD" \
        CODE_SIGN_IDENTITY="$APP_IDENTITY" \
        CODE_SIGN_STYLE=Manual \
        DEVELOPMENT_TEAM="$TEAM_ID" \
        MARKETING_VERSION="$VERSION" \
        archive -archivePath "$XCODE_BUILD/edr.xcarchive"

    SRC_APP="$XCODE_BUILD/edr.xcarchive/Products/Applications/edr.app"
    mkdir -p "$STAGE/app-root/Applications"
    cp -R "$SRC_APP" "$STAGE/app-root/Applications/Fleet EDR.app"

    # Embed the provisioning profiles inside each restricted-entitlement
    # bundle. Without them the sysext + NE load on SIP-disabled dev VMs but
    # fail at runtime on SIP-enabled systems: ES returns
    # ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED; NE fails to register with
    # NetworkExtension framework.
    SYSEXT="$STAGE/app-root/Applications/Fleet EDR.app/Contents/Library/SystemExtensions/com.fleetdm.edr.securityextension.systemextension"
    if [ ! -d "$SYSEXT" ]; then
        echo "ERROR: expected sysext bundle at $SYSEXT but it does not exist." >&2
        echo "       Check the Xcode project's embedded-targets settings." >&2
        exit 5
    fi
    cp "$PROFILE_SYSEXT" "$SYSEXT/Contents/embedded.provisionprofile"

    PROFILE_NET="$ROOT/packaging/provisioning/networkextension.provisionprofile"
    NETEXT="$STAGE/app-root/Applications/Fleet EDR.app/Contents/Library/SystemExtensions/com.fleetdm.edr.networkextension.systemextension"
    if [ -f "$PROFILE_NET" ] && [ -d "$NETEXT" ]; then
        cp "$PROFILE_NET" "$NETEXT/Contents/embedded.provisionprofile"
    fi

    # Re-sign every bundle the edr.app embeds, bottom-up, with the hardened
    # runtime flag. Notary rejects any Mach-O inside the outer bundle that
    # lacks `--options runtime`, so all three inner bundles + the app bundle
    # itself get re-signed after the provisioning profile embed above (which
    # invalidates the Xcode-time signature).
    # shellcheck disable=SC2086
    codesign $CODESIGN_FLAGS --sign "$APP_IDENTITY" $KEYCHAIN_ARG "$SYSEXT"
    if [ -d "$NETEXT" ]; then
        # shellcheck disable=SC2086
        codesign $CODESIGN_FLAGS --sign "$APP_IDENTITY" $KEYCHAIN_ARG "$NETEXT"
    fi
    # shellcheck disable=SC2086
    codesign $CODESIGN_FLAGS --sign "$APP_IDENTITY" $KEYCHAIN_ARG \
        "$STAGE/app-root/Applications/Fleet EDR.app"
fi

echo "==> packaging app component pkg"
sign_pkg pkgbuild \
    --identifier com.fleetdm.edr.app \
    --version "$VERSION" \
    --root "$STAGE/app-root" \
    --install-location / \
    --component-plist /dev/stdin \
    "$STAGE/app.pkg" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <dict>
        <key>BundleHasStrictIdentifier</key><true/>
        <key>BundleIsRelocatable</key><false/>
        <key>BundleIsVersionChecked</key><true/>
        <key>BundleOverwriteAction</key><string>upgrade</string>
        <key>RootRelativeBundlePath</key><string>Applications/Fleet EDR.app</string>
    </dict>
</array>
</plist>
PLIST

# ---------------------------------------------------------------
# Support payload: uninstall.sh + VERSION stamp.
# ---------------------------------------------------------------
echo "==> building support component pkg"
SUPPORT_ROOT="$STAGE/support-root"
mkdir -p "$SUPPORT_ROOT/Library/Application Support/com.fleetdm.edr"
cp "$ROOT/packaging/pkg/uninstall.sh" \
    "$SUPPORT_ROOT/Library/Application Support/com.fleetdm.edr/uninstall.sh"
chmod 0755 "$SUPPORT_ROOT/Library/Application Support/com.fleetdm.edr/uninstall.sh"
printf '%s' "$VERSION" > "$SUPPORT_ROOT/Library/Application Support/com.fleetdm.edr/VERSION"

sign_pkg pkgbuild \
    --identifier com.fleetdm.edr.support \
    --version "$VERSION" \
    --root "$SUPPORT_ROOT" \
    --install-location / \
    "$STAGE/support.pkg"

# ---------------------------------------------------------------
# Product build: combine components with preinstall + postinstall.
# ---------------------------------------------------------------
echo "==> building distribution pkg"
SCRIPTS_DIR="$STAGE/scripts"
mkdir -p "$SCRIPTS_DIR"
cp "$ROOT/packaging/pkg/scripts/preinstall" "$SCRIPTS_DIR/preinstall"
cp "$ROOT/packaging/pkg/scripts/postinstall" "$SCRIPTS_DIR/postinstall"
chmod 0755 "$SCRIPTS_DIR/preinstall" "$SCRIPTS_DIR/postinstall"

DIST_XML="$STAGE/distribution.xml"
# Git tags are legal shell input but can contain characters that are
# meaningful to sed replacement (notably `&`, `\`, and the `/` delimiter).
# Escape any of those in the replacement value and use `|` as the delimiter
# so a tag like `release/v1.2` does not collide with the default `/`.
ESCAPED_VERSION=$(printf '%s' "$VERSION" | sed 's/[&|\\]/\\&/g')
sed "s|__VERSION__|$ESCAPED_VERSION|g" "$ROOT/packaging/pkg/distribution.xml" > "$DIST_XML"

# Filename-safe variant of $VERSION: replace `/` with `-` so a namespaced
# git tag like `release/v1.2` produces `fleet-edr-release-v1.2.pkg` rather
# than trying to write into a subdirectory that does not exist.
SAFE_VERSION=$(printf '%s' "$VERSION" | tr '/' '-')
PKG_OUT="$DIST/fleet-edr-${SAFE_VERSION}.pkg"
sign_pkg productbuild \
    --distribution "$DIST_XML" \
    --package-path "$STAGE" \
    --scripts "$SCRIPTS_DIR" \
    "$PKG_OUT"

echo "==> pkg signature"
pkgutil --check-signature "$PKG_OUT" | head -5

if [ "$DRY_RUN" -eq 1 ]; then
    echo "==> dry-run: skipping notarization and staple"
    echo "built $PKG_OUT"
    exit 0
fi

# ---------------------------------------------------------------
# Notarize + staple.
# ---------------------------------------------------------------
echo "==> submitting to notarytool (this may take a few minutes)"
: "${APPLE_NOTARY_APPLE_ID:?missing}"
: "${APPLE_NOTARY_APP_PASSWORD:?missing}"

xcrun notarytool submit "$PKG_OUT" \
    --apple-id "$APPLE_NOTARY_APPLE_ID" \
    --team-id "$TEAM_ID" \
    --password "$APPLE_NOTARY_APP_PASSWORD" \
    --wait

echo "==> stapling ticket"
xcrun stapler staple "$PKG_OUT"
xcrun stapler validate "$PKG_OUT"

echo "==> final gate: spctl"
spctl -a -v --type install "$PKG_OUT"

echo ""
echo "SUCCESS: $PKG_OUT"
shasum -a 256 "$PKG_OUT"
