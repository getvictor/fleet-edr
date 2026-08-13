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
# Code-signing identifier the system extension's XPC peer requirement pins (XPCEventServer.agentIdentifierDebug). Set
# explicitly at signing time because codesign's default differs by signing mode: an ad-hoc signature of a bare Mach-O
# derives `fleet-edr-agent-<hash>`, which the extension rejects.
AGENT_SIGNING_IDENTIFIER="fleet-edr-agent"

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
    # Propagate the tool's exit code. `return 0` here would mask pkgbuild /
    # productbuild failures and let the script continue into notarization
    # against a broken artifact. Explicit `return $?` satisfies Sonar's
    # "explicit return" rule without lying about the outcome.
    return $?
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
# --identifier is pinned rather than left to codesign's default. For a bare Mach-O signed ad-hoc, codesign derives
# `fleet-edr-agent-<hash>`, and the extension's debug XPC peer requirement pins the bare `fleet-edr-agent`, so a dry-run
# pkg installs an agent the extension then refuses to talk to (it reports never_connected and the host silently loses
# telemetry). Setting it explicitly also makes the release path deterministic rather than relying on codesign's default
# happening to match what XPCEventServer documents the notarized release as carrying. Matches `task build:agent`.
# shellcheck disable=SC2086  # intentional word-split on CODESIGN_FLAGS + KEYCHAIN_ARG
codesign $CODESIGN_FLAGS --identifier "$AGENT_SIGNING_IDENTIFIER" --sign "$APP_IDENTITY" $KEYCHAIN_ARG \
    "$AGENT_ROOT/usr/local/bin/fleet-edr-agent"

# Assert what was actually produced rather than trusting the flag. This runs on BOTH paths, so the dry-run CI job
# enforces the identifier for the ad-hoc mode and a real tag enforces it for the Developer ID mode; that is what makes
# "does not vary with signing mode" a checked property instead of a claim. A wrong identifier is otherwise invisible
# here and only surfaces on an endpoint as an agent that installs, connects to nothing, and reports never_connected.
# spec:release-packaging/the-packaged-agent-carries-the-identifier-the-extension-expects/the-packaged-agent-is-accepted-by-the-extension
# spec:release-packaging/the-packaged-agent-carries-the-identifier-the-extension-expects/the-identifier-does-not-vary-with-signing-mode
# The read is a separate step from the extraction on purpose. This script is /bin/sh with `set -eu` and no portable
# `pipefail`, so piping codesign straight into sed would let a codesign failure be masked by sed's success: the
# identifier would come back empty and the mismatch branch below would report "the identifier is wrong" when the truth
# is "codesign could not read the binary", with codesign's own diagnostics filtered into the pipe and lost. Capturing
# first keeps the two failures distinguishable and preserves the diagnostics.
if ! SIGNING_INFO=$(codesign -dvv "$AGENT_ROOT/usr/local/bin/fleet-edr-agent" 2>&1); then
    echo "could not read the packaged agent's code signature:" >&2
    echo "$SIGNING_INFO" >&2
    exit 16
fi
SIGNED_IDENTIFIER=$(printf '%s\n' "$SIGNING_INFO" | sed -n 's/^Identifier=//p')
if [ "$SIGNED_IDENTIFIER" != "$AGENT_SIGNING_IDENTIFIER" ]; then
    echo "agent signed with identifier '$SIGNED_IDENTIFIER', expected '$AGENT_SIGNING_IDENTIFIER';" \
        "the system extension's XPC peer requirement will reject it" >&2
    exit 15
fi

echo "==> packaging agent component pkg"
# Install scripts (preinstall + postinstall) attach to the COMPONENT pkg via
# `pkgbuild --scripts`. `productbuild --scripts` exists but Installer.app's
# script-execution phase only fires for scripts attached at the component
# level; distribution-level scripts get bundled into the distribution pkg
# but never invoked at install time.
AGENT_SCRIPTS_DIR="$STAGE/agent-scripts"
mkdir -p "$AGENT_SCRIPTS_DIR"
cp "$ROOT/packaging/pkg/scripts/preinstall" "$AGENT_SCRIPTS_DIR/preinstall"
cp "$ROOT/packaging/pkg/scripts/postinstall" "$AGENT_SCRIPTS_DIR/postinstall"
chmod 0755 "$AGENT_SCRIPTS_DIR/preinstall" "$AGENT_SCRIPTS_DIR/postinstall"
sign_pkg pkgbuild \
    --identifier com.fleetdm.edr.agent \
    --version "$VERSION" \
    --root "$AGENT_ROOT" \
    --install-location / \
    --scripts "$AGENT_SCRIPTS_DIR" \
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
    # Release build path: Developer ID-signed host app + sysext. The provisioning profiles are embedded further down,
    # after the shared bundle checks.
    #
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
fi

# ---------------------------------------------------------------
# Locate and verify the embedded bundles. Shared by both modes: a staged app
# missing an extension produces a package that installs and then does nothing,
# which is worth failing the build over whichever way the app was built.
# ---------------------------------------------------------------
APP_BUNDLE="$STAGE/app-root/Applications/Fleet EDR.app"
SYSEXT="$APP_BUNDLE/Contents/Library/SystemExtensions/com.fleetdm.edr.securityextension.systemextension"
NETEXT="$APP_BUNDLE/Contents/Library/SystemExtensions/com.fleetdm.edr.networkextension.systemextension"
if [ ! -d "$SYSEXT" ]; then
    echo "ERROR: expected sysext bundle at $SYSEXT but it does not exist." >&2
    echo "       Check the Xcode project's embedded-targets settings." >&2
    exit 5
fi
# The Network Extension is a mandatory part of the shipped product (the
# `edr` scheme embeds both extensions), so a missing NE bundle is a hard
# failure, same as the sysext above. Distinct exit code for CI triage.
if [ ! -d "$NETEXT" ]; then
    echo "ERROR: expected NE bundle at $NETEXT but it does not exist." >&2
    echo "       Check the Xcode project's embedded-targets settings." >&2
    exit 14
fi

if [ "$DRY_RUN" -eq 0 ]; then
    # Embed the provisioning profiles inside each restricted-entitlement
    # bundle. Without them the sysext + NE load on SIP-disabled dev VMs but
    # fail at runtime on SIP-enabled systems: ES returns
    # ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED; NE fails to register with
    # NetworkExtension framework.
    #
    # Release-only, and that is the one thing a dry-run package cannot
    # reproduce: profiles are issued per signing identity, so an ad-hoc
    # package carries none and its restricted entitlements are honoured only
    # where they are not enforced, i.e. a SIP-disabled dev VM. That is exactly
    # where dry-run packages get installed; a SIP-on host still requires the
    # release path.
    PROFILE_SYSEXT="$ROOT/packaging/provisioning/securityextension.provisionprofile"
    if [ ! -f "$PROFILE_SYSEXT" ]; then
        echo "missing $PROFILE_SYSEXT" >&2
        exit 4
    fi
    cp "$PROFILE_SYSEXT" "$SYSEXT/Contents/embedded.provisionprofile"

    PROFILE_NET="$ROOT/packaging/provisioning/networkextension.provisionprofile"
    # Without an embedded provisioning profile the restricted-entitlement
    # re-sign below produces a NE that fails activation on SIP-on hosts: the
    # exact bug the entitlements re-sign exists to fix on the sysext side.
    if [ ! -f "$PROFILE_NET" ]; then
        echo "ERROR: $PROFILE_NET is missing." >&2
        echo "       A NE re-signed without an embedded profile fails activation on SIP-on hosts." >&2
        exit 8
    fi
    cp "$PROFILE_NET" "$NETEXT/Contents/embedded.provisionprofile"

    # Host app needs its own embedded profile because
    # `com.apple.developer.system-extension.install` is a restricted entitlement.
    # On SIP-on hosts AMFI rejects the binary at launch with "No matching
    # profile found" (-413); the visible symptom on a pilot Mac is the host
    # app silently exiting 137 (SIGKILL) before OSSystemExtensionRequest can
    # fire, so the System Settings approval prompt never appears. SIP-off dev
    # VMs don't enforce restricted entitlements, which is what masked this
    # gap from rc.3/rc.4 (the empty-entitlements bug below was hit first).
    PROFILE_HOST="$ROOT/packaging/provisioning/edr.provisionprofile"
    if [ ! -f "$PROFILE_HOST" ]; then
        echo "missing $PROFILE_HOST" >&2
        exit 9
    fi
    cp "$PROFILE_HOST" "$STAGE/app-root/Applications/Fleet EDR.app/Contents/embedded.provisionprofile"

fi

# ---------------------------------------------------------------
# Entitlements. Shared by both modes (issue #689).
#
# Re-sign every bundle the edr.app embeds, bottom-up, with the per-binary
# entitlements (and, on the release path, the hardened runtime flag: notary
# rejects any Mach-O inside the outer bundle that lacks `--options runtime`).
# The release path additionally re-signs after the provisioning-profile embed
# above, which invalidates the Xcode-time signature.
#
# `--entitlements` is load-bearing, and NOT because it preserves something the
# Xcode build already did: the project sets no CODE_SIGN_ENTITLEMENTS at all,
# so every bundle it produces carries only `get-task-allow`. This step is the
# ONLY place the shipped entitlements are applied. Without it the app has no
# `com.apple.developer.system-extension.install` and cannot even submit an
# activation request, and neither extension declares a category, so sysextd
# rejects it with "does not appear to belong to any extension categories". The
# visible symptom is "I never got the System Settings approval prompt".
#
# It used to run on the release path only, which meant a dry-run package
# installed but could never activate anything, so the dry run could not
# exercise the install path's most failure-prone step. Running it in both modes
# is what makes a dry-run package usable on a SIP-disabled dev VM, and it puts
# this step under CI on every packaging PR rather than only at tag time.
if [ "$DRY_RUN" -eq 1 ]; then
    # A Debug build carries SwiftUI Previews scaffolding that the Release build does not. __preview.dylib is not linked by
    # the main binary (otool shows only edr.debug.dylib) and has no business in an installer, and it arrives UNSIGNED from a
    # fresh build. codesign refuses to seal a bundle containing unsigned nested code, so leaving it in place fails the outer
    # signature with "code object is not signed at all". Dropping it fixes that and makes the dry-run artifact closer to the
    # release one, which has no such file.
    rm -f "$APP_BUNDLE/Contents/MacOS/__preview.dylib"

    # Whatever nested Mach-Os remain must carry their own signature before the enclosing bundle can be sealed. The debug
    # dylib IS linked, so it is signed rather than dropped. Signing an already-signed dylib is a no-op with --force, and the
    # Release build produces none of these, which is why this is dry-run only.
    for dylib in "$APP_BUNDLE/Contents/MacOS/"*.dylib; do
        [ -f "$dylib" ] || continue
        # shellcheck disable=SC2086
        codesign $CODESIGN_FLAGS --sign "$APP_IDENTITY" $KEYCHAIN_ARG "$dylib"
    done
fi

SYSEXT_ENTITLEMENTS="$ROOT/extension/edr/extension/extension.entitlements"
NETEXT_ENTITLEMENTS="$ROOT/extension/edr/networkextension/networkextension.entitlements"
APP_ENTITLEMENTS="$ROOT/extension/edr/edr/edr.entitlements"
# All three bundles are mandatory, so all three entitlement plists are
# required (the NE bundle's presence is asserted above).
for f in "$SYSEXT_ENTITLEMENTS" "$NETEXT_ENTITLEMENTS" "$APP_ENTITLEMENTS"; do
    [ -f "$f" ] || { echo "missing entitlements file: $f" >&2; exit 6; }
done

# shellcheck disable=SC2086
codesign $CODESIGN_FLAGS --sign "$APP_IDENTITY" $KEYCHAIN_ARG \
    --entitlements "$SYSEXT_ENTITLEMENTS" "$SYSEXT"
# shellcheck disable=SC2086
codesign $CODESIGN_FLAGS --sign "$APP_IDENTITY" $KEYCHAIN_ARG \
    --entitlements "$NETEXT_ENTITLEMENTS" "$NETEXT"
# shellcheck disable=SC2086
codesign $CODESIGN_FLAGS --sign "$APP_IDENTITY" $KEYCHAIN_ARG \
    --entitlements "$APP_ENTITLEMENTS" "$APP_BUNDLE"

# Read the entitlements back off each signed bundle and fail the build if the
# one that makes it activatable is absent. Same reasoning as the agent's
# identifier assertion (#684 fallout): the step above is load-bearing, was
# silently skipped in one mode for months, and its absence is invisible until
# somebody installs the package and watches the activation fail with a reason
# the OS only reports as `<private>`. A comment cannot fail a build.
# assert_entitlement <bundle> <key> <kind> <label>
#
# kind is "true" for a boolean that must be enabled, or "nonempty" for an array that must declare at least one member.
# Checking that the KEY is present is not enough: `system-extension.install` set to false, or a networkextension array with
# no provider types in it, both sign cleanly and both produce a bundle that cannot activate, which is the exact failure this
# assertion exists to catch.
assert_entitlement() {
    bundle="$1"; key="$2"; kind="$3"; label="$4"
    ents_file="$STAGE/entitlements-readback.plist"
    if ! codesign -d --entitlements - --xml "$bundle" > "$ents_file" 2>/dev/null; then
        echo "ERROR: could not read entitlements back off $label ($bundle)" >&2
        exit 17
    fi
    # plutil reads "." as a key-path separator, so an entitlement key's own dots must be escaped. Unescaped, every lookup
    # reports "no value at that key path" for a key that is present, and the assertion fails on correctly signed bundles.
    escaped_key=$(printf '%s' "$key" | sed 's/\./\\./g')
    if ! value=$(plutil -extract "$escaped_key" raw -o - "$ents_file" 2>/dev/null); then
        echo "ERROR: $label is signed without $key." >&2
        echo "       It would install and then fail to activate. Check the entitlements plists and that this script" >&2
        echo "       signed with them." >&2
        exit 17
    fi
    case "$kind" in
        true)
            if [ "$value" != "true" ]; then
                echo "ERROR: $label has $key set to '$value' rather than true, so the entitlement does nothing." >&2
                exit 17
            fi
            ;;
        nonempty)
            # plutil prints an array's element count for a raw extract, so a declared-but-empty array reads as 0.
            case "$value" in
                ''|*[!0-9]*)
                    echo "ERROR: $label has a non-array value for $key: '$value'." >&2
                    exit 17
                    ;;
            esac
            if [ "$value" -lt 1 ]; then
                echo "ERROR: $label declares no values for $key, so it belongs to no extension category." >&2
                exit 17
            fi
            ;;
    esac
}
# spec:release-packaging/packaged-bundles-carry-the-entitlements-they-need-to-activate/every-build-mode-applies-the-entitlements
# spec:release-packaging/packaged-bundles-carry-the-entitlements-they-need-to-activate/a-bundle-missing-its-entitlement-fails-the-build
assert_entitlement "$APP_BUNDLE" "com.apple.developer.system-extension.install" true "the host app"
assert_entitlement "$SYSEXT" "com.apple.developer.endpoint-security.client" true "the security extension"
assert_entitlement "$NETEXT" "com.apple.developer.networking.networkextension" nonempty "the network extension"

# Guard the extensions' user-facing display names. macOS reads
# CFBundleDisplayName verbatim for the Login Items & Extensions and Full
# Disk Access entries; a generic value ("extension" / "networkextension")
# leaves a manual installer unable to tell which FDA entry is Fleet EDR's,
# which boot-loops the ES extension on a missing grant (issue #370). Fail
# the build rather than ship a pkg whose extensions are unrecognizable in
# System Settings. Runs on both the dry-run and release paths because the
# name is baked in at xcodebuild time, independent of signing.
#
# Both extensions are part of the shipped product (Fleet EDR is two system
# extensions: Endpoint Security + Network), so a staged bundle that is
# missing entirely is a hard build failure with its own exit code, not a
# silently skipped check. Asserting the Info.plist exists before querying
# it also keeps the display-name error from misfiring (a missing plist
# would otherwise yield an empty name and a misleading "wrong name" error).
STAGED_APP="$STAGE/app-root/Applications/Fleet EDR.app"
STAGED_SYSEXT="$STAGED_APP/Contents/Library/SystemExtensions/com.fleetdm.edr.securityextension.systemextension"
STAGED_NETEXT="$STAGED_APP/Contents/Library/SystemExtensions/com.fleetdm.edr.networkextension.systemextension"
if [ ! -f "$STAGED_SYSEXT/Contents/Info.plist" ]; then
    echo "ERROR: expected Endpoint Security extension at $STAGED_SYSEXT but its Info.plist is missing." >&2
    echo "       The extension was not built or staged correctly (issue #370)." >&2
    exit 12
fi
# spec:release-packaging/system-extensions-present-recognizable-display-names/security-extension-shows-a-recognizable-name
SYSEXT_NAME="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleDisplayName' "$STAGED_SYSEXT/Contents/Info.plist" 2>/dev/null || true)"
if [ "$SYSEXT_NAME" != "Fleet EDR Security Extension" ]; then
    echo "ERROR: Endpoint Security extension CFBundleDisplayName is '$SYSEXT_NAME', expected 'Fleet EDR Security Extension'." >&2
    echo "       Check INFOPLIST_KEY_CFBundleDisplayName on the securityextension target (issue #370)." >&2
    exit 10
fi
if [ ! -f "$STAGED_NETEXT/Contents/Info.plist" ]; then
    echo "ERROR: expected Network Extension at $STAGED_NETEXT but its Info.plist is missing." >&2
    echo "       A pkg without it ships single-extension coverage (no network/DNS events); issue #370." >&2
    exit 13
fi
# spec:release-packaging/system-extensions-present-recognizable-display-names/network-extension-shows-a-recognizable-name
NETEXT_NAME="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleDisplayName' "$STAGED_NETEXT/Contents/Info.plist" 2>/dev/null || true)"
if [ "$NETEXT_NAME" != "Fleet EDR Network Extension" ]; then
    echo "ERROR: Network Extension CFBundleDisplayName is '$NETEXT_NAME', expected 'Fleet EDR Network Extension'." >&2
    echo "       Check INFOPLIST_KEY_CFBundleDisplayName on the networkextension target (issue #370)." >&2
    exit 11
fi

# spec:release-packaging/installation-activates-the-system-extensions/install-with-a-user-logged-in-activates-immediately
#
# Activation LaunchAgent rides in the app component because it launches the
# app: OSSystemExtensionRequest must come from the host app in a user session,
# so login-time (RunAtLoad) plus the postinstall's gui-domain bootstrap are
# what turn "pkg installed" into "extensions activated" without an operator.
# The gui-domain bootstrap lives in packaging/pkg/scripts/postinstall, which
# spectrace cannot scan (no .sh extension); this staging block plus that
# script are the scenario's enforcement surface.
mkdir -p "$STAGE/app-root/Library/LaunchAgents"
cp "$ROOT/packaging/pkg/com.fleetdm.edr.activate.plist" \
    "$STAGE/app-root/Library/LaunchAgents/com.fleetdm.edr.activate.plist"
chmod 0644 "$STAGE/app-root/Library/LaunchAgents/com.fleetdm.edr.activate.plist"

# Version-checking is what makes a release upgrade replace the app only when the version actually moves. It also makes a
# DRY-RUN package useless for install testing, and silently so: every dry-run build stamps the Debug bundle's fixed 1.1/1,
# so installing one over any existing install skips the app while still replacing the agent, reports "The upgrade was
# successful", and leaves a host running a new agent against the OLD app and OLD extensions. Measured on edr-dev (#689).
#
# So: version-checked on release, never on a dry run. A dry-run package is an unsigned, unnotarized artifact for a
# SIP-disabled dev VM, and there "always replace what is there" is the only behaviour that makes it worth installing.
# spec:release-packaging/a-package-built-for-testing-replaces-what-is-already-installed/a-test-package-installs-over-an-existing-install
BUNDLE_VERSION_CHECKED="true"
if [ "$DRY_RUN" -eq 1 ]; then
    BUNDLE_VERSION_CHECKED="false"
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
        <key>BundleIsVersionChecked</key><$BUNDLE_VERSION_CHECKED/>
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
# NOTE: install scripts live on the agent.pkg component (see `pkgbuild
# --scripts` above), not on productbuild. `productbuild --scripts` bundles
# scripts into the distribution pkg but Installer.app never invokes them,
# so attaching here would silently fail at install time.

DIST_XML="$STAGE/distribution.xml"
# Git tags are legal shell input but can contain characters that are
# meaningful to sed replacement (notably `&`, `\`, and the `/` delimiter).
# Escape any of those in the replacement value and use `|` as the delimiter
# so a tag like `release/v1.2` does not collide with the default `/`.
ESCAPED_VERSION=$(printf '%s' "$VERSION" | sed 's/[&|\\]/\\&/g')
sed "s|__VERSION__|$ESCAPED_VERSION|g" "$ROOT/packaging/pkg/distribution.xml" > "$DIST_XML"

# spec:release-packaging/final-artifact-naming/versioned-package-name
# spec:release-packaging/final-artifact-naming/tag-with-a-path-separator-character
#
# Both spec scenarios pin the same two lines below:
#   - versioned-package-name: dist/fleet-edr-<tag>.pkg is the canonical artifact path. A tag like `v1.2.3` lands as
#     `dist/fleet-edr-v1.2.3.pkg`.
#   - tag-with-a-path-separator-character: a namespaced tag like `release/v1.2` would otherwise try to write into a
#     non-existent subdirectory. The `tr '/' '-'` substitution makes it land as `dist/fleet-edr-release-v1.2.pkg`.
SAFE_VERSION=$(printf '%s' "$VERSION" | tr '/' '-')
PKG_OUT="$DIST/fleet-edr-${SAFE_VERSION}.pkg"
sign_pkg productbuild \
    --distribution "$DIST_XML" \
    --package-path "$STAGE" \
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
