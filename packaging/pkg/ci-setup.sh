#!/bin/sh
# Import the Developer ID .p12 files into an ephemeral keychain so codesign +
# productbuild + productsign can find them during a release build. Designed
# for GitHub Actions macos-14 runners; the keychain is torn down when the
# job exits (the tempdir the runner uses gets wiped).
#
# Required env (set from the `release-signing` environment's secrets):
#   APPLE_DEV_ID_APP_P12_BASE64
#   APPLE_DEV_ID_APP_P12_PASSWORD
#   APPLE_DEV_ID_INSTALLER_P12_BASE64
#   APPLE_DEV_ID_INSTALLER_P12_PASSWORD
#
# Writes the keychain path to $GITHUB_ENV under CI_KEYCHAIN so subsequent
# steps pick it up for `codesign --keychain` etc.

set -eu

: "${APPLE_DEV_ID_APP_P12_BASE64:?missing}"
: "${APPLE_DEV_ID_APP_P12_PASSWORD:?missing}"
: "${APPLE_DEV_ID_INSTALLER_P12_BASE64:?missing}"
: "${APPLE_DEV_ID_INSTALLER_P12_PASSWORD:?missing}"

# Fresh per-job password; not a secret since the keychain is thrown away.
KC_PW="$(openssl rand -hex 24)"
KC_FILE="${RUNNER_TEMP:-/tmp}/edr-build.keychain-db"

# Paranoia: wipe any leftover keychain from a previous run that shared the
# tempdir (shouldn't happen on fresh runners but harmless if it does).
/usr/bin/security delete-keychain "$KC_FILE" 2>/dev/null || true

/usr/bin/security create-keychain -p "$KC_PW" "$KC_FILE"
/usr/bin/security set-keychain-settings -lut 21600 "$KC_FILE"
/usr/bin/security unlock-keychain -p "$KC_PW" "$KC_FILE"

# Base64 bytes → temp .p12 files → import → delete the plaintext copies.
APP_P12="${RUNNER_TEMP:-/tmp}/dev-id-app.p12"
INST_P12="${RUNNER_TEMP:-/tmp}/dev-id-installer.p12"

printf '%s' "$APPLE_DEV_ID_APP_P12_BASE64" | base64 --decode > "$APP_P12"
printf '%s' "$APPLE_DEV_ID_INSTALLER_P12_BASE64" | base64 --decode > "$INST_P12"

/usr/bin/security import "$APP_P12" -k "$KC_FILE" -P "$APPLE_DEV_ID_APP_P12_PASSWORD" \
    -T /usr/bin/codesign -T /usr/bin/productbuild -T /usr/bin/productsign -T /usr/bin/pkgbuild
/usr/bin/security import "$INST_P12" -k "$KC_FILE" -P "$APPLE_DEV_ID_INSTALLER_P12_PASSWORD" \
    -T /usr/bin/codesign -T /usr/bin/productbuild -T /usr/bin/productsign -T /usr/bin/pkgbuild

rm -f "$APP_P12" "$INST_P12"

# Let signing tools use the keys without the "allow" GUI prompt (no GUI in CI).
/usr/bin/security set-key-partition-list -S 'apple-tool:,apple:' -s -k "$KC_PW" "$KC_FILE"

# Prepend our temp keychain to the search list so codesign finds it.
ORIG=$(/usr/bin/security list-keychains -d user | tr -d '"' | xargs)
# shellcheck disable=SC2086  # word-splitting on the orig list is intentional
/usr/bin/security list-keychains -d user -s "$KC_FILE" $ORIG

echo "Imported identities:"
/usr/bin/security find-identity -p codesigning -v "$KC_FILE"
/usr/bin/security find-identity -p basic -v "$KC_FILE" | grep 'Developer ID Installer' || true

# Publish to the GitHub Actions step env so downstream steps can reference it.
if [ -n "${GITHUB_ENV:-}" ]; then
    {
        echo "CI_KEYCHAIN=$KC_FILE"
        echo "CI_KEYCHAIN_PW=$KC_PW"
    } >> "$GITHUB_ENV"
fi
