#!/bin/sh
# Uninstall script for Fleet EDR.
#
# Installed by the pkg at /Library/Application Support/com.fleetdm.edr/
# uninstall.sh so operators (or the MDM) can remove the agent without a
# signed uninstaller pkg. Tears down the LaunchDaemon, deactivates the
# sysext, and removes binaries + local state. Leaves /etc/fleet-edr.conf in
# place on purpose so a subsequent re-install picks up the same enroll
# config without re-provisioning.
#
# Run as root:
#   sudo /Library/Application\ Support/com.fleetdm.edr/uninstall.sh

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall: must run as root" >&2
    exit 2
fi

LABEL=com.fleetdm.edr.agent
PLIST=/Library/LaunchDaemons/${LABEL}.plist
APP=/Applications/Fleet\ EDR.app
AGENT_BIN=/usr/local/bin/fleet-edr-agent
SUPPORT=/Library/Application\ Support/com.fleetdm.edr
VAR_DB=/var/db/fleet-edr
LOG=/var/log/fleet-edr-agent.log

echo "==> stopping and unloading LaunchDaemon"
if [ -f "$PLIST" ]; then
    /bin/launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
fi

echo "==> deactivating system extension"
# Derive the team ID from the installed host app rather than hardcoding; an
# operator who re-signed with a different team ID (fork, team migration)
# needs `systemextensionsctl deactivate` to use that team ID, not ours.
if [ -d "$APP" ]; then
    TEAM_ID=$(/usr/bin/codesign -dv --verbose=4 "$APP" 2>&1 \
        | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')
    if [ -n "$TEAM_ID" ]; then
        /usr/bin/systemextensionsctl deactivate "$TEAM_ID" com.fleetdm.edr.securityextension 2>/dev/null || true
    else
        echo "uninstall: could not determine Team ID from $APP; skipping sysext deactivate" >&2
    fi
fi

echo "==> removing binaries"
rm -f "$AGENT_BIN"
rm -rf "$APP"
rm -rf "$SUPPORT"

echo "==> removing runtime state"
rm -rf "$VAR_DB"
rm -f "$LOG"

echo ""
echo "Fleet EDR removed. /etc/fleet-edr.conf preserved so a future re-install"
echo "picks up the existing enroll config. Delete it manually if you want a"
echo "clean slate:"
echo "   sudo rm /etc/fleet-edr.conf"
exit 0
