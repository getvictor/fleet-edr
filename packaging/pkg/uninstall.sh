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
/usr/bin/systemextensionsctl deactivate FDG8Q7N4CC com.fleetdm.edr.securityextension 2>/dev/null || true

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
