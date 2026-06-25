#!/bin/sh
# spec:release-packaging/uninstall-path-is-deliverable/operator-runs-the-uninstall-script
#
# Uninstall script for Fleet EDR. THIS script IS the spec scenario's enforcement surface: it stops + unloads the agent's
# LaunchDaemon (the launchctl bootout block below), deactivates BOTH system extensions through the host app's `deactivate`
# subcommand (NOT systemextensionsctl, which has no deactivate verb and whose developer commands are blocked under SIP), and
# removes the agent's binaries + runtime state. The package install path drops this script at
# /Library/Application Support/com.fleetdm.edr/uninstall.sh so an operator (or the MDM) can invoke it without the
# original signed installer.
#
# Deactivation mirrors activation (Apple's model): OSSystemExtensionRequest must be submitted by the host app running in a
# logged-in user's GUI (Aqua) session, so this script invokes `edr deactivate` via `launchctl asuser`, the same way the
# activation LaunchAgent submits `edr activate`. A root daemon or `systemextensionsctl` cannot do it. The deactivation runs
# BEFORE the app bundle is removed, because deleting the app first would orphan the extensions with no host app left to
# tear them down.
#
# The script verifies the post-deactivation state with `systemextensionsctl list` rather than trusting an exit code, and
# branches the operator-facing output on what actually happened:
#   - extensions removed                -> remove the app + remaining binaries, report clean.
#   - extensions staged (reboot needed) -> remove the app, tell the operator to reboot to finish.
#   - extensions still active           -> KEEP the app (so a retry / MDM removal can still tear them down) and print
#                                          specific guidance: MDM-managed hosts must remove the system-extension profile;
#                                          an unmanaged host with no console user must log in and re-run.
#
# Leaves /etc/fleet-edr.conf in place on purpose so a subsequent re-install picks up the same enroll config without
# re-provisioning.
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
APP_BIN=$APP/Contents/MacOS/edr
AGENT_BIN=/usr/local/bin/fleet-edr-agent
SUPPORT=/Library/Application\ Support/com.fleetdm.edr
VAR_DB=/var/db/fleet-edr
LOG=/var/log/fleet-edr-agent.log
SYSEXT_PROFILE=com.fleetdm.edr.profile.system-extension

# Console user whose GUI (Aqua) session can submit OSSystemExtensionRequests. 0 means the login window (no user), in which
# case the host app cannot deactivate the extensions and we fall back to guidance.
CONSOLE_UID=$(/usr/bin/stat -f %u /dev/console 2>/dev/null || echo 0)

# count_active_exts / count_pending_exts read the live systemextensionsctl state so the script reports what actually
# happened, not what a command's exit code claimed. "activated enabled" means still installed; a "uninstall on reboot"
# state means the OS staged the removal and a reboot will finish it.
count_active_exts() {
    /usr/bin/systemextensionsctl list 2>/dev/null | /usr/bin/grep "com.fleetdm.edr" | /usr/bin/grep -c "activated enabled" || true
}
count_pending_exts() {
    /usr/bin/systemextensionsctl list 2>/dev/null | /usr/bin/grep "com.fleetdm.edr" | /usr/bin/grep -c "uninstall on reboot" || true
}
mdm_sysext_profile_present() {
    /usr/bin/profiles list -all 2>/dev/null | /usr/bin/grep -q "$SYSEXT_PROFILE"
}

echo "==> stopping and unloading LaunchDaemon"
if [ -f "$PLIST" ]; then
    /bin/launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
fi

# spec:release-packaging/installation-activates-the-system-extensions/uninstall-removes-the-activation-launchagent
echo "==> removing activation LaunchAgent"
ACTIVATE_LA=/Library/LaunchAgents/com.fleetdm.edr.activate.plist
if [ -f "$ACTIVATE_LA" ]; then
    if [ "$CONSOLE_UID" -gt 0 ]; then
        /bin/launchctl bootout "gui/$CONSOLE_UID" "$ACTIVATE_LA" 2>/dev/null || true
    fi
    rm -f "$ACTIVATE_LA"
fi

# spec:release-packaging/uninstall-path-is-deliverable/uninstall-deactivates-both-extensions-via-the-host-app
echo "==> deactivating system extensions"
# Submit the deactivation through the host app in the console user's GUI session (Apple's model), the same path the
# activation LaunchAgent uses. `edr deactivate` requests removal of BOTH extensions (HostAppExtensionID.all). systemextensionsctl
# is deliberately NOT used: it has no `deactivate` subcommand, and its `uninstall` developer verb is blocked while SIP is on.
if [ -x "$APP_BIN" ] && [ "$CONSOLE_UID" -gt 0 ]; then
    /bin/launchctl asuser "$CONSOLE_UID" "$APP_BIN" deactivate >/dev/null 2>&1 &
    DEACT_PID=$!
    # The host app exits once both deactivation outcomes are recorded; a watchdog bounds the wait so a request stuck
    # pending user approval cannot hang the uninstall. `wait` reaps the host app whether it exited on its own or the
    # watchdog killed it, so the shell does not print an async "Killed" job notification.
    (sleep 30; kill -9 "$DEACT_PID" 2>/dev/null) &
    WATCHDOG_PID=$!
    wait "$DEACT_PID" 2>/dev/null || true
    kill "$WATCHDOG_PID" 2>/dev/null || true
    wait "$WATCHDOG_PID" 2>/dev/null || true
    # Give sysextd a moment to settle the state before we read it back.
    sleep 2
elif [ ! -x "$APP_BIN" ]; then
    echo "uninstall: host app not found at $APP; cannot submit a deactivation request" >&2
elif [ "$CONSOLE_UID" -le 0 ]; then
    echo "uninstall: no user logged in at the console; cannot submit a deactivation request" >&2
fi

ACTIVE_EXTS=$(count_active_exts)
PENDING_EXTS=$(count_pending_exts)

echo "==> removing binaries"
rm -f "$AGENT_BIN"

# Only delete the host app once the extensions are gone or staged for removal on reboot. If they are still active the app
# is the only thing that can tear them down, so we keep it and tell the operator what to do.
APP_REMOVED=no
if [ "$ACTIVE_EXTS" -eq 0 ]; then
    rm -rf "$APP"
    APP_REMOVED=yes
fi

echo "==> removing runtime state"
rm -rf "$VAR_DB"
rm -f "$LOG"
# Keep the support dir (and this script) only when we kept the app, so the operator still has a working uninstall to retry.
if [ "$APP_REMOVED" = yes ]; then
    rm -rf "$SUPPORT"
fi

echo ""
if [ "$ACTIVE_EXTS" -eq 0 ] && [ "$PENDING_EXTS" -eq 0 ]; then
    echo "Fleet EDR removed."
elif [ "$ACTIVE_EXTS" -eq 0 ] && [ "$PENDING_EXTS" -gt 0 ]; then
    echo "Fleet EDR removed. The system extensions are staged for removal:"
    echo "REBOOT to finish removing them. After reboot, 'systemextensionsctl list' shows no com.fleetdm.edr entries."
else
    echo "WARNING: $ACTIVE_EXTS Fleet EDR system extension(s) are still active and were NOT removed."
    echo "The agent binaries are gone, but the extensions remain. To remove them:"
    if mdm_sysext_profile_present; then
        echo ""
        echo "  This host is MDM-managed: the extensions were approved by the '$SYSEXT_PROFILE'"
        echo "  configuration profile, so macOS refuses a local deactivation (authorizationRequired)."
        echo "  Remove that profile via your MDM (Fleet, Jamf, Intune, Kandji, Mosyle). macOS removes the"
        echo "  now-unauthorized extensions automatically once the profile is gone."
    elif [ "$CONSOLE_UID" -le 0 ]; then
        echo ""
        echo "  No user was logged in at the console, so the host app could not submit the request."
        echo "  Log in at the console, then re-run this script:"
        echo "     sudo $SUPPORT/uninstall.sh"
    elif [ ! -x "$APP_BIN" ]; then
        echo ""
        echo "  The host app is missing, so there is nothing to submit the deactivation request."
        echo "  Re-install the package and run its uninstall script again, or (MDM hosts) remove the"
        echo "  '$SYSEXT_PROFILE' profile."
    else
        echo ""
        echo "  Open System Settings > General > Login Items & Extensions, find the Fleet EDR entries"
        echo "  under Endpoint Security Extensions and Network Extensions, and remove them. If removal is"
        echo "  blocked, the extensions are managed by a configuration profile that must be removed first."
    fi
    echo ""
    echo "  The host app at '$APP' was kept so you can retry after clearing the blocker."
fi
echo ""
echo "/etc/fleet-edr.conf preserved so a future re-install picks up the existing enroll config."
echo "Delete it manually if you want a clean slate:"
echo "   sudo rm /etc/fleet-edr.conf"
exit 0
