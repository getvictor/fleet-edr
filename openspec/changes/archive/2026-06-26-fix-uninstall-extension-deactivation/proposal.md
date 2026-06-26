# Fix uninstall extension deactivation

## Why

`uninstall.sh` never removes the system extensions. The deactivation line runs `systemextensionsctl deactivate <teamID> com.fleetdm.edr.securityextension`, but `systemextensionsctl` has no `deactivate` subcommand: the call exits 64 (`EX_USAGE`) and is swallowed by `2>/dev/null || true`. Even the real developer verb (`systemextensionsctl uninstall`) requires `systemextensionsctl developer on`, which macOS blocks while SIP is enabled. The block also names only the Endpoint Security extension (the Network Extension is never targeted) and runs before `rm -rf "$APP"`, so once the script finishes the host app that could tear the extensions down is gone, leaving them orphaned and unremovable under SIP.

Reproduced on edr-qa (SIP on, macOS 26.4.1) on 2026-06-25: the bundled script reported `exit=0` "Fleet EDR removed", deleted the agent, app, and LaunchDaemon, yet both `com.fleetdm.edr.networkextension` and `com.fleetdm.edr.securityextension` stayed `activated enabled`. This matches the operator report that prompted the change ("removed the agent but left the extensions; after restart the extensions were still active; manual removal said it isn't supported with SIP enabled").

Deactivation has to use the same Apple-sanctioned path activation already uses: `OSSystemExtensionRequest`, submitted by the host app in a logged-in user's GUI (Aqua) session. The host app already ships an `edr deactivate` subcommand that requests removal of both extensions (`HostAppExtensionID.all`); `uninstall.sh` simply never calls it.

On MDM-managed hosts there is a second wall: extensions approved by the `com.fleetdm.edr.profile.system-extension` profile (`AllowedSystemExtensions`, `AllowUserOverrides=false`) cannot be removed locally at all. A correct `edr deactivate` is refused by sysextd with `OSSystemExtensionErrorDomain Code=13` (authorizationRequired); the only removal path is the MDM pulling the profile, after which macOS removes the now-unauthorized extensions. The script must detect this rather than claim success.

## What changes

- `uninstall.sh` deactivates both extensions through `launchctl asuser <console-uid> "Fleet EDR.app/Contents/MacOS/edr" deactivate` (the activation model in reverse), BEFORE removing the app bundle. `systemextensionsctl` is no longer used for deactivation.
- The script verifies the result against live `systemextensionsctl list` state instead of trusting an exit code, and branches its operator-facing output:
  - extensions removed: delete the app + remaining binaries, report a clean removal.
  - extensions staged for removal on reboot: delete the app, tell the operator to reboot to finish.
  - extensions still active: KEEP the app bundle and its `uninstall.sh` (so a retry or post-profile-removal teardown can still run) and print cause-specific guidance: MDM-managed hosts must remove the system-extension profile via their MDM; an unmanaged host with no console user must log in and re-run; a host whose app is already gone must reinstall first.
- The deactivation is bounded by a watchdog so a request stuck pending user approval cannot hang the uninstall.
- Docs corrected: `install-agent-manual.md` uninstall section gains the reboot-to-finish note and the "extensions still active" recovery steps; `mdm-deployment.md` documents that managed-host removal is profile removal, not the local script.

### Not in this change

- Automating MDM profile removal from the script: the script has no MDM channel; profile removal is the MDM's job (Fleet / Jamf / Intune / Kandji / Mosyle). The script detects the managed case and tells the operator.
- Headless hosts with no GUI session: Apple provides no path to deactivate a system extension without a user session, the same known limitation activation has.
