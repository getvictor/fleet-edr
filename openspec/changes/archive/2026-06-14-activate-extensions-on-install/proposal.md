# Activate extensions on install

## Why

The MDM deployment path never activates the system extensions. The pkg postinstall only bootstraps the agent LaunchDaemon; the agent has no activation code; the host app's `edr activate` (the only activation entry point) is never invoked by anything. On a fresh MDM-managed host the profiles land, the pkg installs, the agent enrolls, and then the agent loops `receiver connect` warnings forever because the extensions whose XPC services it needs were never activated. Observed on a fresh edr-qa copy on 2026-06-12; earlier QA setups had activation run manually, masking the gap. `docs/mdm-deployment.md` and the postinstall comment both claim an activation step that does not exist.

## What changes

- The pkg ships a LaunchAgent (`/Library/LaunchAgents/com.fleetdm.edr.activate.plist`, staged in the app component) that runs the host app's `activate` subcommand at every login (`RunAtLoad`, no `KeepAlive`). Activation requests must originate from the host app in a user session, so a LaunchAgent is the only Apple-sanctioned vehicle; running at every login is idempotent because re-activation replaces the extensions with the current bundle (already specified in `host-app-extension-manager`).
- The postinstall bootstraps that LaunchAgent into the console user's GUI domain when a user is logged in at install time, so activation happens within seconds instead of waiting for the next login. Activation problems never fail the install.
- The preinstall boots the LaunchAgent out before an upgrade replaces the app bundle; `uninstall.sh` boots it out and removes the plist.
- The pkg dry-run CI job asserts the LaunchAgent is present in the app component's BOM.
- Docs corrected: `mdm-deployment.md`'s claim that "the pkg installer runs the host app's sysext-activation request" becomes true and the install-flow step list gains the activation step; `install-agent-manual.md` notes the login-time auto-attempt.

### Not in this change

- Backoff for unmanaged Macs where the user declines the approval prompt (the LaunchAgent re-prompts at each login; acceptable for an EDR's required permissions).
- Headless hosts with no GUI session: Apple provides no path to activate a system extension without a user session; known limitation.
