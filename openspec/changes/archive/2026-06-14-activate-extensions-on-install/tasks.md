# Activate extensions on install: tasks

## 1. Packaging

- [x] New LaunchAgent `packaging/pkg/com.fleetdm.edr.activate.plist` (RunAtLoad, runs `Fleet EDR.app/Contents/MacOS/edr activate`).
- [x] `build.sh`: stage the plist into `app-root/Library/LaunchAgents/` on both the dry-run and release branches.
- [x] `postinstall`: bootstrap the LaunchAgent into `gui/<console-uid>` when a user is on console; fix the false "LaunchDaemon activates the sysext" comment; never fail the install.
- [x] `preinstall`: bootout the LaunchAgent on upgrade before the app bundle is replaced.
- [x] `uninstall.sh`: bootout the LaunchAgent and remove the plist.

## 2. CI + spec

- [x] `pkg-dryrun.yml`: lsbom check that app.pkg contains `Library/LaunchAgents/com.fleetdm.edr.activate.plist`.
- [x] `release-packaging` spec: ADDED requirement "Installation activates the system extensions" with scenarios for install-while-logged-in, install-at-loginwindow, and uninstall cleanup; markers in postinstall, pkg-dryrun.yml, and uninstall.sh.

## 3. Docs

- [x] `docs/mdm-deployment.md`: correct the activation claim and add the activation step to the install-flow list.
- [x] `docs/fleet-deployment.md`: verify section notes activation fires at install time (or next login when installed at the loginwindow).
- [x] `docs/install-agent-manual.md`: note the LaunchAgent retries activation at each login on unmanaged Macs.

## 4. Verification

- [x] `plutil -lint` the LaunchAgent; shellcheck postinstall/preinstall/uninstall.sh; actionlint; `openspec validate`; spectrace.
- [x] edr-qa VM: emulate the postinstall path (copy plist, `launchctl bootstrap gui/501`) and confirm both extensions reach `activated enabled` silently and the agent's `receiver connect` warnings stop.
