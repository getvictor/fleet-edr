# Fix uninstall extension deactivation: tasks

## 1. Uninstall script

- [x] Replace the `systemextensionsctl deactivate` block with `launchctl asuser <console-uid> edr deactivate`, submitted before the app bundle is removed, targeting both extensions via the host app.
- [x] Bound the deactivation with a watchdog (`wait`-reaped) so a pending-approval request cannot hang the uninstall and no async "Killed" notification leaks.
- [x] Verify the result from live `systemextensionsctl list` state (active vs. staged-for-reboot) rather than an exit code.
- [x] Branch operator output: clean removal / reboot-to-finish / still-active-with-cause-specific-guidance (MDM profile, no console user, app missing).
- [x] Keep the app bundle + support dir (uninstall.sh) when extensions remain active, so the operator can retry.

## 2. Spec + traceability

- [x] `release-packaging` spec: MODIFIED "Uninstall path is deliverable" so the deactivation requirement reflects the host-app GUI-session mechanism, both extensions, the verify-and-guide behavior, and the MDM-managed limitation.
- [x] spectrace markers: `operator-runs-the-uninstall-script` and the new `uninstall-deactivates-both-extensions-via-the-host-app` scenario referenced from `uninstall.sh` and the script test.
- [x] CI assertion (`pkg-dryrun.yml`) on the shipped `uninstall.sh`: no `systemextensionsctl deactivate`; uses `launchctl asuser` + `"$APP_BIN" deactivate`. Carries the new scenario marker.

## 3. Docs

- [x] `docs/install-agent-manual.md`: uninstall section gains the reboot-to-finish note and the "extensions still active" recovery steps.
- [x] `docs/mdm-deployment.md`: managed-host removal is MDM profile removal (which deauthorizes and removes the extensions), not the local script.

## 4. QA

- [x] Reproduce the original bug on edr-qa (SIP on, MDM-managed): old script leaves both extensions `activated enabled`.
- [x] Verify the new script on edr-qa (MDM-managed): attempts deactivation, detects it is refused, keeps the app, prints the MDM-profile guidance.
- [x] Verify the new script on a non-MDM host (MDM controls disabled on edr-qa): `edr deactivate` removes the extensions or stages them for removal on reboot, and the script reports the observed outcome accurately. Verified 2026-06-25: both extensions advanced `activated_enabled -> terminated_waiting_to_uninstall_on_reboot` and the script printed the reboot-to-finish message.
