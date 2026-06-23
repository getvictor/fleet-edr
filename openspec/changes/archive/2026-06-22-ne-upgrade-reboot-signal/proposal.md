# Surface "reboot required" after a sysext upgrade leaves the NE registration stale

## Why

After a signed-pkg **upgrade** replaces the system extensions, macOS defers removing the previous version until reboot. During that window the network extension's Mach service `group.com.fleetdm.edr.networkextension` (owned by `nesessionmanager`, not the extension process) stays bound to the OLD, `terminated waiting to uninstall on reboot` extension. The new NE runs and captures, but the agent's `xpc_connection_create_mach_service` resolves the stale registration and never gets a hello-ack. The agent silently loses all network + DNS telemetry until the host reboots, and the only signal is a bare `xpc_bridge_connect failed` WARN that is indistinguishable from the benign "NE not approved yet" state (#399).

The Endpoint Security extension is unaffected: it vends a team-prefixed `NSEndpointSecurityMachServiceName` it re-registers itself on activation, so it cuts over without a reboot. Only the NE (nesessionmanager-owned service) is stuck. Observed live on a v0.1.1 to v0.2.1 upgrade.

## What changes

- **Host app surfaces a reboot-required signal.** The `OSSystemExtensionRequest` delegate already reports `.willCompleteAfterReboot`, which the host app folds into an `AggregateVerdict.rebootRequired`. On that verdict the activate path emits a distinct, operator-facing log line ("Fleet EDR upgrade staged; reboot to finish the extension cutover and restore network + DNS coverage") instead of only the generic info log. A fresh install reports `.allSucceeded` (no prior version to evict), so it gets no prompt.
- **Agent emits an actionable hint instead of the bare warning.** When the NE receiver has failed to connect for more than a grace period (a small number of consecutive reconnect failures) AND a pending-uninstall old NE version exists, the agent logs a distinct WARN ("Network Extension XPC registration is stale after an upgrade; reboot to complete the cutover") and (optionally) increments a counter, so the "endpoint rejecting / stale after upgrade" state reaches the server-side log/telemetry surface. The bare warning stays for the genuine not-yet-approved case, which has no pending-uninstall version.
- The agent learns "a pending-uninstall old NE version exists" by reading the OS's own system-extension state (`systemextensionsctl list`, matched on the NE bundle id + the `waiting to uninstall on reboot` phrase). The detection is behind an injectable probe so it is unit-testable and so a future host-app marker could replace it without touching the receiver logic.

### Not in this change

- The GUI user-notification popup (`UNUserNotificationCenter`). The host app is a short-lived CLI-style process whose lifecycle + notification authorization make a reliable popup a separate effort; the reliable operator signal here is the os_log line (which the manual-install docs and MDM reference). Tracked as a follow-up.
- Forcing `nesessionmanager` to rebind without a reboot (issue stretch goal). Disable/enable-filter and bouncing `nesessionmanager` are confirmed non-fixes; on SIP-on there is no known way to evict an extension already waiting to uninstall short of reboot. Investigation only, out of scope for the code change.

## Impact

- Affected capabilities: `agent-xpc-receiver`, `host-app-extension-manager`.
- Affected code: `agent/receiver/` (grace-period tracking + the upgrade-pending probe + the distinct log), `agent/cmd/fleet-edr-agent/main.go` (wire the probe into the NE loop only), `extension/edr/edr/ExtensionManagerLogic.swift` + `main.swift` (the reboot-required decision + log line).
- No wire-format, schema, or server change. Verification needs a signed-pkg upgrade on the edr-qa VM (two notarized builds), which is the legitimate upgrade path (not the binary-swap method).
