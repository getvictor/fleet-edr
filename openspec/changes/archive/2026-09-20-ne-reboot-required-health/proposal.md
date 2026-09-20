# The console says when an agent upgrade needs a restart

Issue #985. After an in-place agent upgrade, macOS keeps the previous network extension registered until the Mac restarts, and its Mach service stays bound to that version, so the agent cannot connect to the new one and network and DNS telemetry stop. The agent already recognises this and logs a distinct "reboot to complete the extension cutover" warning, but its reported health for the network extension still read `never_connected`, "Network extension not activated". That points an operator at approving the extension, which is already approved, instead of restarting the Mac.

## What changes

- **The network extension reports `reboot_required`.** When the receiver logs its reboot-required signal, the agent also marks the `network_extension` component unhealthy with reason `reboot_required` and the message "Network extension: the previous version is still registered until the Mac restarts; restart it to finish the upgrade". The host's Details panel in the console shows it. The next established session replaces it.
- The reason vocabulary is open on the server, so no server or console change is needed.

## Out of scope

- Removing the need to restart, for example by giving the network extension a service name that re-registers on activation. The issue lists it as the most invasive option.
