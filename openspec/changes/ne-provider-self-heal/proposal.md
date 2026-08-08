# Restore stopped network extension capture providers automatically

## Why

A network extension capture provider that stops takes the host's network and DNS telemetry with it, and today nothing brings it back. The host stays blind until a human notices the health alert and runs the host app's `activate` by hand. For a security product that is the wrong failure mode twice over: the blind window is unbounded, and it is exactly the window an attacker who disabled the sensor operates in.

Two triggers are already on record for the same end state:

- **Agent pkg upgrade** (dogfood, 2026-07-08, host `B7D79E29`, v0.4.0-rc.1). `exec` and `fork` stayed current while `network_connect` and `dns_query` stopped dead at the upgrade. The Endpoint Security extension recovers on its own, so process telemetry keeps flowing and the outage is easy to miss.
- **A disable then re-enable of the network extension from System Settings** (dogfood, 2026-07-17). The extension process relaunches with no provider sessions at all.

Install-time activation is not the missing piece. The pkg postinstall has re-run the activation LaunchAgent on upgrade since #357 (it bootstraps into the console user's GUI domain, and falls back to `launchctl kickstart` when the agent is already loaded), and that code was present in the very pkg that failed. Activation runs; the providers still end up disabled. Anything that keys on the cause therefore misses cases, because the causes are not enumerable: an upgrade, a settings toggle, a half-failed activation and a staged reboot cutover all end in the same place.

What changed is that the end state is now observable. #649 made the agent grade `network_extension` health on which providers report themselves running, so "nothing is capturing" is a signal the agent holds rather than something only a human could infer from event freshness on the server.

## What changes

- **The agent restores a stopped capture provider itself.** When the network extension reports a provider stopped and it stays stopped past a short grace window, the agent re-enables it through the host app's `enable-filter` / `enable-dns-proxy` subcommands.
- **Remediation is driven by outcome, not by cause.** The trigger is "a provider that should be capturing is not", so the same mechanism covers the upgrade, the settings toggle and any future trigger nobody has seen yet.
- **A deliberately disabled provider is never touched.** #649 already reports an operator-disabled DNS proxy as ABSENT from the provider map rather than as stopped, and only a stopped provider is remediated. Without that distinction this feature would fight the operator who turned the opt-in DNS proxy off, so the two are a package.
- **Attempts are bounded and back off.** Repeated failure means the fault is not the kind re-enabling fixes, and a repair loop that retries forever would hide it. After the attempt budget is spent the component reports a distinct reason, so "self-heal is working on it" and "self-heal gave up, a human is needed" are different operator-visible states.
- **No GUI session is required.** `OSSystemExtensionRequest` must come from a user Aqua session, but the `NEFilterManager` / `NEDNSProxyManager` save that enables a provider does not. Measured on edr-dev: `edr enable-filter` run as plain root, with no `launchctl asuser` wrapper, brought the content filter back 13 seconds later. So the agent's root LaunchDaemon can remediate directly, including at the loginwindow where no console user exists.

## What this deliberately does NOT do

- **It does not re-activate the system extension.** A component that reports `never_connected` has no extension to talk to, and recovering that needs `OSSystemExtensionRequest` from a logged-in user's session. That path is both partial (it cannot work at the loginwindow) and the fragile one: re-activation has repeatedly broken flow delivery during QA. It is tracked separately so it gets its own validation rather than gating this fix.
- **It does not yet write a durable record of the remediation to the server.** A provider being switched off and silently restored is tamper-adjacent evidence an analyst should keep, but health is level state: once the heal succeeds the component reads healthy again and the history is gone. Carrying that properly means a new event type, which touches `schema/events.json`, server acceptance and the UI, so it ships as its own change rather than being half-done here. Until then the remediation is in the agent's structured logs and in the escalation reason when it fails.
