# Tasks

## Network extension

- [x] Measure containment semantics on edr-dev: filter settings against per-flow verdicts, established connections, provider stop and restart, DHCP and DNS under a narrow lifeline.
- [x] Decode and validate `network_containment.update`, order updates by epoch then version, and accept a lifeline refresh at the same version.
- [x] Persist accepted state and apply it as a starting filter's first settings.
- [x] Apply containment as filter settings with the lifeline allowed and everything else dropped; restore the telemetry settings on release.
- [x] Keep the released containment's server flows allowed on release, so the agent's connections opened while contained are not cut.
- [x] Report containment status to the agent after each change and on hello.
- [x] Route `network_containment.update` through the shared XPC server to the network extension.
- [x] VM: contain and release edr-dev from a hand-sent update; containment survives an extension restart; the lifeline, DHCP and direct DNS keep working; established connections elsewhere are cut.

## Agent

- [x] `set_network_containment` command: resolve the lifeline with a direct resolver query, send the extension its document, complete only on the extension's confirmation.
- [x] Dial the server through the lifeline while contained: agent transport, enrollment and token refresh, control channel (except through a proxy).
- [x] Refresh the lifeline every five minutes while contained, and once when a restarted agent learns the containment from the extension.
- [x] Consume `ne_containment_status` without uploading it.
- [x] VM: contain and release edr-dev through a server command; uploads and command delivery keep working while contained.

## Later steps

- [ ] DNS proxy answers only the server name while contained.
- [ ] Server state, API, audit, delivery and host API.
- [ ] Console actions and state.
