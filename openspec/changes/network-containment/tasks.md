# Tasks

## Network extension

- [x] Measure containment semantics on edr-dev: filter settings against per-flow verdicts, established connections, provider stop and restart, DHCP and DNS under a narrow lifeline.
- [x] Decode and validate `network_containment.update`, order updates by epoch then version, and accept a lifeline refresh at the same version.
- [x] Persist accepted state and apply it as a starting filter's first settings.
- [x] Apply containment as filter settings with the lifeline allowed and everything else dropped; restore the telemetry settings on release.
- [x] Report containment status to the agent after each change and on hello.
- [x] Route `network_containment.update` through the shared XPC server to the network extension.
- [x] VM: contain and release edr-dev from a hand-sent update; containment survives an extension restart; the lifeline, DHCP and direct DNS keep working; established connections elsewhere are cut.

## Later steps

- [ ] Agent command, lifeline resolution and refresh, status reporting.
- [ ] DNS proxy answers only the server name while contained.
- [ ] Server state, API, audit, delivery and host API.
- [ ] Console actions and state.
