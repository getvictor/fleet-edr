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

## DNS proxy

- [x] Carry the lifeline's host names in the containment document, validated and normalized.
- [x] While contained, forward only single-question queries for those names, answer the rest REFUSED, drop non-queries, and close DNS over TCP.
- [x] VM: while contained, the server's name resolves, other names are refused (including queries addressed to another resolver), DNS over TCP gets nothing; release restores DNS.

## Server

- [x] Record each host's desired containment, versioned with a change-time epoch, and queue `set_network_containment` on a change.
- [x] `POST` and `GET /api/hosts/{host_id}/containment` with `host.isolate` and `host.read`, a required reason, and `host.contain` / `host.release` audit events.
- [x] Catch-up every five minutes for hosts whose latest command does not deliver their state.
- [x] Refuse `isolate` and `set_network_containment` on the generic command endpoint.
- [x] Dev server and VM: contain and release edr-dev through the API.

## Console

- [x] `GET /api/containment` for the host list.
- [x] Containment badge and Contain host / Release host with a reason on the host header, polling while a change is on its way.
- [x] Containment badges on the host list.
- [x] Chrome: contain and release edr-dev from the host page.

## Acceptance

- [x] L5 scenario `network-containment`: contain through the API, assert from a probe on the VM that only the server stays reachable and other names are refused, release, assert the network is back; passes on edr-dev, fails when the probed destination is inside the lifeline, and releases the host when it fails while contained.
- [x] VM: containment holds through a reboot, and the rebooted host is released from the server.
- [x] Operator guide (`docs/operations.md`), RC runbook step for edr-qa, and CHANGELOG.
