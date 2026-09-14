# Tasks

## Extension

- [x] The decider records the highest-precedence DETECT match, keeps walking for a PROTECT rule, and reports the match only on an allow.
- [x] The AUTH_EXEC dispatch emits `application_control_would_block` with the block payload, without a notification, and never caches that allow.
- [x] Document the event type in `schema/events.json` and `docs/api/openapi.yaml`, with a test keeping the two lists equal.
- [x] Unit tests, including an exhaustive check that DETECT rules never change the verdict; mutation-check them.
- [x] Verify on a VM that a DETECT rule lets the exec run and the event reaches the server.

## Server: would-block records

- [x] `application_control_would_block` projection rule in monitor mode, with a fixture.
- [x] Restate the shared rules-engine requirements identically in `sensor-recovery-as-host-health`.
- [x] Integration test for a would-block event becoming a monitor record; mutation-check it.

## Enforcement and console

- [ ] Require enforcement on rule create and bulk upsert, and change it on update.
- [ ] Enforcement choice in the console's add and paste forms, Promote to Protect, and a rule's would-block impact.
