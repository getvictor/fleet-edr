# Tasks

## Extension

- [x] The decider records the highest-precedence DETECT match, keeps walking for a PROTECT rule, and reports the match only on an allow.
- [x] The AUTH_EXEC dispatch emits `application_control_would_block` with the block payload, without a notification, and never caches that allow.
- [x] Document the event type in `schema/events.json` and `docs/api/openapi.yaml`, with a test keeping the two lists equal.
- [x] Unit tests, including an exhaustive check that DETECT rules never change the verdict; mutation-check them.
- [ ] Verify on a VM that a DETECT rule lets the exec run and the event reaches the server.

## Server

- [x] Accept enforcement on rule create and update, validate it, push it, and audit it; a create without it stays PROTECT.
- [x] `application_control_would_block` projection rule in monitor mode, with a fixture.
- [x] Restate the shared rules-engine requirements identically in `sensor-recovery-as-host-health`.
- [x] Integration tests for the API and for a would-block event becoming a monitor record; mutation-check them.
- [x] Document Detect mode in `docs/operations.md` and the changelog.

## Console

- [ ] Enforcement selector (defaulting to Detect), Promote to Protect, and a link to the rule's monitor records.
