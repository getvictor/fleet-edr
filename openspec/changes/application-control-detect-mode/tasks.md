# Tasks

## Extension

- [x] The decider records the highest-precedence DETECT match, keeps walking for a PROTECT rule, and reports the match only on an allow.
- [x] The AUTH_EXEC dispatch emits `application_control_would_block` with the block payload, without a notification, and never caches that allow.
- [x] Document the event type in `schema/events.json`.
- [x] Unit tests, including an exhaustive check that DETECT rules never change the verdict; mutation-check them.
- [ ] Verify on a VM that a DETECT rule lets the exec run and the event reaches the server.

## Server and console

- [ ] Accept enforcement on rule create and update, and choose the default for new rules.
- [ ] Record would-block matches for operators.
- [ ] Enforcement selector, Promote to Protect, and the would-block view in the console.
