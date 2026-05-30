# Tasks

## Extension

- [x] Subscribe to `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`; emit `btm_launch_item_add`.
- [x] Evaluate the registered executable's code-signing out-of-band via `SecStaticCode`; emit `executable_code_signing`.
- [x] Run `SecStaticCodeCheckValidity` with `.noNetworkAccess` (no network on the ES callback thread).
- [x] Decision: notarization is NOT a trust signal (not checkable network-free in-process; Apple notarizes malware). The
      `is_notarized` field was removed; trust is platform-binary + team-ID allowlist. Notarization/reputation, if pursued,
      is server-side.

## Wire contract

- [x] Add `btm_launch_item_add` event + `executable_code_signing` to `schema/events.json`.
- [x] Swift `BtmLaunchItemAddPayload` + Go `btmLaunchItemAddPayload` carry the field; round-trip tests both sides.

## Rule

- [x] `privilege_launchd_plist_write` decides on `executable_code_signing` (platform binary / managed / team-ID
      allowlist), not the instigator; emits a process-less finding with a `launchdaemon:<item>` subject.

## Persistence

- [x] `alerts.process_id` nullable; `subject` dedup column; `uk_alerts_dedup` keyed on `subject`.
- [x] `InsertAlert` rejects a process-less alert with an empty subject (no collapse to `"0"`).

## Specs + traceability

- [x] Update canonical `server-detection-rules-engine` (persisted-alert-schema, alert-dedup-by-subject) and
      `endpoint-event-collection` (launch-item registration event) specs.
- [x] Cover the new normative scenarios with canonical-ID markers (spectrace `--strict` green).

## Validation

- [x] L0 unit + L1 integration + L6 efficacy green; runtime-confirmed on edr-dev.
- [ ] edr-qa L5 on a notarized RC: confirm the unsigned dropper fires and an allowlisted/platform daemon is trusted,
      on the notarized build where ESF process signing is not redacted (#187).
