# Tasks

## Extension

- [x] Subscribe to `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`; emit `btm_launch_item_add` carrying `executable_path`.
- [x] Decision: notarization is NOT a trust signal (not checkable network-free in-process; Apple notarizes malware). The
      `is_notarized` field was removed; trust is platform-binary + team-ID allowlist. Notarization/reputation, if pursued,
      is server-side.

## Agent

- [x] Evaluate the registered executable's code-signing out-of-band via `SecStaticCode` in the agent (an unsandboxed root
      daemon), filling `executable_code_signing` before upload. The system extension cannot do it: a SIP-enabled host's
      sandbox denies the read of the registered executable (ground-truthed on edr-qa). Doing it in the agent also keeps
      the evaluation off the ES callback thread.
- [x] Run `SecStaticCodeCheckValidity` with `kSecCSNoNetworkAccess` (never block on an OCSP/CRL fetch).
- [x] Fill-if-missing + non-destructive: a pre-populated `executable_code_signing` (e.g. a synthetic test feed) is left
      untouched; the linux headless build's evaluator is a no-op stub.

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
- [ ] edr-qa L5 on a notarized RC (rc.4, first build with agent-side signing): confirm the unsigned dropper fires and an
      allowlisted/platform daemon is trusted. This is the build that proves the agent reads the registered executable
      where the SIP-enabled extension sandbox could not.
