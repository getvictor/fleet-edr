# BTM LaunchDaemon persistence: executable-signing discriminator + process-optional alerts

## Why

`privilege_launchd_plist_write` (T1543.004) was migrated to key on the high-level Background Task Management event
`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD` (ADR-0008). The first implementation gated the detection on the BTM
**instigator's** code-signing. A direct capture on edr-dev (`ai/btm-attribution/experiment.md`) proved that wrong: for a
legacy `launchctl bootstrap`, the instigator is Apple's `smd` (`com.apple.xpc.smd`), a platform binary, for **every**
LaunchDaemon registration. Gating on the instigator therefore suppresses the canonical attack.

Two reviews (Copilot, Gemini) plus the ground-truth converge on the corrected design, captured in the ADR-0008
amendment (PR #305):

1. **Discriminate on the registered executable**, not the instigator: the rule fires when the registered executable is
   not an Apple platform binary, not notarized, not MDM-managed, and not on the operator's team-ID allowlist. The
   extension evaluates the executable's code-signing out-of-band (`SecStaticCode`), because the BTM event carries
   signing for the instigator/app processes but not for the to-be-launched executable.
2. **Process-optional alerts**: the registered executable has no live process at registration and the instigator (`smd`)
   is not the attacker, so a persistence alert carries no process link. `alerts.process_id` becomes a nullable
   enrichment FK, and alert dedup moves from `(source, host, rule, process_id)` to `(source, host, rule, subject)` so
   distinct registrations produce distinct alerts without a process row.

## What Changes

- **Persisted alert schema** (`server-detection-rules-engine`): the linked process identifier is now OPTIONAL; a
  process-less finding persists an alert with no process link.
- **Alert dedup** (`server-detection-rules-engine`): the dedup key is now `(source, host, rule, subject)`. For a
  process-backed finding the subject is its process id (preserving the historical dedup); a process-less finding's
  firing rule supplies the subject (the registered launch item).
- **Launch-item registration event** (`endpoint-event-collection`): the extension emits `btm_launch_item_add` carrying
  the registered executable's code-signing (`executable_code_signing`), evaluated out-of-band.

## Impact

- Schema: `alerts.process_id` becomes nullable; a `subject` column carries the dedup identity; `uk_alerts_dedup` keys on
  `subject`. The repo has no migration framework (CREATE TABLE IF NOT EXISTS); existing pilot DBs require a reset, per
  the established pre-1.0 pattern.
- Wire: `schema/events.json` gains `btm_launch_item_add_payload.executable_code_signing`.
- Validation: L0 unit + L1 integration + L6 efficacy green; runtime-confirmed on edr-dev. Real-world confirmation of the
  "trusted notarized vendor daemon" path is pending the edr-qa L5 run on a notarized build (ESF signing is redacted on
  the ad-hoc edr-dev extension, issue #187).
