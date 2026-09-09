# Application control is specified once, in the extension capability

## Why

The #905 audit lists nineteen `endpoint-event-collection` scenarios that an archived change declared and the canonical spec does not carry. Restoring them was the obvious repair and is the wrong one. Every archived application-control change declared the same behaviour TWICE, once under `endpoint-event-collection` and once under `extension-application-control`:

| Behaviour | `endpoint-event-collection` (dropped) | `extension-application-control` (canonical) |
| --- | --- | --- |
| Deny on a BLOCK match | `Process exec authorization` (3 MODIFIED versions) | `Precedence walk`, `AUTH_EXEC denial on BLOCK match`, `Deadline-guarded synchronous SHA-256 for BINARY rule consultation`, `Deadline fallback posture` |
| Block event | `Application control block event kind` | `Block event emission` |
| Undecided event | `Application Control undecided event kind` | `Application Control undecided event` |
| Would-block event | `Application control would-block event kind` | `Detect-mode allows the exec and emits a would-block event` |
| Exec event per decision | `Every AUTH_EXEC decision emits a corresponding exec event` | `Every AUTH_EXEC decision emits a regular exec event` |

The archive kept one copy of each pair. That is the right outcome reached by accident, and restoring the other copy would undo it. The two copies have also drifted apart, so restoring would put two contradicting requirements in the canonical tree: the dropped `Process exec authorization` says the walk is `CDHASH → BINARY → SIGNINGID → TEAMID` and stops as soon as a BINARY consultation is uncertain, while the surviving `Precedence walk` says `CDHASH → BINARY → CERTIFICATE → SIGNINGID → TEAMID → PATH` and continues past BINARY uncertainty so a definitive lower-precedence deny can dominate it. The code does the second, and the first describes a bypass that was fixed under review before it shipped.

So seventeen of the nineteen scenarios are already specified and need nothing. What the audit did surface is three real defects, which is why this change exists rather than a note closing the finding.

## What changes

**One field is genuinely unspecified.** The `exec` event carries `cdhash`, the extension serializes it, `web-ui` requires the process panel to display and copy it, and `server-detection-rules-engine` reads it to suppress a `suspicious_exec` finding by signing identity. No collection requirement says the event carries it, so two consumer requirements depend on a producer field with no producer requirement. `Process lifecycle event capture` already owns the exec event's field list and gains it there, rather than a whole duplicate requirement being restored around it.

Restored as a corrected statement rather than the archived text. The dropped requirement also claimed the exec event carries `leaf_cert_sha256`; it does not, the string does not appear in `schema/events.json` at all, and the leaf certificate hash is a decision-time lookup that the spec elsewhere requires NOT to block the AUTH callback. Restoring that sentence would have written a field that has never existed into the canonical event contract.

**`Process exec authorization` still described the singleton blocklist** that application control replaced. It says the system evaluates every exec "against the active blocklist" and denies when "the target binary path is on the blocklist". Three archived changes rewrote it and the archive applied none of them. It is **removed** here rather than rewritten. Every clause a rewrite would carry is already canonical elsewhere: `extension-application-control/AUTH_EXEC denial on BLOCK match` states that a `BLOCK` / `PROTECT` match is denied so the new image does not run and that any other outcome is allowed, and `Process lifecycle event capture` in this capability already states that an exec emits an `exec` event. A rewrite would re-create the duplicate that caused the drift.

**`Block event emission` lists four fields the event does not carry.** It requires `rule_identifier`, `matched_identifier`, `process`, and `ancestry`. The extension emits `pid`, `path`, `rule_id`, `rule_type`, `identifier`, `severity`, `custom_msg`, `custom_url`, `policy_id`, `policy_version`; `ancestry` appears zero times in `schema/events.json`, and the server's `application_control_block` catalog rule decodes exactly the shipped set. Both sides of the wire agree with each other and disagree with the requirement. The field list is corrected to the shipped one, keeping the semantics the requirement was actually asserting: the identifier on the event is the value from the target tuple that caused the match, not the rule's own identifier.

## Marker drift found alongside it

Three spec markers resolve, so the gate is green, and none of them is attached to a test of its scenario.

- `process-exec-authorization/an-exec-of-a-blocklisted-path-is-denied` and `.../an-exec-of-a-non-blocklisted-path-is-allowed` sit on two `ApplicationControlStore` tests that assert rules route into their typed maps. Their comments concede the gap in prose. They move to a new `Snapshot persistence format is typed` scenario that describes what they test.
- `block-event-emission/a-block-emits-a-block-event-whose-matched-identifier-matches-the-rule-type` sits on a test of `decideAuthExec`'s return value, which emits no event. A test of the serialized payload is added and takes the marker.

## Review found a fourth defect, in the requirement this change added

The `cdhash` requirement as first written was a biconditional: carried when the process runs under the Hardened Runtime, omitted otherwise. That is wrong, and it would have written a rule the product violates. `cdhashHexString` returns nil for an all-zero kernel value, so a HARDENED process whose reported hash is all zeros carries no `cdhash` either. Emitting the zeros instead would be worse than omitting them, because a `CDHASH` rule whose identifier is forty zeros would then match every such exec by coincidence.

The requirement now names both omission cases and why each is deliberate.

That branch had **no test at all**, which is how the gap survived my own review: the payload-level tests construct `ExecPayload` directly, so they can pair the Hardened Runtime flag with any hash the author likes, including one the kernel would never report. `CDHashHex.swift` sat outside the unit-testable target because it carried an `EndpointSecurity` import, and that import was unused: the only `es_` references in the file are in comments, and it compiles without it. Removing it moves the file into `EDRExtensionLogic` as a one-line `sources` edit, which the target's own header comment invites, and the all-zero rejection now has a test. The companion case, a real hash whose only non-zero byte is the last, is tested too, because an implementation checking a prefix rather than the whole array would silently drop `cdhash` from every event carrying a hash shaped like that.

## The two new serializer tests pin whole payloads, not fragments

Both originally asserted selected JSON fragments with `contains`. The encoder uses `.sortedKeys`, so the bytes are deterministic and one equality assertion is available, and it is the stronger one here: a substring check cannot fail when a field is ADDED. That is exactly the direction this change is about, since the defect being fixed is a requirement claiming four fields the wire never carried. The four absence assertions stay alongside the literal, because a literal alone would not say which four the requirement invented if this regresses.

## Impact

- Affected specs: `endpoint-event-collection`, `extension-application-control`
- Affected code: one unused `import EndpointSecurity` removed from `CDHashHex.swift`, and that file moved from the SwiftPM target's `exclude` list to its `sources` list so its all-zero rejection can be tested. No behaviour changes; every statement here is corrected to match shipped behaviour, and the tests added are new coverage of behaviour that already exists.
