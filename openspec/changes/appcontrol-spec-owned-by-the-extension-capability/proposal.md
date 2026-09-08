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

**`Process exec authorization` still describes the singleton blocklist** that application control replaced. It says the system evaluates every exec "against the active blocklist" and denies when "the target binary path is on the blocklist". Three archived changes rewrote it and the archive applied none of them. It is rewritten here to state only what this capability owns, an allowed exec emits an `exec` event and a denied one does not run, and to name `extension-application-control` as the owner of the decision itself. That removes the duplicate instead of re-creating it.

**`Block event emission` lists four fields the event does not carry.** It requires `rule_identifier`, `matched_identifier`, `process`, and `ancestry`. The extension emits `pid`, `path`, `rule_id`, `rule_type`, `identifier`, `severity`, `custom_msg`, `custom_url`, `policy_id`, `policy_version`; `ancestry` appears zero times in `schema/events.json`, and the server's `application_control_block` catalog rule decodes exactly the shipped set. Both sides of the wire agree with each other and disagree with the requirement. The field list is corrected to the shipped one, keeping the semantics the requirement was actually asserting: the identifier on the event is the value from the target tuple that caused the match, not the rule's own identifier.

## Marker drift found alongside it

Three spec markers resolve, so the gate is green, and none of them is attached to a test of its scenario.

- `process-exec-authorization/an-exec-of-a-blocklisted-path-is-denied` and `.../an-exec-of-a-non-blocklisted-path-is-allowed` sit on two `ApplicationControlStore` tests that assert rules route into their typed maps. Their comments concede the gap in prose. They move to a new `Snapshot persistence format is typed` scenario that describes what they test.
- `block-event-emission/a-block-emits-a-block-event-whose-matched-identifier-matches-the-rule-type` sits on a test of `decideAuthExec`'s return value, which emits no event. A test of the serialized payload is added and takes the marker.

## Impact

- Affected specs: `endpoint-event-collection`, `extension-application-control`
- Affected code: none. Every statement here is corrected to match shipped behaviour; the tests added are new coverage of behaviour that already exists.
