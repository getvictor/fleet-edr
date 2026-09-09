# Correct the block-event ingest contract to the fields the wire carries

## Why

`server-application-control/Application control block event contract` says every `application_control_block` event MUST carry `rule_identifier`, `matched_identifier`, `process` and `ancestry`. The wire has never carried any of them, and the requirement omits three fields it does carry.

Four sources agree against the spec:

| Source | Fields |
| --- | --- |
| `EventSerializer.swift`'s block payload | `pid`, `path`, `rule_id`, `rule_type`, `identifier`, `severity`, `custom_msg`, `custom_url`, `policy_id`, `policy_version` |
| `schema/events.json` `application_control_block_payload` | the same ten |
| the server's decoder in `application_control_block.go` | the same ten |
| the requirement | four fields that appear in none of them |

`rule_identifier`, `matched_identifier` and `ancestry` appear nowhere in `server/` or `extension/` outside the test that pins their absence.

This is the same defect #931 found and fixed on the extension side. Application control declared its block event twice, once in `extension-application-control` and once here, and the in-flight `appcontrol-spec-owned-by-the-extension-capability` change corrected only the extension copy. This is the other half: a requirement that has been describing a wire shape that does not exist, on the ingest side, where an implementer reading it would build a decoder for fields no agent sends.

## What changes

The field list is corrected to what the four sources agree on, and the `identifier` clause explains what the value is, matching the wording the extension-side fix uses so the two copies say the same thing rather than drifting again.

Both scenarios are kept verbatim. They are accurate, they are covered by markers in `server/detection/internal/tests/integration_test.go`, and rewriting them would have orphaned that coverage for no gain.

## The clause canonical dropped, and why it stays dropped

`archive-verify` reports that the archived restatement also required the server to "log a server-side warning for operator visibility on the unknown-rule path", which canonical does not. That is not restored: nothing logs such a warning. `application_control_block.go` has no warning on the unknown-rule path and no logging of any kind for it.

Dropping an unimplemented SHALL is a legitimate narrowing rather than a loss, and restoring it would put a requirement in the canonical tree with nothing to test. If the warning is wanted, it is a feature with a code change, not a spec repair.

## Impact

- Affected specs: `server-application-control`
- Affected code: none
- No behaviour changes. The ingest path already accepts exactly these fields; only the description was wrong.
