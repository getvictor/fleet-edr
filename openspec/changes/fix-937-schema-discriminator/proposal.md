# Select the event payload schema by event type

## Why

`schema/events.json` picked the payload with `payload.oneOf`, which requires EXACTLY ONE subschema to match. No payload definition sets `additionalProperties: false`, and `snapshot_heartbeat_payload` requires only `pid`, so every payload carrying a `pid` matched two definitions and `oneOf` failed. Ten of the fourteen documented event types were affected: `exec`, `exit`, `open`, `file_rename`, `network_connect`, `dns_query`, `application_control_block` and `application_control_undecided`, plus `file_truncate` and `file_delete` once #940 lands. An `exec` envelope has never validated against the document.

Nothing validated against it at runtime, so the defect was invisible. That is the reason to fix it rather than shrug: the document is cited as the wire contract in eight places across the agent, the extension, the server and the UI, and three emitters mirror it by hand (`test/fakeagent`, `test/e2e/fixtures/agent.ts`, and the extension's Swift payload structs). A reader is entitled to expect it validates the events we actually send.

Issue #937 offered `additionalProperties: false` as an alternative. It cannot work here: `file_truncate_payload` and `file_delete_payload` have identical required AND property sets, so `{"pid": 1, "path": "/x"}` matches both no matter how strict each definition is. Only discriminating on `event_type` distinguishes them, which makes it the sole viable option rather than the preferred one.

## What changes

- `schema/events.json` selects the payload with a top-level `allOf` of `if`/`then` clauses keyed on `event_type`, one per enum value. `payload` itself becomes a plain object.
- `test/fakeagent` emits a real UUID for `event_id`. The document declares `format: uuid` and the production agent (`uuid.New`), the extension (`UUID().uuidString`) and the TypeScript twin (`crypto.randomUUID()`) all honour it; the fake agent emitted a bare 32-character hex string and was the one emitter that did not. The new validation test found this, which is the drift it exists to catch.
- Four tests in `test/fakeagent/schema_test.go` validate against the document with `santhosh-tekuri/jsonschema/v6`, already present in the module graph as an indirect dependency and promoted to direct.

Payload definitions deliberately keep `additionalProperties` unset. With `event_type` doing the discrimination, forbidding extra keys would no longer buy correctness, and it would make the document stricter than the ingest path, which tolerates unknown fields. The consequence is stated plainly: a payload carrying the required fields of its own type plus extra keys is accepted, so a body belonging to a type whose required set is a subset of another's is not rejected on shape alone.

## Impact

- Affected specs: `endpoint-event-collection`
- Affected code: `schema/events.json`, `test/fakeagent/option.go`, `test/fakeagent/schema_test.go`, `go.mod`, `go.sum`
- No runtime behavior changes. The schema is documentation and a test fixture; no server or agent code path validates against it. What changes is that the document now says what the system already does, and a test keeps it that way.
