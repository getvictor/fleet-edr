# Record capture-provider transitions as durable events: tasks

## 1. Extension carries the raw stop reason

- [x] `extension/edr/networkextension/ProviderLiveness.swift`: track the platform stop reason per stopped provider alongside the graded state, and clear it when a provider starts so a running provider never reports a stale reason from a previous stop. `ProviderStatusPayload` gains `stop_reasons` as a SEPARATE additive field rather than a richer `providers` value: the extension and agent ship together but skew across an upgrade, and an additive field degrades safely in both directions where a shape change would break liveness reporting on both sides at once.
- [x] `extension/edr/networkextension/ProviderStatusReporter.swift`: pass the reason through on a fault stop and publish the reason map.

## 2. Agent records transitions

- [x] `agent/sensorevent/transition.go`: diffs consecutive liveness reports and emits one event per real transition. The first report establishes a baseline instead of emitting, because the extension re-publishes on every handshake and emitting there would manufacture a transition out of every reconnect. A provider going absent never emits, since #649 reports a supported opt-out as absence. A failed emit deliberately does NOT advance the baseline, so the transition is retried rather than silently lost.
- [x] `agent/sensorevent/enqueue.go`: adapts the agent queue to the emitter seam and builds the ingest envelope. Refuses to emit before enrollment, because an event that cannot be attributed to a host is not evidence.
- [x] `agent/cmd/fleet-edr-agent/main.go`: `parseProviderStatus` returns the stop reasons alongside the graded states; the network-extension loop feeds the same report to health, self-heal and the recorder, so all three read one account of what is running.

## 3. Wire contract

- [x] `schema/events.json`: `sensor_provider_transition` event type and payload definition. No server change: ingest validates only that `event_type` is non-empty, so an unrecognised type is accepted and stored. Recovery is carried by the SUBSEQUENT running transition rather than by a remediation-outcome field, because whether a stop was repaired is not known when the stop happens and may never be answered at all.

## 4. Reuse

- [x] `internal/eventid`: the v4 UUID minting that `agent/reconcile` already had, extracted rather than cloned when a second caller appeared. `schema/events.json` declares `event_id` as uuid-format and the server dedups on it, so one implementation is what keeps the two producers agreeing by construction. The format and uniqueness test moved with the function.

## 5. Spec

- [x] `agent-status-reporting` delta: ADDED "Capture-provider transitions are recorded as durable events", "Transition records distinguish a fault from a supported configuration", and "A transition record is not lost to a transient failure".

## 6. Tests

- [x] `agent/sensorevent/transition_test.go`: baseline-not-emitted on first report, stop carries the raw reason, running carries none, repeated identical reports emit once, absence never emits, re-appearance after absence does emit, a failed emit is retried on the next report, missing `stop_reasons` still emits, an unrecognised state is not invented into an event, deterministic ordering.
- [x] `agent/sensorevent/enqueue_test.go`: the ingest envelope shape (a missing required field is a 4xx for the whole batch, not just this event), refusal before enrollment, and queue failures surfaced so the retry works.
- [x] `extension/edr/Tests/EDRExtensionLogicTests/ProviderLivenessTests.swift`: reason carried alongside the graded state, cleared on start, dropped on forget, encoded under the `stop_reasons` wire key, and a payload without it still decodes (the version-skew case).

## 7. Verification

- [x] `go test ./agent/... ./internal/...`, `go vet -tags integration`, builds for darwin, linux and windows. `agent/sensorevent` coverage 92.5%. `swift test` 224 tests.
- [x] `golangci-lint` (0 issues); `swiftlint --strict` (0 violations); `openspec validate sensor-provider-transition-event --strict`; spectrace 775/775 with 0 invalid references.
- [ ] Live macOS VM: pending.
