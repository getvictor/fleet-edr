# Record capture-provider transitions as durable events: tasks

## 1. Extension carries the raw stop reason

- [x] `extension/edr/networkextension/ProviderLiveness.swift`: track the platform stop reason per stopped provider alongside the graded state, and clear it when a provider starts so a running provider never reports a stale reason from a previous stop. `ProviderStatusPayload` gains `stop_reasons` as a SEPARATE additive field rather than a richer `providers` value: the extension and agent ship together but skew across an upgrade, and an additive field degrades safely in both directions where a shape change would break liveness reporting on both sides at once.
- [x] `extension/edr/networkextension/ProviderStatusReporter.swift`: pass the reason through on a fault stop and publish the reason map.

## 2. Agent records transitions

- [x] `agent/sensorevent/transition.go`: diffs consecutive liveness reports and emits one event per real transition. The first report establishes a baseline instead of emitting, because the extension re-publishes on every handshake and emitting there would manufacture a transition out of every reconnect. A provider going absent never emits, since #649 reports a supported opt-out as absence. A failed emit deliberately does NOT advance the baseline, so the transition is retried rather than silently lost.
- [x] `agent/sensorevent/enqueue.go`: adapts the agent queue to the emitter seam and builds the ingest envelope. Refuses to emit before enrollment, because an event that cannot be attributed to a host is not evidence. The host id is read per event through `telemetryDeps.hostIDFn` (the token provider's live accessor, the same one `agent/reconcile` takes) rather than captured: a re-enrollment replaces the agent's identity, and tamper evidence stamped with the superseded id lands on a host that may no longer exist.
- [x] `agent/cmd/fleet-edr-agent/main.go`: `parseProviderStatus` returns the stop reasons alongside the graded states, plus a `Decoded` flag separating "the extension told us nothing is running" from "we could not read what it told us". Both yield an empty map and health treats them alike, but only a decoded report may move the transition baseline: feeding an unreadable one to the recorder would clear the baseline and make the next valid report look like a fresh set of transitions, inventing tamper evidence out of a parse error. the network-extension loop feeds the same report to health, self-heal and the recorder, so all three read one account of what is running.

## 3. Wire contract

- [x] `schema/events.json`: `sensor_provider_transition` event type and payload definition. No server change: ingest validates only that `event_type` is non-empty, so an unrecognised type is accepted and stored. Recovery is carried by the SUBSEQUENT running transition rather than by a remediation-outcome field, because whether a stop was repaired is not known when the stop happens and may never be answered at all.

## 4. Reuse

- [x] Shared v4 UUID minting: the generation `agent/reconcile` already had, extracted rather than cloned when a second caller appeared. `schema/events.json` declares `event_id` as uuid-format and the server dedups on it, so one implementation is what keeps the two producers agreeing by construction. This was the `internal/eventid` package, whose format and uniqueness test moved with the function; PR #806 superseded it with Go 1.27's standard-library `uuid`, which each producer now calls directly, so the package and its test were removed.

## 5. Spec

- [x] `agent-status-reporting` delta: ADDED "Capture-provider transitions are recorded as durable events", "Transition records distinguish a fault from a supported configuration", and "A transition record is not lost to a transient failure".

## 6. Tests

- [x] `agent/sensorevent/transition_test.go`: baseline-not-emitted on first report, stop carries the raw reason, running carries none, repeated identical reports emit once, absence never emits, re-appearance after absence does emit, a failed emit is retried on the next report, missing `stop_reasons` still emits, an unrecognised state is not invented into an event, deterministic ordering.
- [x] `agent/sensorevent/enqueue_test.go`: the ingest envelope shape (a missing required field is a 4xx for the whole batch, not just this event), refusal before enrollment, and queue failures surfaced so the retry works.
- [x] `agent/sensorevent/wire_pbt_test.go`: the `Unmarshal . Marshal == identity` round-trip the testing-strategy matrix requires for a new wire field, over the envelope ingest actually receives. The payload IS the evidence, so a field that silently fails to survive the round trip turns a recorded tamper into an event nothing can interpret, and it would be invisible at emit time.
- [x] `agent/cmd/fleet-edr-agent/providerstatus_test.go`: stop reasons decoded, an extension that sends none still decodes, and the pair that matters most: an undecodable payload is still a control message (so it stays out of the upload queue) but is NOT a usable transition baseline, while an explicitly empty provider set IS.
- [x] `extension/edr/Tests/EDRExtensionLogicTests/ProviderLivenessTests.swift`: reason carried alongside the graded state, cleared on start, dropped on forget, encoded under the `stop_reasons` wire key, and a payload without it still decodes (the version-skew case).

## 7. Verification

- [x] `go test ./agent/... ./internal/...`, `go vet -tags integration`, builds for darwin, linux and windows. `agent/sensorevent` coverage 92.5%. `swift test` 224 tests.
- [x] `golangci-lint` (0 issues); `swiftlint --strict` (0 violations); `openspec validate sensor-provider-transition-event --strict`; spectrace 775/775 with 0 invalid references.
- [x] Live macOS VM (edr-dev, macOS 26.3, sysext `1.1/23`) against `task dev:server`, reading the events out of the server's ClickHouse archive rather than trusting the agent's logs.

  **A mandatory provider switched off leaves durable evidence.** Stop reason 1 (`userInitiated`), graded a fault:

  | time         | event                                                                                 |
  | ------------ | ------------------------------------------------------------------------------------- |
  | 10:23:00.223 | extension: `content_filter stopped (reason 1); treating it as a fault`                 |
  | 10:23:00.313 | agent: recorded transition `state=stopped stop_reason=1`, 90ms after the extension     |
  | 10:23:37.910 | agent: self-heal restoring the provider                                                |
  | 10:23:38.118 | extension: `content_filter is running`                                                 |
  | 10:23:38.133 | agent: recorded transition `state=running`, no stop reason                             |

  On the server:

  ```
  {"provider":"content_filter","state":"stopped","stop_reason":1}
  {"provider":"content_filter","state":"running"}
  ```

  That pair is the whole point of the change, and the contrast with health makes it concrete: after the self-heal, `host_health` for this host reads `healthy / activated` and carries no trace that anything happened, while the two events still say the provider was switched off and came back 38 seconds later.

  **The opt-in DNS proxy leaves none.** Stop reason 9 (`configurationDisabled`) on the opt-in provider is graded deliberate, so #649 reports it ABSENT and no transition is recorded. Verified twice over: no agent log line, and the server-side count for the whole run was exactly 2, not 3.

  Re-enabling the DNS proxy afterwards did record a `state=running` transition, which is correct: absence to running is a real change and worth recording. It carries no stop reason, so a rule keyed on stops does not see it.

- [x] Re-verified after the review fixes, which changed the event path (the `Decoded` baseline guard and the live host-id lookup). Same host, agent restarted onto the fixed build: the server-side count went from 3 to exactly 5, the stopped/running pair and nothing else. `content_filter stopped stop_reason=1` at 15:41:25.745, `running` at 15:41:57.938. Exactly two is the assertion that matters here: the agent restart in the middle of this run means its first report after reconnect was a baseline, so any regression in that guard, or in the decoded-versus-unreadable distinction, would have shown up as extra events rather than missing ones.

- [ ] Not covered: an agent pkg upgrade. The rule in the follow-up change depends on an upgrade producing lifecycle stop reasons rather than operator-driven ones, and that has still never been observed on a real upgrade. It is the assumption most likely to make a naive rule fire fleet-wide, so it is called out here rather than discovered later.
