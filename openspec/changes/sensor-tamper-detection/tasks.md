# Detect tampering with the EDR's own sensor: tasks

## 1. The rule

- [x] `server/rules/internal/catalog/sensor_tamper.go`: fires on a capture-provider stop unless capture for the same provider resumes within `sensorRecoveryWindow` (5s). Process-less by design: the transition record says a provider stopped, not who stopped it, and attributing it to the extension's own pid would name the victim as the actor. The dedup subject carries the stop's event id, so the retry path collapses onto one alert while a separate stop later raises its own; keying on the provider alone would let last month's alert silently swallow today's tamper.
- [x] `sensorRecoveryGrace` (8s) bounds how long an undecided stop is held. It has to exceed the window, because a resumption at the far edge still needs uploading (1s agent interval) and archiving before the rule can see it. Inside the grace the rule raises the existing retryable sentinel and the processor re-evaluates; past it the stop is reported, so a recovery that never arrives cannot retry forever.
- [x] Registered in `registry.go`, darwin in `platforms.go`, no exclusions: there is no benign writer to allowlist, and the one supported way to run without a provider is to disable it, which never reaches the rule.

## 2. The correlation read

- [x] `server/visibility/api` + `internal/clickhouse`: `EventsByTypeForHost` returns one host's events of a single type within an EVENT-time range. The WHERE clause is the archive's sorting-key prefix `(host_id, event_type, timestamp_ns)`, so it is a primary-key range scan rather than a scan of the host's stream. Event time rather than ingest time because both events come from the same producer on one host and share a clock; the cross-stream reads bound on ingest time because they join producers whose clocks drift.
- [x] Row cap on the query. Events are agent-supplied, so the number of rows a host can put inside a window is host-controlled, and an unbounded correlation read is something a hostile agent could inflate. The cap is far above what an honest window holds.
- [x] `server/detection/api` `GraphReader.GetHostEventsByType` + the store delegation, the same post-ADR-0015 shape `GetNetworkEventsForProcess` already uses: the events live in ClickHouse, the rule reaches the detection store.

## 3. Spec

- [x] `server-detection-rules-engine` delta: MODIFIED the registered-rule catalog to include `sensor_tamper`, ADDED "EDR sensor tamper detection" with the recovery-window discrimination, the bounded wait, and the deliberate exclusion of an operator-disabled provider.

## 4. Tests

- [x] `sensor_tamper_test.go`: the discrimination table (1.1s cutover suppressed, 32s tamper alerts, never-resumed alerts) drives the rule with the MEASURED gaps and an identical stop reason on both sides, so a regression to reason-based judging fails here. Plus the window bounds (a resumption predating the stop is not a recovery from it), same-provider matching, the wait-then-decide timing, dedup subject identity, a broken archive read surfacing rather than being read as either answer, and a batch whose decided stop survives an undecided sibling (#661).
- [x] Mutation-checked: widening the window past the self-heal, dropping the provider comparison, unbounding the window on the left, and deciding immediately without waiting are each caught.
- [x] `test/efficacy/corpus/T1562.001-sensor-tamper/`: the attack scenario, closing the corpus's Impair Defenses gap.
- [x] `test/efficacy/noise/agent-upgrade-cutover.yaml`: the false-positive case that decides whether this is usable. It carries the same `stop_reason` as the attack scenario deliberately, so the two disagree if the rule ever regresses to judging on it.
- [x] `test/fakeagent`: `sensor_provider_transition` support. `stop_reason` is a pointer and is omitted when unset, because platform reason 0 is a real value and defaulting would assert something the scenario never said.

## 5. Verification

- [ ] Live macOS VM against `task dev:server`: the four QA steps on issue #684 (disable the mandatory filter, disable the opt-in DNS proxy, upgrade the agent pkg, exhaust the self-heal budget). BLOCKED: edr-dev cannot currently activate either extension, so it can neither produce a real cutover nor a real tamper. It needs rebuilding.

## 6. Not covered

- [ ] The remediation outcome on the alert, which issue #684 asks for. Whether the repair succeeded is not known when the stop must be reported. Called out in the proposal with the honest way to get it later.
- [ ] A real pkg upgrade, still never observed end to end. The rule is reason-agnostic so its design does not depend on one, but the noise scenario's 1.1s gap comes from an `edr activate` cutover rather than from a full pkg install.
