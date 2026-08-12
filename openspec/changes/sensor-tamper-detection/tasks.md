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
- [x] `scripts/uat/scenarios/sensor-tamper/`: the asserted L5 driver, so the live path is exercised by a harness rather than by hand. It switches off the real content filter, confirms the extension reported the stop, waits out the self-heal so the host is left capturing, and lets the driver poll `/api/alerts`. That covers the four pieces of production code upstream of the rule that the synthetic corpus never executes: the extension noticing, grading the stop a fault rather than an opt-out, the agent diffing liveness into an event, and the event reaching the server.
- [x] `test/fakeagent`: `sensor_provider_transition` support. `stop_reason` is a pointer and is omitted when unset, because platform reason 0 is a real value and defaulting would assert something the scenario never said.

## 5. Verification

- [x] Live macOS VM (edr-dev, macOS 26.3) against `task dev:server`, reading the alerts out of MySQL and the transitions out of ClickHouse rather than trusting agent logs. All four QA steps on issue #684:

  **1. A mandatory provider switched off alerts, and the alert outlives the repair.**

  | time (UTC)   | event                                                              |
  | ------------ | ------------------------------------------------------------------ |
  | 16:44:47.517 | `content_filter stopped`, platform reason 1                         |
  | 16:44:56.545 | alert 1811 raised, 9.0s after the stop                              |
  | 16:45:23.235 | `content_filter running`, the self-heal, 35.7s after the stop       |
  | 16:45:25     | `host_health` back to `healthy / activated`                         |

  Health carries no trace that anything happened; the alert is the only surviving record. That contrast is the whole reason the change exists.

  **2. The opt-in DNS proxy switched off is silent.** No transition recorded at all (not a suppressed one), so the rule had nothing to judge, and health continued to report the host healthy. 64s of polling, no alert.

  **3. An upgrade cutover does not fire.** Extension versions bumped 26 to 27 and re-activated, which is the same replacement the pkg postinstall triggers:

  | time (UTC)   | event                                       |
  | ------------ | ------------------------------------------- |
  | 16:51:30.520 | `content_filter stopped`, platform reason 1 |
  | 16:51:31.537 | `content_filter running`, 1.017s later      |

  Alert count unchanged. The stop reason is byte-identical to the tamper in step 1, so this is the direct demonstration that reason-based discrimination would have alerted here and the recovery window does not. The measured 1.017s also confirms the 1.1s the design was built on.

  **4. Exhausting the self-heal budget alerts, but the alert does not say so.** With the repair path broken, the three attempts failed and the agent logged "giving up on re-enabling capture provider; operator action required". The stop alerted (alert 1812, 13s after the stop, correct: it never recovered) and `host_health` reported `unhealthy / self_heal_failed` naming the provider. But the alert's own text is IDENTICAL to the step-1 alert that healed 35s later. Issue #684 asks for the alert to distinguish the two; it does not. This is the gap called out under "Not covered" below, now measured rather than predicted.

## 6. Not covered

- [ ] The upgrade-cutover half is not automated in L5: reproducing it mutates installed extension versions and reliably drops SSH mid-cutover. Verified manually (1.017s resume, no alert) and pinned on every L6 run by `test/efficacy/noise/agent-upgrade-cutover.yaml`.
- [ ] The remediation outcome on the alert, which issue #684 asks for. Whether the repair succeeded is not known when the stop must be reported. Called out in the proposal with the honest way to get it later.
- [ ] A full pkg install, blocked by a separate defect found while attempting it: `task pkg:dryrun` produces a package whose app bundle AND both nested extensions carry only `get-task-allow`, because the dry-run path skips the entitlements re-sign that the release path performs. An app in that state cannot activate its extensions at all, so a dry-run install can never exercise the install path's most failure-prone step. Filed as #689. The cutover in step 3 above exercises the same extension replacement the postinstall triggers, so the rule's discriminator is verified against a real cutover even though a full pkg install is not.
