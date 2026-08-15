# Tasks

## 1. Wire contract

- [x] 1.1 Register `sensor_recovery_failed` and its payload in `schema/events.json`, documenting why it is a separate event rather than a field on the transition
- [x] 1.2 Teach the fake agent to emit it, so efficacy scenarios can drive it

## 2. Agent: report the escalation at the edge

- [x] 2.1 Give the self-heal controller an `Escalation` type carrying the provider, attempts, and which failure shape it hit
- [x] 2.2 Add the edge-triggered `OnEscalation` callback, fired where the budget is spent and NOT from the health re-assertion path
- [x] 2.3 Emit the durable event from `sensorevent`, rejecting a record that cannot name its provider
- [x] 2.4 Wire the two together in the agent, sharing one emitter with the transition recorder

## 3. Agent tests

- [x] 3.1 Contrast test: over the same reports, health is re-asserted repeatedly while the escalation fires exactly once
- [x] 3.2 Mutation-check that guard by moving the emission onto the health path and confirming the test fails
- [x] 3.3 Both failure shapes are reported distinctly
- [x] 3.4 A provider that comes back produces no escalation
- [x] 3.5 Wire round-trip property test for the new payload, matching the transition event's

## 4. Server: the rule

- [x] 4.1 `sensor_recovery_failed` rule at Critical, naming the provider, the attempt count, and the failure shape
- [x] 4.2 Register it, declare its platform, and update the three anti-drift rosters that pin the catalog
- [x] 4.3 Unit tests: severity, dedup subject, the two failure shapes, an unrecognised outcome, and every input it must ignore
- [x] 4.4 Regenerate the rule docs and the ATT&CK layer

## 5. Efficacy corpus

- [x] 5.1 Scenario feeding the full episode (stop, then exhaustion) and asserting BOTH alerts fire
- [x] 5.2 Register the event type with the fake agent's scenario validator, and run the L6 harness locally to prove it: both alerts fire within SLA and the noise lane stays clean. The harness needs `CGO_ENABLED=0` on macOS (its build tag excludes darwin+cgo) and only runs nightly in CI, so a corpus scenario that fails validation would otherwise go unnoticed until then
- [ ] 5.3 No `attack.sh`: reproducing this on a VM means deliberately breaking the repair path, which the issue's QA covers by hand rather than as an automated attack

## 6. Live QA on the VM (issue #691 QA steps)

Run on edr-dev 2026-08-15 against the real agent, extension, and dev server. One timeline covers all four:

```
12:17:15  content_filter stopped        self-heal repaired it
12:17:53  content_filter running        -> ONE alert: sensor_tamper (high)
12:20:11  content_filter stopped        repair path broken (chmod 000 on the host app)
12:22:33  sensor_recovery_failed        -> SECOND alert: sensor_recovery_failed (critical)
          enable_failed, attempts 3        142s after the stop: grace 30 + backoffs 30 and 60
12:28:19  content_filter running        restored by hand
```

- [x] 6.1 Disable the mandatory content filter and let the self-heal repair it: confirm ONE alert, unchanged from today. Repaired in 38s, matching the ~35.7s on record; alert 1819 only, no recovery-failed event or alert
- [x] 6.2 Break the repair path, disable the filter, let all three attempts fail: confirm a second, distinct alert naming the provider. Alerts 1820 (`sensor_tamper`, high) and 1821 (`sensor_recovery_failed`, critical), the latter reading "still stopped after 3 automatic repair attempts (every attempt to re-enable it failed)"
- [x] 6.3 Confirm host health still reports `unhealthy / self_heal_failed`, so the two surfaces agree. Confirmed, and it returned to `healthy` once the filter was re-enabled
- [x] 6.4 Confirm no second alert arrives on subsequent liveness reports while the provider stays stopped. Left stopped for a further 3 minutes with liveness republishing throughout: still exactly ONE event and ONE alert. This is the storm guard the unit test can only approximate, verified on real hardware
