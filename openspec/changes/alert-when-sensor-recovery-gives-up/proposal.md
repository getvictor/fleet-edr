# Alert when automatic capture recovery gives up

## Why

The `sensor_tamper` alert reads identically whether the host repaired itself or was left blind. Measured on edr-dev during #690's QA:

- Alert 1811: the self-heal restored capture 35.7 seconds later. The host was fine.
- Alert 1812: every repair attempt failed, the agent logged `giving up on re-enabling capture provider; operator action required`, and the host was left **without capture**.

Both printed the same sentence, word for word. An analyst working an alert list cannot tell which hosts still need them, which is the difference between a closed ticket and a host that is silently not reporting.

#684's expected behavior asked for exactly this distinction ("stopped and self-healed, stopped and still stopped, or stopped and automatic recovery gave up"). It was deliberately left out of #690 and tracked as #691.

## What changes

The agent already knows the answer and already computes it: `selfheal`'s controller records an escalation when its attempt budget is spent, including which of the two failure shapes it hit. Today that goes only to health. This adds a durable event carrying it, and a rule that turns the event into a Critical alert naming the provider to restore.

## Why a second alert rather than amending the first

Alerts cannot be amended. `UpdateAlertStatus` is the only mutation the alerts store offers, and `InsertAlert` dedups on `subject`, so there is no path to rewrite the stop alert's text once the outcome is known. The literal reading of #684 (one record carrying the final outcome) would need new alert-amendment machinery.

Waiting for the outcome before raising anything is worse: it would delay or suppress the case that matters most, a provider that never comes back at all.

Two alerts is the shape the system can actually support, and it reads correctly on a timeline: capture stopped, then capture could not be restored. "Stopped and healed" stays a single alert, because nothing is required of the operator and a follow-up would be noise.

## Why an event and not a field on the transition

The transition event carries provider state changes, and the repair giving up is not one: the provider has not transitioned, it is still stopped, and what changed is that the agent stopped trying. The existing pair (stopped at T, running at T+36s) cannot express it either, since a stop with no following running transition reads identically whether the repair is still in flight or ran out of attempts minutes ago.

## The emission has to be edge-triggered, and that is the main implementation risk

`selfheal`'s `escalate()` re-runs on **every** liveness report while a provider stays escalated, deliberately: it re-asserts health because something else keeps overwriting it, and health is level state that is idempotent under that. An event is an append. Emitting from the same place would produce one event, and therefore one alert, per liveness report, and the extension re-publishes liveness on every agent handshake.

So the new callback fires at the edge where the budget is spent, and a test asserts the contrast directly: over the same reports, health is re-asserted repeatedly while the escalation fires exactly once.

## Impact

- Affected specs: `server-detection-rules-engine`, `agent-status-reporting`
- Affected code: `agent/selfheal` (escalation callback), `agent/sensorevent` (the event), `agent/cmd/fleet-edr-agent` (wiring), `server/rules/internal/catalog` (the rule), `schema/events.json`, `test/fakeagent`, `test/efficacy/corpus`
- **Archive-order hazard, for whoever runs the release archive.** This delta MODIFIES `Requirement: Registered rule catalog`, which the in-flight `sensor-tamper-detection` change also modifies. This delta's version is the cumulative one (it lists both `sensor_tamper` and `sensor_recovery_failed`), so it must archive AFTER that change, or reconcile the two by hand. Archiving them the other way round silently drops `sensor_recovery_failed` from the canonical catalog list.
