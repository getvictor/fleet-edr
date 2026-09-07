# Record capture-provider transitions as durable events

## Why

Agent health is level state. It answers "what is true now", which is the right shape for a dashboard and the wrong shape for evidence.

That became a problem the moment recovery got good. #649 made the agent grade `network_extension` health on which capture providers report themselves running, and #632 made the agent restore a stopped provider by itself. Measured on edr-dev: a content filter switched off is capturing again 36 seconds later and health reads `healthy / activated`. Nothing anywhere records that it ever stopped.

Switching off security tooling is MITRE T1562.001, and it is an ordinary early move for an attacker who has reached admin on a host. The product currently repairs that and erases it. An analyst asking "was this host's sensor tampered with?" a day later has nothing to look at, which is worse for detection than the pre-#632 behaviour where the host at least sat visibly unhealthy until a human noticed.

The repo has tamper detection for sudoers (T1548.003) but nothing watching the EDR's own components, and the efficacy corpus carries no T1562 scenario at all. This change is the producer half of closing that: it puts the evidence on the server. The detection rule that consumes it follows separately.

## What changes

- **The extension carries the raw platform stop reason.** It already grades the reason to decide whether a stop is a fault (#649); it now also reports the unreduced value, so a consumer can discriminate for itself instead of inheriting a verdict that has already collapsed the distinction. Added as a separate `stop_reasons` field rather than by changing the shape of `providers`, because the extension and agent ship together but skew across an upgrade, and an additive field degrades safely in both directions.
- **The agent records provider transitions as events.** A new `sensor_provider_transition` event type carrying the provider, the state it moved into, and the stop reason.
- **Recovery is carried by the next transition, not by an outcome field.** Whether a stop was repaired is not known when the stop happens: the self-heal resolves up to ninety seconds later, and may not run at all. Rather than model an outcome it cannot populate, the emitter records transitions and lets the pair state it: stopped at T followed by running at T+36s is a repaired tamper; a stopped with nothing after it is an unrepaired one. This also keeps the emitter entirely decoupled from the self-heal controller.
- **The first report after a connect establishes a baseline rather than emitting.** The extension re-publishes liveness on every handshake, so the first report describes state this agent process never observed changing. Emitting there would manufacture a transition out of every restart and reconnect, and a tamper signal that fires on restarts is one operators learn to ignore.
- **A provider going absent never emits.** #649 reports a deliberately disabled provider as absent rather than stopped, so a supported opt-out cannot produce tamper evidence.

No server change is needed: ingest validates only that `event_type` is non-empty, so an unrecognised type is accepted and stored.

## What this deliberately does not do

- **It does not detect anything.** This change puts evidence on the server; the T1562.001 rule and its efficacy corpus are a separate change, so the rule can be designed and tuned against events that already exist rather than against a fixture.
- **It does not decide which stop reasons are tamper.** The event carries the reason unreduced precisely so that judgement lives in the rule, where it can change without a wire change. One assumption there is still unverified and is why the rule is not in this change: an agent pkg upgrade is believed to produce lifecycle stop reasons rather than operator-driven ones, but that has never been observed on a real upgrade. If it turns out otherwise, a naive rule would alert on every host on every upgrade, which is precisely how tamper alerting gets muted.
