# Observability instrumentation

## MODIFIED Requirements

### Requirement: Stable counter names

The system SHALL expose the following counters with stable names so dashboards and alerts can be authored against them: `edr.events.ingested` (events accepted by the ingest endpoint), `edr.alerts.created` (newly created alerts, deduplicated alerts not counted), `edr.detection.monitor_matches` (rule matches suppressed because the resolved mode was monitor), `edr.agent.queue.dropped` (events the agent queue dropped), `edr.processes.ttl_reconciled` (processes whose exit time was synthesized by the freshness-TTL reconciler), `edr.detection.materialization_retries` (detection batches re-queued because an event's subject or flow process was not materialized yet), and `edr.events.set_aside` (queued events withdrawn from processing because their batch could not be processed). Renaming any of these is a breaking change and MUST NOT happen silently.

`edr.detection.monitor_matches` SHALL carry the same `rule_id` and `severity` attributes as `edr.alerts.created`, and SHALL label a match with the severity the alert would have carried, so that the two series describe one rule identically and can be compared. Comparing them is how an operator judges what promoting a rule to alerting would produce.

`edr.detection.monitor_matches` SHALL be recorded once the batch that produced the matches will not be processed again, not while the batch is evaluated, and this SHALL be documented where the counter is defined. A batch that fails is nacked and replayed whole, so a counter incremented during evaluation counts a retried batch once per attempt; recorded on the transition that ends the batch's life, which is usually its acknowledgement and is also its withdrawal from the queue after repeated failure, a replayed batch is counted once.

The counter SHALL be documented as counting MATCHES rather than would-be alerts. `edr.alerts.created` counts newly created alerts, which deduplicate on (host, rule, subject) permanently, so a rule that keeps matching one subject increments the monitor series every time and would raise exactly one alert. That biases the monitor series upward against what promoting the rule produces, while the counter's documented losses bias it downward, so it SHALL be described as an approximation rather than as a bound in either direction. Documenting that is what keeps the recommended comparison from being read as a forecast.

`edr.events.set_aside` SHALL carry a `host_id` attribute. The question it answers is which host has stopped contributing some of its activity, and a fleet-wide total cannot answer it. WHAT it stopped contributing depends on the stage the batch was withdrawn at and is not derivable from the counter, so the counter SHALL NOT be documented as identifying a gap in that host's process graph; the accompanying log record carries the stage and its consequence.

#### Scenario: Ingested events are counted by host

- **GIVEN** the ingest endpoint accepts a batch of events for a host
- **WHEN** the batch is committed
- **THEN** `edr.events.ingested` is incremented by the size of the batch with a `host_id` attribute

#### Scenario: Alerts are counted only on creation

- **GIVEN** the detection engine evaluates a rule
- **WHEN** evaluation produces a newly-created alert
- **THEN** `edr.alerts.created` is incremented with `rule_id` and `severity` attributes

#### Scenario: Already-delivered queue trim is distinguishable from data loss

- **GIVEN** the agent queue drops events
- **WHEN** the dropped events were already delivered (lossless trim) or had not yet been delivered (lossy drop)
- **THEN** `edr.agent.queue.dropped` is incremented with a `lossy` boolean attribute reflecting which case applied

#### Scenario: A suppressed match is counted rather than only logged

- **GIVEN** a rule whose resolved mode is monitor
- **WHEN** it matches an event
- **THEN** `edr.detection.monitor_matches` is incremented with `rule_id` and `severity` attributes
- **AND** no alert is created for that match

#### Scenario: A suppressed match is labelled with the severity the alert would have carried

- **GIVEN** a rule whose resolved mode is monitor and whose setting carries a severity override
- **WHEN** it matches an event
- **THEN** the counter's `severity` attribute is the overridden severity, not the rule's declared one

#### Scenario: Materialization-miss batch retries are counted

- **GIVEN** a detection batch that will be re-queued because a rule saw an event whose subject or flow process was not materialized yet
- **WHEN** the retry is recorded
- **THEN** `edr.detection.materialization_retries` is incremented

#### Scenario: Events withdrawn from processing are counted per host

- **GIVEN** a batch whose events are set aside because it could not be processed
- **WHEN** they are set aside
- **THEN** `edr.events.set_aside` is incremented by the number of events with a `host_id` attribute

### Requirement: Monitor-mode matches are recorded durably per rule

The system SHALL record, durably and per rule, how many times each rule matched in monitor mode, so that an operator deciding whether to promote a rule has the rule's observed behaviour in the product rather than only in a metrics backend.

A monitor match SHALL be attributed to the host it matched on and to the day it was recorded, so the record answers both questions a promotion turns on: how often the rule fires, and across how much of the fleet. Those are different decisions. A rule matching many times on one host is a candidate for an exclusion, while the same volume spread across every host means the rule itself is too broad, and a fleet-wide total alone cannot distinguish them.

Counts SHALL be recorded on the transition that ends the batch's life, not while the batch is evaluated. A batch that fails is nacked and replayed whole, so a count written during evaluation is written again by every retry.

Usually that transition is the acknowledgement. The other is the batch being withdrawn from processing for good once its retry bounds are passed, and where the attempt that was withdrawn had itself evaluated the batch, the matches THAT attempt resolved SHALL be recorded rather than discarded, because there is no later attempt to record them. Discarding them under-reports for precisely the hosts that had processing trouble, and the figure is what an operator reads when deciding whether to promote a monitor-mode rule, so the bias is toward believing a rule is quiet.

A withdrawal on an attempt that did NOT evaluate the batch records nothing, and matches from that batch's earlier attempts are NOT carried to it. Processing has stages, and a batch withdrawn at a stage before evaluation has no matches of its own to record, while an earlier attempt's were discarded when that attempt was retried. Closing this would mean holding a batch's matches somewhere that survives its retries, which is either state in the work queue that is telemetry rather than work, or per-replica state that a stateless app tier cannot keep. It is stated here rather than closed, so the figure's remaining bias is documented rather than implied away.

Only a batch withdrawn IN FULL SHALL be counted this way. The withdrawal decision is made per queued event, so a partly withdrawn batch leaves events that are claimed and evaluated again while the recorded figure covers all of them, and recording it would count the remainder twice. Exactly-once SHALL rest on the queue reporting a withdrawal to one caller rather than on coordination between workers, and withdrawal SHALL be a state an event does not leave. An event that has been withdrawn is not returned to the queue, so no later attempt can withdraw it again and no later attempt is told that it did.

A partial withdrawal therefore loses whatever the withdrawn events alone had matched, and this SHALL be documented rather than implied away. The surviving events are evaluated again and their matches are counted then, but a match that only the withdrawn events produced has no later attempt to produce it. Recording the survivors' share instead would need the figure to carry which event each match came from, which it does not: it is aggregated per rule and host for the batch. Discarding the whole attempt is the choice that cannot over-count, and over-counting is the direction that makes a noisy rule look worse than it is rather than safer than it is.

A withdrawal reported to an attempt that no longer owns the events SHALL also be documented as a loss, for as long as withdrawing is identified by an event's state rather than by the claim it was issued for. An attempt whose processing outran its claim lease can withdraw events a replacement has since claimed, and the count it is given describes only its own view: it can be short of that attempt's batch, which rejects its tally, while the replacement's later nack reports nothing because the events are already withdrawn. Neither attempt records, so the events are counted by nobody. Acknowledging is already conditional on still holding the claim, so only withdrawing is open; closing it is tracked separately, and until then it is a bound on this requirement rather than a promise it keeps.

Two residual inaccuracies remain besides those three, and SHALL be documented rather than implied away. A crash between the transition and the record loses those counts, and so does a recording failure, which is dropped rather than allowed to fail a batch already finished with the queue (below); the observability counter has already advanced by then, so both also leave the counter ahead of the durable record. That is the direction that carries risk, not the one that avoids it: a rule whose recorded volume is too low looks quiet, which is what persuades an operator to promote it, and promoting a noisy rule is the alert flood monitor mode exists to prevent. It is accepted because the alternative, counting during evaluation, is systematically wrong on every retry rather than rarely wrong in the window between two adjacent statements. A third once stood here, an evaluation outliving its claim lease and being counted by both itself and its replacement, and no longer applies: acknowledgement is conditional on still holding the claim and the loser records nothing. The recorded figure is therefore approximate, and MUST NOT be presented as an exact count of what promoting a rule would produce.

A failure to record SHALL NOT fail the batch. By the time the record is attempted the batch has reached a state it will not be processed again from, whether acknowledged or withdrawn, so there is nothing left to fail; replaying real detection work, or undoing a withdrawal, to save a counter would trade the more valuable thing for the less valuable one.

Recorded counts SHALL be subject to the deployment's data-retention window, and pruning them SHALL NOT require a leader-elected task. The delete is idempotent and needs no coordination, whereas every leader-gated loop holds a database connection for the lifetime of the process and the event processor sizes itself against what those loops leave behind.

#### Scenario: A monitor match is counted once for a batch that is retried

- **GIVEN** a rule in monitor mode that matches events in a batch
- **WHEN** the batch fails and is nacked, and the replayed batch then succeeds and is acknowledged
- **THEN** the rule's recorded match count reflects the batch once, not once per attempt

#### Scenario: Counts are attributed to the rule and the host

- **GIVEN** a rule in monitor mode that matches on two different hosts
- **WHEN** the batches are evaluated and acknowledged
- **THEN** the record distinguishes the two hosts for that rule
- **AND** the per-rule total is the sum across them

#### Scenario: A recording failure does not fail the batch

- **GIVEN** an acknowledged batch whose monitor matches cannot be persisted
- **WHEN** the recording fails
- **THEN** the failure is logged
- **AND** the batch is not nacked and its events are not replayed

#### Scenario: Counts older than the retention window are pruned

- **GIVEN** recorded counts older than the configured retention window
- **WHEN** the prune runs
- **THEN** those counts are deleted
- **AND** counts inside the window are kept

#### Scenario: A withdrawn batch is counted once, not lost

- **GIVEN** a rule in monitor mode that matched events in a batch that then failed
- **WHEN** the batch exhausts its retry bounds and every one of its events is withdrawn from processing
- **THEN** the matches that attempt resolved are recorded
- **AND** they are recorded once, because no later attempt will evaluate those events

#### Scenario: A partly withdrawn batch is not counted yet

- **GIVEN** a failing batch in which only some events have passed their retry bounds
- **WHEN** those events are withdrawn and the rest return to the queue
- **THEN** nothing is recorded for that attempt
- **AND** the events that returned are counted by the attempt that finishes them

#### Scenario: A withdrawal before evaluation records nothing

- **GIVEN** a batch that evaluated and failed on one attempt, and on a later attempt failed before evaluation was reached
- **WHEN** that later attempt withdraws every one of its events
- **THEN** nothing is recorded, because the withdrawing attempt resolved no matches
- **AND** the earlier attempt's matches are not carried to it

