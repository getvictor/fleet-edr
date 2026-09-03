# Observability instrumentation: bounded detection-retry logging delta

## MODIFIED Requirements

### Requirement: Stable counter names

The system SHALL expose the following counters with stable names so dashboards and alerts can be authored against them: `edr.events.ingested` (events accepted by the ingest endpoint), `edr.alerts.created` (newly created alerts, deduplicated alerts not counted), `edr.detection.monitor_matches` (rule matches suppressed because the resolved mode was monitor), `edr.agent.queue.dropped` (events the agent queue dropped), `edr.processes.ttl_reconciled` (processes whose exit time was synthesized by the freshness-TTL reconciler), `edr.detection.materialization_retries` (detection batches re-queued because an event's subject or flow process was not materialized yet), and `edr.events.set_aside` (queued events withdrawn from processing because their batch could not be processed). Renaming any of these is a breaking change and MUST NOT happen silently.

`edr.detection.monitor_matches` SHALL carry the same `rule_id` and `severity` attributes as `edr.alerts.created`, and SHALL label a match with the severity the alert would have carried, so that the two series describe one rule identically and can be compared. Comparing them is how an operator judges what promoting a rule to alerting would produce.

`edr.detection.monitor_matches` SHALL be recorded once the batch that produced the matches is acknowledged, not while the batch is evaluated, and this SHALL be documented where the counter is defined. A batch that fails is nacked and replayed whole, so a counter incremented during evaluation counts a retried batch once per attempt; recorded after the acknowledgement, a replayed batch is counted once.

The counter SHALL be documented as counting MATCHES rather than would-be alerts. `edr.alerts.created` counts newly created alerts, which deduplicate on (host, rule, subject) permanently, so a rule that keeps matching one subject increments the monitor series every time and would raise exactly one alert. That biases the monitor series upward against what promoting the rule produces, while the counter's documented losses bias it downward, so it SHALL be described as an approximation rather than as a bound in either direction. Documenting that is what keeps the recommended comparison from being read as a forecast.

`edr.events.set_aside` SHALL carry a `host_id` attribute. The question it answers is which host has stopped contributing to the graph, and a fleet-wide total cannot answer it.

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

## ADDED Requirements

### Requirement: Detection materialization-miss retries are bounded in log volume

The detection processor re-queues (nacks) a batch whenever rule evaluation reports the retryable not-yet-materialized error class for an event's subject or flow process. Because that condition can persist for a sustained interval under normal operational and failure modes (a replica behind on graph materialization, an agent that stopped sending fork/exec while its processes keep connecting, a datastore restore or replica re-seed, or a batch of orphaned flows for a long-lived process), the same batch re-nacks on every poll tick within its grace window. The system therefore SHALL NOT emit a warn-level log line per materialization-miss retry; it SHALL instead increment the `edr.detection.materialization_retries` counter and log the retry at debug level, so a sustained materialization-miss condition produces bounded log volume while remaining observable through the counter. A genuine (non-materialization) detection batch failure, such as an alert persistence error, SHALL continue to log at warn level so a real fault stays loud.

#### Scenario: A materialization-miss retry is debug-logged and counted

- **GIVEN** the processor evaluates a claimed batch and rule evaluation returns the retryable not-yet-materialized error class
- **WHEN** the processor re-queues the batch
- **THEN** the retry is logged at debug level, not warn level
- **AND** the `edr.detection.materialization_retries` counter is incremented

#### Scenario: A genuine detection failure still warn-logs

- **GIVEN** the processor evaluates a claimed batch and rule evaluation returns a failure that is not the not-yet-materialized error class
- **WHEN** the processor re-queues the batch
- **THEN** the failure is logged at warn level
- **AND** the `edr.detection.materialization_retries` counter is not incremented
