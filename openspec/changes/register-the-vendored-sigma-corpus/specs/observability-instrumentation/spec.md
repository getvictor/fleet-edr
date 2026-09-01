# Observability instrumentation

## MODIFIED Requirements

### Requirement: Stable counter names

The system SHALL expose the following counters with stable names so dashboards and alerts can be authored against them: `edr.events.ingested` (events accepted by the ingest endpoint), `edr.alerts.created` (newly created alerts, deduplicated alerts not counted), `edr.detection.monitor_matches` (rule matches suppressed because the resolved mode was monitor), `edr.agent.queue.dropped` (events the agent queue dropped), and `edr.processes.ttl_reconciled` (processes whose exit time was synthesized by the freshness-TTL reconciler). Renaming any of these is a breaking change and MUST NOT happen silently.

`edr.detection.monitor_matches` SHALL carry the same `rule_id` and `severity` attributes as `edr.alerts.created`, and SHALL label a match with the severity the alert would have carried, so that the two series describe one rule identically and can be compared. Comparing them is how an operator judges what promoting a rule to alerting would produce.

`edr.detection.monitor_matches` SHALL be recorded once the batch that produced the matches is acknowledged, not while the batch is evaluated, and this SHALL be documented where the counter is defined. A batch that fails is nacked and replayed whole, so a counter incremented during evaluation counts a retried batch once per attempt; recorded after the acknowledgement, a replayed batch is counted once. The residual inaccuracy is the opposite one, a crash between the acknowledgement and the record, which under-reports. That is the safe direction for a number that gates promotion, because it makes a rule look cheaper to promote than it was rather than more expensive.

#### Scenario: Ingested events are counted by host

- **GIVEN** the ingest endpoint accepts a batch of events for a host
- **WHEN** the batch is accepted
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

## ADDED Requirements

### Requirement: A per-rule span reports the alerts it raised

The per-rule evaluation span SHALL report the number of findings that were raised as NEW alerts, not the number the rule produced. A finding the resolved mode suppresses SHALL NOT be counted as an alert, and a finding whose alert deduplicated against one that already existed SHALL NOT be counted as an alert either.

Those two SHALL be reported as separate counts alongside the alert count, so the span still says how much the rule found and an operator can tell which of the two happened. They are not the same event: a suppressed finding was held back by a configuration the operator chose, and a deduplicated one is the deduplication working as intended on a rule that is alerting normally. Reporting them as one count made a rule in alert mode with a standing condition show a climbing suppressed count with nothing suppressing it, which is a question the operator cannot answer by reading their own settings.

The alert count and the produced-finding count were the same number while every rule alerted. They are not once rules ship in a mode that suppresses, and a span that counted produced findings would report alerts that were never raised to every dashboard grouping by rule.

#### Scenario: A rule whose findings are all suppressed reports no alerts

- **GIVEN** a rule whose resolved mode is one that raises no alert, whether monitor or disabled, and which produces findings for a batch
- **WHEN** the batch is evaluated
- **THEN** the rule's span reports an alert count of zero
- **AND** reports the number of suppressed findings
- **AND** reports a deduplicated count of zero, since nothing reached persistence to deduplicate against
