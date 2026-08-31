# Observability instrumentation

## MODIFIED Requirements

### Requirement: Stable counter names

The system SHALL expose the following counters with stable names so dashboards and alerts can be authored against them: `edr.events.ingested` (events accepted by the ingest endpoint), `edr.alerts.created` (newly created alerts, deduplicated alerts not counted), `edr.detection.monitor_matches` (rule matches suppressed because the resolved mode was monitor), `edr.agent.queue.dropped` (events the agent queue dropped), and `edr.processes.ttl_reconciled` (processes whose exit time was synthesized by the freshness-TTL reconciler). Renaming any of these is a breaking change and MUST NOT happen silently.

`edr.detection.monitor_matches` SHALL carry the same `rule_id` and `severity` attributes as `edr.alerts.created`, and SHALL label a match with the severity the alert would have carried, so that the two series describe one rule identically and can be compared. Comparing them is how an operator judges what promoting a rule to alerting would produce.

Unlike `edr.alerts.created`, `edr.detection.monitor_matches` SHALL NOT be deduplicated, and this SHALL be documented where the counter is defined. An alert deduplicates when it is written and a suppressed match has nothing to write, so re-evaluating a retried batch counts its matches again. Retries arise from a materialization race rather than steady state, so the series overstates occasionally and never understates, which is the safe direction for a number that gates promotion.

#### Scenario: Ingested events are counted by host

- **GIVEN** the ingest endpoint accepts a batch of events for a host
- **WHEN** the batch is accepted
- **THEN** `edr.events.ingested` is incremented by the size of the batch with a `host_id` attribute

#### Scenario: Alerts are counted only on creation

- **GIVEN** the detection engine evaluates a rule
- **WHEN** evaluation produces a newly-created alert
- **THEN** `edr.alerts.created` is incremented with `rule_id` and `severity` attributes

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

The per-rule evaluation span SHALL report the number of findings that were raised as alerts, not the number the rule produced. A finding the resolved mode suppresses SHALL NOT be counted as an alert, and the count of suppressed findings SHALL be reported alongside it so the span still says how much the rule found.

The two were the same number while every rule alerted. They are not once rules ship in a mode that suppresses, and a span that counted produced findings would report alerts that were never raised to every dashboard grouping by rule.

#### Scenario: A rule whose findings are all suppressed reports no alerts

- **GIVEN** a rule whose resolved mode is monitor and which produces findings for a batch
- **WHEN** the batch is evaluated
- **THEN** the rule's span reports an alert count of zero
- **AND** reports the number of suppressed findings
