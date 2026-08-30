# Server detection rules engine: a rule can match on the parent process delta

## ADDED Requirements

### Requirement: A rule can match on the parent process

The system SHALL make the executing process's parent image available to a detection as a field, so a rule can condition on what spawned a process without reaching into the process graph itself.

The system SHALL resolve that image when the rule is evaluated rather than when the event is stored. Processes are materialized before rules run and events are stored before that, so a value written at storage time would be missing for any process whose parent arrived in the same batch, and would be missing permanently.

The system SHALL report the field as absent when the parent cannot be resolved, so a rule keyed on a parent declines rather than matching a process whose image is unknown. An unresolvable parent SHALL NOT fail the batch; a graph read that genuinely errors SHALL, so the batch is retried rather than silently under-detecting.

The evaluator SHALL NOT itself depend on the process graph. The value is supplied to it, which keeps matching semantics testable against literal values and keeps the lookup where the retry behaviour lives.

#### Scenario: The parent image is supplied by the caller

- **GIVEN** an exec event whose parent the caller has resolved
- **WHEN** a rule matching on the parent image is evaluated
- **THEN** it sees the resolved path

#### Scenario: An unresolvable parent declines rather than matching

- **GIVEN** an exec event whose parent cannot be resolved
- **WHEN** a rule matching on the parent image is evaluated
- **THEN** the rule does not match, and the batch is not failed
