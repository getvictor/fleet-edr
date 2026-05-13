# Server Detection Rules Engine Specification (delta)

## ADDED Requirements

### Requirement: Application control blocks become alerts

The system SHALL map every accepted `application_control_block` ingest event to an alert. The alert SHALL
carry `source='application_control'`, the matched rule's identifier as the alert's `rule_id`, the matched
rule's severity as the alert's severity, the matched rule's `custom_msg` (or a sensible default when the
field is absent) as the alert's summary, the `policy_id` and `policy_version` from the event as alert
attributes, and the standard `host_id` and linked process identifier as on any other alert. The mapping
SHALL be performed in-pipeline with catalog-rule findings so that the alert read API returns both shapes
through the same endpoints.

#### Scenario: A block event produces an alert with source=application_control

- **GIVEN** an ingested `application_control_block` event carrying `rule_id=R1`, `severity=high`,
  `custom_msg="Blocked: corporate policy"`, `policy_id=P1`, `policy_version=7`
- **WHEN** the engine processes the event
- **THEN** an alert is persisted with `source='application_control'`, `rule_id=R1`, `severity=high`,
  `summary="Blocked: corporate policy"`, and attributes that include `policy_id=P1` and `policy_version=7`

#### Scenario: Default summary when custom_msg is absent

- **GIVEN** an ingested `application_control_block` event with no `custom_msg`
- **WHEN** the engine maps the event to an alert
- **THEN** the alert's summary is a deterministic, human-readable default that names the rule type and
  identifier (for example `Blocked TEAMID rule for EQHXZ8M8AV`)

## MODIFIED Requirements

### Requirement: Persisted alert schema

The system SHALL persist each finding as an alert that carries a host identifier, a rule identifier, a
severity (`low`, `medium`, `high`, or `critical`), a source (`detection` for catalog-rule findings or
`application_control` for application-control blocks), a human-readable title, a human-readable summary
or description, the linked process identifier, and, for catalog-rule alerts only, the list of MITRE
ATT&CK technique identifiers that the firing rule maps to. Alerts with `source='application_control'`
MAY have an empty technique list.

#### Scenario: A catalog rule fires and creates an alert

- **GIVEN** an event batch that satisfies one catalog rule's pattern against a known process
- **WHEN** the engine evaluates the rule and persists the finding
- **THEN** the resulting alert row carries the host id, rule id, severity, `source='detection'`, title,
  description, linked process id, and technique list of the firing rule

#### Scenario: An application control block creates an alert

- **GIVEN** an ingested `application_control_block` event for a known process on a known host
- **WHEN** the engine maps the event to an alert
- **THEN** the resulting alert row carries the host id, rule id, severity, `source='application_control'`,
  title, summary, and linked process id

### Requirement: Alert dedup by (host, rule, process)

The system SHALL treat the triple (host id, rule id, process id) as the alert dedup key for both catalog
rule findings and application control blocks. Re-evaluating the same catalog rule against the same process
on the same host in a later batch MUST NOT create a second alert row; the existing alert remains the single
record for that finding. A subsequent `application_control_block` event for the same triple MUST NOT create
a second alert row either; the existing alert remains the single record.

#### Scenario: A catalog rule re-fires on the same process in a later batch

- **GIVEN** an existing alert for a (host, rule, process) triple with `source='detection'`
- **WHEN** a later batch causes the same rule to find the same process again
- **THEN** the existing alert row is reused and no new alert row is inserted

#### Scenario: An application control block repeats for the same process

- **GIVEN** an existing alert for a (host, rule, process) triple with `source='application_control'`
- **WHEN** a later `application_control_block` event arrives for the same triple
- **THEN** the existing alert row is reused and no new alert row is inserted
