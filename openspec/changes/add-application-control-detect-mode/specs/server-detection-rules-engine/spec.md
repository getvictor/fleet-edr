# Server Detection Rules Engine Specification (delta)

## ADDED Requirements

### Requirement: Would-block events map to alerts with subtype=would_block

The system SHALL map every accepted `application_control_would_block` ingest event to an alert.
The alert SHALL carry `source='application_control'`, `subtype='would_block'`, the matched rule's
identifier as the alert's `rule_id`, the matched rule's severity as the alert's severity, the
matched rule's `custom_msg` (or a sensible default that names the rule type and identifier) as the
alert's summary, the `policy_id` and `policy_version` from the event as alert attributes, and the
standard `host_id` and linked process identifier as on any other alert. The mapping SHALL be
performed in-pipeline with `application_control_block` events so the alert read API returns both
shapes through the same endpoints.

#### Scenario: A would-block event produces a would-block alert

- **GIVEN** an ingested `application_control_would_block` event carrying `rule_id=R1`,
  `severity=high`, `custom_msg="Would have blocked: corporate policy"`, `policy_id=P1`,
  `policy_version=7`
- **WHEN** the engine processes the event
- **THEN** an alert is persisted with `source='application_control'`, `subtype='would_block'`,
  `rule_id=R1`, `severity=high`, `summary="Would have blocked: corporate policy"`, and attributes
  including `policy_id=P1` and `policy_version=7`

### Requirement: Alert subtype distinguishes block from would-block

The system SHALL persist each application-control alert with a `subtype` column. Alerts produced
from `application_control_block` events SHALL carry `subtype='block'`. Alerts produced from
`application_control_would_block` events SHALL carry `subtype='would_block'`. Existing
catalog-rule findings carry `subtype='detection'` so the column is non-NULL everywhere. Future
Phase B subtypes (e.g. `silent_block`, `would_allow`) extend the same dimension without further
schema migration.

#### Scenario: A catalog rule's alert carries subtype=detection

- **GIVEN** a catalog rule fires on an event batch
- **WHEN** the engine persists the resulting alert
- **THEN** the row carries `source='detection'` and `subtype='detection'`

#### Scenario: A block alert carries subtype=block

- **GIVEN** an ingested `application_control_block` event
- **WHEN** the engine maps the event to an alert
- **THEN** the row carries `source='application_control'` and `subtype='block'`

#### Scenario: A would-block alert carries subtype=would_block

- **GIVEN** an ingested `application_control_would_block` event
- **WHEN** the engine maps the event to an alert
- **THEN** the row carries `source='application_control'` and `subtype='would_block'`

### Requirement: Alerts list filters by source and subtype

The alerts read API SHALL accept `source` and `subtype` as filter parameters. Both filters are
optional and combine with AND semantics. `subtype` accepts free-form string values so future Phase
B subtypes work without API changes; unknown values return an empty result set rather than a 4xx.

#### Scenario: Filter to would-block alerts only

- **GIVEN** alerts of mixed source and subtype exist for a host
- **WHEN** the operator queries
  `GET /api/v1/alerts?source=application_control&subtype=would_block`
- **THEN** the response contains only alerts with `source='application_control'` and
  `subtype='would_block'`

#### Scenario: Filter to a catalog source ignores subtype

- **GIVEN** the operator queries `GET /api/v1/alerts?source=detection`
- **WHEN** the server reads the alerts
- **THEN** the response contains every catalog-rule alert for the operator's deployment

#### Scenario: Filter on an unknown subtype returns empty

- **GIVEN** the operator queries
  `GET /api/v1/alerts?source=application_control&subtype=does_not_exist_yet`
- **WHEN** the server reads the alerts
- **THEN** the response is well-formed and contains zero alerts

## MODIFIED Requirements

### Requirement: Persisted alert schema

The system SHALL persist each finding as an alert that carries a host identifier, a rule
identifier, a severity (`low`, `medium`, `high`, or `critical`), a source (`detection` for
catalog-rule findings or `application_control` for application-control events), a subtype string
that further classifies the alert within its source (`detection` for catalog-rule findings,
`block` for application-control block events, `would_block` for application-control would-block
events, with the column reserved as a string for Phase B Sub-classes), a human-readable title, a
human-readable summary or description, the linked process identifier, and, for catalog-rule alerts
only, the list of MITRE ATT&CK technique identifiers that the firing rule maps to. Alerts with
`source='application_control'` MAY have an empty technique list.

The change from the prior requirement is the addition of the `subtype` column and the requirement
that catalog-rule alerts and application-control alerts populate it with the documented values.

#### Scenario: A catalog rule fires and creates an alert

- **GIVEN** an event batch that satisfies one catalog rule's pattern against a known process
- **WHEN** the engine evaluates the rule and persists the finding
- **THEN** the resulting alert row carries the host id, rule id, severity,
  `source='detection'`, `subtype='detection'`, title, description, linked process id, and
  technique list of the firing rule

#### Scenario: An application control block creates an alert with subtype=block

- **GIVEN** an ingested `application_control_block` event for a known process on a known host
- **WHEN** the engine maps the event to an alert
- **THEN** the resulting alert row carries the host id, rule id, severity,
  `source='application_control'`, `subtype='block'`, title, summary, and linked process id

#### Scenario: An application control would-block creates an alert with subtype=would_block

- **GIVEN** an ingested `application_control_would_block` event for a known process on a known
  host
- **WHEN** the engine maps the event to an alert
- **THEN** the resulting alert row carries the host id, rule id, severity,
  `source='application_control'`, `subtype='would_block'`, title, summary, and linked process id

### Requirement: Alert dedup key depends on source

The system SHALL dedup alerts using a source-specific key. `subtype` is NOT part of either key.
The mapping is:

- `source='detection'`: dedup key `(source, host_id, rule_id, process_id)`. Re-evaluating the same
  catalog rule against the same process on the same host in a later batch MUST NOT create a second
  alert row; the existing alert remains the single record for that finding.
- `source='application_control'`: dedup key `(source, host_id, rule_id)`. Each AUTH_EXEC produces a
  fresh kernel `process_id`, so including it in the key would defeat the cross-execution
  lifecycle. Subsequent `application_control_block` or `application_control_would_block` events
  for the same `(source, host_id, rule_id)` tuple MUST NOT create a second alert row; the existing
  alert is updated in place, the `linked_process_id` is replaced with the most recent matching
  exec, and the `subtype` reflects the most recent decision.

The system SHALL enforce each key with an index that backs the in-application UPSERT used during
event ingest. MySQL does not support partial unique indexes, so the implementation MAY use either
two unique indexes (one per source) or a synthetic dedup_discriminator column that collapses to
`process_id` for `detection` rows and to a fixed sentinel for `application_control` rows under a
single unique index. The choice is an implementation detail; the spec mandates only that the
logical keys above hold and that ingest writes them through an UPSERT path that cannot insert a
duplicate.

The change from the prior requirement is the split-by-source dedup semantics: Phase A's single
`(host_id, rule_id, process_id)` key is preserved for `source='detection'`, and a new
`(source, host_id, rule_id)` key is introduced for `source='application_control'` so the
would_block → block lifecycle collapses into one row.

#### Scenario: A would-block followed by a block updates the existing alert

- **GIVEN** an existing alert with `source='application_control'`, `subtype='would_block'` for
  `(host_a, rule_X)` whose `linked_process_id` is `process_42`
- **WHEN** an `application_control_block` event arrives for `(host_a, rule_X)` with
  `linked_process_id=process_99` after the rule is promoted from DETECT to PROTECT
- **THEN** the existing alert row is updated with `subtype='block'` and
  `linked_process_id=process_99`
- **AND** no new alert row is inserted

#### Scenario: Repeated would-block events on the same Detect rule collapse into one alert

- **GIVEN** an `application_control_would_block` event has produced an alert for
  `(host_a, rule_X)` with `linked_process_id=process_42`
- **WHEN** a second `application_control_would_block` event for `(host_a, rule_X)` arrives with
  `linked_process_id=process_43` (a separate exec of the same binary, fresh kernel PID)
- **THEN** the existing alert row is reused with `linked_process_id` updated to `process_43`
- **AND** no new alert row is inserted

#### Scenario: A catalog rule re-fires on the same process in a later batch

- **GIVEN** an existing alert for a `(source='detection', host, rule, process)` tuple
- **WHEN** a later batch causes the same rule to find the same process again
- **THEN** the existing alert row is reused and no new alert row is inserted

#### Scenario: A catalog rule fires on a different process on the same host

- **GIVEN** an existing `source='detection'` alert for `(host_a, rule_X, process_42)`
- **WHEN** the same rule fires against a different process on the same host, `process_99`
- **THEN** a second alert row is inserted with `linked_process_id=process_99`
- **AND** the original alert row for `process_42` is preserved

#### Scenario: A catalog rule id and an app-control rule id collide on the same process

- **GIVEN** a catalog rule and an application-control rule that happen to share an identifier
  value
- **AND** both have already produced alerts for the same `(host, process)` pair
- **WHEN** the alerts list is queried
- **THEN** two distinct alert rows are returned, one with `source='detection'` and one with
  `source='application_control'`
