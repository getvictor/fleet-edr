# Server Detection Rules Engine Specification

## Purpose

The detection rules engine is the analytic layer that turns the materialized process graph and raw event stream into
behavioral alerts. It runs operator-curated rules against each batch of events that the processor releases, persists the
resulting findings as alerts, and exposes them to the UI through the read API.

The capability owns the contract for what an alert is: how a rule firing maps to a row in the alerts table, how repeated
firings of the same rule against the same process collapse to a single record, how MITRE ATT&CK technique mappings travel
with each alert, and how a rule failure interacts with the rest of the batch.

## Requirements

### Requirement: Evaluate every registered rule against each batch

The system SHALL evaluate every rule that has been registered with the engine against each batch of events the processor
delivers. A single rule MAY emit zero, one, or many findings per batch.

#### Scenario: A batch produces multiple findings from one rule

- **GIVEN** a batch of events that satisfies a rule's pattern in two distinct contexts
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the rule emits two findings
- **AND** both findings are persisted as separate alert rows

#### Scenario: A batch produces no findings from any rule

- **GIVEN** a batch of events that does not satisfy any registered rule
- **WHEN** the engine evaluates all rules against the batch
- **THEN** no alerts are persisted for that batch

### Requirement: Registered rule catalog

The system SHALL register the following named rules at startup so each becomes evaluable against every batch:
`suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`,
`credential_keychain_dump`, `privilege_launchd_plist_write`, and `sudoers_tamper`.

#### Scenario: The engine reports its rule catalog

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** the catalog includes `suspicious_exec`, `shell_from_office`, `osascript_network_exec`,
  `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, and
  `sudoers_tamper`

### Requirement: Persisted alert schema

The system SHALL persist each finding as an alert that carries a host identifier, a rule identifier, a severity
(`low`, `medium`, `high`, or `critical`), a human-readable title, a human-readable summary or description, the linked
process identifier, and the list of MITRE ATT&CK technique identifiers that the firing rule maps to.

#### Scenario: A rule fires and creates an alert

- **GIVEN** an event batch that satisfies one rule's pattern against a known process
- **WHEN** the engine evaluates the rule and persists the finding
- **THEN** the resulting alert row carries the host id, rule id, severity, title, description, linked process id, and
  technique list of the firing rule

### Requirement: Alert dedup by (host, rule, process)

The system SHALL treat the triple (host id, rule id, process id) as the alert dedup key. Re-evaluating the same rule
against the same process on the same host in a later batch MUST NOT create a second alert row; the existing alert remains
the single record for that finding.

#### Scenario: A rule re-fires on the same process in a later batch

- **GIVEN** an existing alert for a (host, rule, process) triple
- **WHEN** a later batch causes the same rule to find the same process again
- **THEN** the existing alert row is reused and no new alert row is inserted

### Requirement: Alert-to-event linkage

The system SHALL record the set of triggering event identifiers for each alert so that the read API can return them on the
alert detail endpoint and analysts can pivot from the alert to the underlying telemetry.

#### Scenario: An analyst opens an alert and sees its triggering events

- **GIVEN** a persisted alert produced from a batch of events
- **WHEN** the alert detail is requested
- **THEN** the response includes the list of `event_id` values that caused the rule to fire

### Requirement: MITRE ATT&CK technique stamping

The system SHALL stamp each persisted alert with the MITRE ATT&CK technique identifiers declared by the firing rule. The
stamped list MUST be preserved on the alert row even if the rule's technique mapping is later refined.

#### Scenario: A rule advertises ATT&CK techniques

- **GIVEN** a rule that declares technique identifiers such as `T1059.002` and `T1105`
- **WHEN** the rule fires and an alert is persisted
- **THEN** the alert row carries those technique identifiers
- **AND** subsequent edits to the rule's technique mapping do not modify the historical alert's stamped list

### Requirement: Rule failure isolation, batch retry on persistence failure

The system SHALL isolate a single rule's evaluation failure so that other rules in the batch still run. The system MUST
NOT silently drop alerts on persistence failures: when persisting a finding fails, the batch is surfaced as failed so the
processor can retry it.

#### Scenario: One rule errors during evaluation

- **GIVEN** a batch where one registered rule's evaluation returns an error
- **WHEN** the engine processes the batch
- **THEN** the error is recorded and the engine continues evaluating the remaining rules
- **AND** the remaining rules' findings are persisted normally

#### Scenario: An alert persistence write fails

- **GIVEN** a finding that the engine attempts to persist
- **WHEN** the persistence layer returns an error
- **THEN** the engine signals the failure to its caller so the entire batch is retried on a future cycle
- **AND** the failed finding is not silently discarded

### Requirement: Snapshot exec events are excluded from rule evaluation

The system SHALL exclude `exec` events flagged as snapshot from rule evaluation. Such events describe processes that
existed before the agent began subscribing and represent historical state, not new attacker activity.

#### Scenario: A snapshot exec is delivered in a batch

- **GIVEN** a batch containing one or more `exec` events with the snapshot flag set
- **WHEN** the engine evaluates rules against the batch
- **THEN** the snapshot-flagged events are not visible to any rule
- **AND** no alerts are produced from those events even when they would otherwise match a rule's pattern

### Requirement: Operator toggling of individual rules

The system SHALL allow an operator to disable individual rules at startup through configuration. A disabled rule MUST NOT
evaluate against any batch and MUST NOT produce alerts until it is re-enabled.

#### Scenario: An operator disables a noisy rule for their environment

- **GIVEN** a running engine where one rule has been disabled by configuration
- **WHEN** a batch arrives that would otherwise satisfy that rule
- **THEN** the disabled rule does not evaluate
- **AND** no alerts are produced for that rule
- **AND** the remaining rules continue to evaluate normally

