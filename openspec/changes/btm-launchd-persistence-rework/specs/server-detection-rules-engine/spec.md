# Server Detection Rules Engine Specification (delta)

## MODIFIED Requirements

### Requirement: Persisted alert schema

The system SHALL persist each finding as an alert that carries a host identifier, a rule identifier, a severity
(`low`, `medium`, `high`, or `critical`), a human-readable title, a human-readable summary or description, an OPTIONAL
linked process identifier, and the list of MITRE ATT&CK technique identifiers that the firing rule maps to. The process
identifier is present when the finding is attributable to a live process and absent for process-less findings (for
example a Background Task Management persistence registration, whose attacker has no live process at registration time).

#### Scenario: A rule fires and creates an alert

- **GIVEN** an event batch that satisfies one rule's pattern against a known process
- **WHEN** the engine evaluates the rule and persists the finding
- **THEN** the resulting alert row carries the host id, rule id, severity, title, description, linked process id, and
  technique list of the firing rule

#### Scenario: An alert with no attributable process omits the process link

- **GIVEN** a finding produced with no attributable process (a process-less finding)
- **WHEN** the engine persists the finding as an alert
- **THEN** the resulting alert row carries no linked process identifier and still records the host id, rule id, severity,
  title, description, and technique list

### Requirement: Alert dedup by subject

The system SHALL deduplicate alerts on the tuple (source, host id, rule id, subject), where the subject is a stable
identity for the finding: for a process-backed finding the subject is its process identifier (preserving the historical
(host, rule, process) dedup), and for a process-less finding the firing rule supplies the subject (for example the
registered launch item). Re-evaluating a rule that yields the same subject on the same host in a later batch MUST NOT
create a second alert row; the existing alert remains the single record for that finding.

#### Scenario: A rule re-fires on the same process in a later batch

- **GIVEN** an existing alert for a (host, rule, process) triple
- **WHEN** a later batch causes the same rule to find the same process again
- **THEN** the existing alert row is reused and no new alert row is inserted

#### Scenario: Process-less findings dedup on a rule-supplied subject

- **GIVEN** an existing alert for a process-less finding whose subject is its registered item
- **WHEN** a later batch causes the same rule to yield the same subject on the same host
- **THEN** the existing alert row is reused, while a finding with a different subject produces a distinct alert
