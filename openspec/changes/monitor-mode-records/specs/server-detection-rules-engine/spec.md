## ADDED Requirements

### Requirement: Monitor-mode matches are kept as records

A finding from a rule that resolves to `monitor` for its host SHALL be persisted as a monitor record, carrying the same context an alert carries: the host, the rule, the severity, the title, the description, the linked process where there is one, the technique identifiers, and the triggering events with their evidence copies. The daily monitor-match counter SHALL continue to count the match as it did before. A count alone cannot tell an operator whether a rule's matches are benign, and that judgement is what promoting a rule turns on.

A monitor record SHALL NOT be an alert. It SHALL NOT be delivered to any webhook destination, SHALL NOT be counted as a created alert, and SHALL NOT be triaged: a request to change its status SHALL be refused, because a monitor record has not been triaged and a status write would restart its retention clock. A finding from a rule that resolves to `alert` SHALL raise an alert as before and SHALL NOT also be kept as a monitor record.

Monitor records SHALL be deduplicated the way alerts are, so a list of them reads as distinct findings rather than being padded by batch retries. The monitor-match counter counts every match, so the two can differ, and neither is wrong.

Promoting a rule SHALL NOT rewrite the records already stored for it. A finding raised after promotion SHALL raise an alert even where a monitor record for the same finding already exists: deduplication applies within a disposition, never across one, or promotion would be silently absorbed by the record it was meant to replace.

Monitor records SHALL be deleted once they are older than a monitor-record retention window, measured from when the record was last written. The window SHALL default to 7 days, the window the promote decision is made over, and SHALL be configured independently of the alert retention window and of the derived-record window: the alert window SHALL NOT delete a monitor record, and the monitor window SHALL NOT delete an alert. A window of zero SHALL disable the monitor-record prune, and a window too long for the system to represent SHALL be refused at startup.

#### Scenario: A monitor-mode match is kept as a monitor record

- **GIVEN** a rule resolved to `monitor` for a host
- **WHEN** an event it matches is evaluated for that host
- **THEN** a monitor record is persisted carrying the rule, host, severity, title, description, process link, techniques, and triggering events
- **AND** no alert is persisted, and the match is counted as before

#### Scenario: An alert-mode match is not also kept as a monitor record

- **GIVEN** a rule resolved to `alert` for a host
- **WHEN** an event it matches is evaluated for that host
- **THEN** an alert is persisted and no monitor record is

#### Scenario: A monitor record is not notified or triaged

- **GIVEN** a webhook destination subscribed to new alerts, and a rule resolved to `monitor`
- **WHEN** the rule's finding is kept as a monitor record
- **THEN** no delivery is enqueued for it
- **AND** a request to change the monitor record's status is refused and the record is unchanged

#### Scenario: Promotion raises an alert for an already recorded finding

- **GIVEN** a monitor record for a rule's finding on a host
- **WHEN** the rule is promoted to `alert` and the same finding is raised again
- **THEN** an alert is persisted for it
- **AND** the monitor record is still there, unchanged

#### Scenario: Monitor records and alerts expire on their own windows

- **GIVEN** a monitor record and an alert, both older than the monitor-record window and younger than the alert window
- **WHEN** a retention pass runs
- **THEN** the monitor record is deleted with its event links
- **AND** the alert is kept, and an alert older than the alert window is deleted while a monitor record younger than its own window is kept

#### Scenario: A zero monitor-record window prunes no monitor record

- **GIVEN** the monitor-record window set to zero, and a monitor record of any age
- **WHEN** a retention pass runs
- **THEN** the monitor record is kept

## MODIFIED Requirements

### Requirement: Alert dedup by subject

The system SHALL deduplicate alerts on the tuple (source, disposition, host id, rule id, subject), where the subject is a stable identity for the finding: for a process-backed finding the subject is its process identifier (preserving the historical (host, rule, process) dedup), and for a process-less finding the firing rule supplies the subject (for example the registered launch item). Re-evaluating a rule that yields the same subject on the same host in a later batch MUST NOT create a second row of the same disposition; the existing row remains the single record for that finding. Disposition is part of the tuple so that an alert and a monitor record for the same finding are two records rather than one absorbing the other.

The change from the prior requirement is disposition in the tuple, which monitor records need (see "Monitor-mode matches are kept as records").

#### Scenario: A rule re-fires on the same process in a later batch

- **GIVEN** an existing alert for a (host, rule, process) triple
- **WHEN** a later batch causes the same rule to find the same process again
- **THEN** the existing alert row is reused and no new alert row is inserted

#### Scenario: Process-less findings dedup on a rule-supplied subject

- **GIVEN** an existing alert for a process-less finding whose subject is its registered item
- **WHEN** a later batch causes the same rule to yield the same subject on the same host
- **THEN** the existing alert row is reused, while a finding with a different subject produces a distinct alert

#### Scenario: An alert and a monitor record for one finding are separate records

- **GIVEN** an existing monitor record for a (host, rule, subject)
- **WHEN** the same finding is persisted as an alert
- **THEN** a new alert row is inserted and the monitor record is not reused
