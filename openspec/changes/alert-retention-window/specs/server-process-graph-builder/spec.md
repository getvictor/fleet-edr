## MODIFIED Requirements

### Requirement: Completed process records are pruned after the retention window

The system SHALL delete process records whose recorded exit time is older than the configured retention window, on a periodic retention pass that computes its cutoff from that window, so the processes table does not grow without bound on long-lived hosts. The prune MUST key on the exit time, never on the fork time, so a still-running record (no exit time, which includes the live snapshot working set) is never deleted and a long-running process that only recently exited is retained for the full window measured from its exit. The prune MUST skip any process record still referenced by an alert so alert detail views continue to resolve their originating process. Because alerts expire on their own window, a record referenced only by an expired alert SHALL become eligible for this prune, in the same retention pass when that alert is pruned in it. Records whose exit event went missing are first force-closed by the freshness-TTL reconciler and become eligible for this prune once their synthesized exit time ages past the window.

The change from the prior requirement is that the alert reference which keeps a record is no longer permanent: an alert now expires, and the record it held becomes eligible when it does. The restatement also drops the claim that this prune shares event retention's cadence and cutoff, which stopped being true when events moved to the archive's own time-based expiry (ADR-0015).

#### Scenario: A completed record older than the window is pruned

- **GIVEN** a process record with an exit timestamp older than the retention window
- **AND** no alert references the record
- **WHEN** a retention pass runs
- **THEN** the record is deleted

#### Scenario: A live record is never pruned

- **GIVEN** a process record with no exit timestamp, whose fork timestamp is older than the retention window
- **WHEN** a retention pass runs
- **THEN** the record is NOT deleted

#### Scenario: A completed record referenced by an alert is retained

- **GIVEN** a process record with an exit timestamp older than the retention window
- **AND** an alert references the record
- **WHEN** a retention pass runs
- **THEN** the record is NOT deleted
