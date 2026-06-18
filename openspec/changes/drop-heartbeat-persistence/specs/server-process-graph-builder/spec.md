# Server process graph builder: drop heartbeat persistence delta

## MODIFIED Requirements

### Requirement: Snapshot heartbeat events extend the freshness window

The system SHALL, for each `snapshot_heartbeat` event, update the freshness timestamp on the matching snapshot-originated process record. The update MUST be scoped to records that are flagged snapshot-originated AND still live, so a stray heartbeat for a recycled PID cannot resurrect an exited row and cannot apply to a non-snapshot row.

The freshness update is applied at ingest time, and the heartbeat is not retained as an `events` row (see the server-event-ingestion capability). The process graph builder retains its heartbeat-handling path only for heartbeat rows that were persisted before this behavior shipped and remain unprocessed at upgrade time; such legacy rows are handled with the identical scoping. The freshness scoping and its no-op cases are unchanged regardless of which path applies the update.

#### Scenario: Heartbeat for a live snapshot row bumps freshness

- **GIVEN** a snapshot-originated process record that has not exited
- **WHEN** a `snapshot_heartbeat` event for the same host and PID arrives
- **THEN** the record's freshness timestamp is updated to the heartbeat's timestamp

#### Scenario: Heartbeat for an exited row is a no-op

- **GIVEN** a snapshot-originated process record that has an exit timestamp set
- **WHEN** a `snapshot_heartbeat` event for the same host and PID arrives
- **THEN** the record's freshness timestamp is NOT updated
- **AND** no other field on the record changes

#### Scenario: Heartbeat for a non-snapshot row is a no-op

- **GIVEN** a process record that originated from kernel fork/exec events rather than the startup snapshot
- **WHEN** a `snapshot_heartbeat` event for the same host and PID arrives
- **THEN** no field on the record changes

#### Scenario: A heartbeat does not create or retain an event row

- **GIVEN** an enrolled host with a live snapshot-originated process record for PID P
- **WHEN** a `snapshot_heartbeat` for PID P is ingested
- **THEN** the freshness timestamp is updated
- **AND** no retained `events` row exists for that heartbeat
