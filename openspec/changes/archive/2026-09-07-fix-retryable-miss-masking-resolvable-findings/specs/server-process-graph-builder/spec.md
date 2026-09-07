# server-process-graph-builder

## MODIFIED Requirements

### Requirement: PID reuse creates a new generation

The system SHALL recognize that operating-system PIDs are reused. When a `fork` event arrives for a PID that already has a non-exited record, the system MUST close the prior record and create a new record for the new generation so the two generations remain distinguishable in the forest.

Only a generation that started BEFORE the incoming fork SHALL be closed. PID reuse means a new fork takes over a PID an older generation held, so a non-exited record whose own fork timestamp is at or after the incoming fork's timestamp is not the generation being displaced: it is a later generation that was merely materialized first, which happens whenever concurrently processed claim batches split a fork/exec pair and deliver the exec's batch first (the exec synthesizes its record stamped at the exec time, and the fork then arrives with an earlier timestamp). Closing such a record produced an impossible lifetime, with an exit timestamp earlier than its own fork timestamp.

The system MUST NOT write a process record whose exit timestamp precedes its own fork timestamp. Such a record is invisible to every point-in-time process lookup, because those lookups bracket on the record being alive at the event time. That silently redirected flow-to-process correlation onto the bare fork record for the same PID, whose path is only the parent's inherited image, and a rule gating on the process path then declined the process as unremarkable instead of matching the exec'd image.

#### Scenario: A new fork lands on a stale PID

- **GIVEN** an existing process record for a host and PID whose original exit was never observed
- **WHEN** a `fork` event arrives for the same host and PID with a different parent
- **AND** the incoming fork's timestamp is later than the existing record's fork timestamp
- **THEN** the prior record is closed at the new fork's timestamp
- **AND** a new process record is created for the new generation with its own fork metadata

#### Scenario: A fork arrives after the exec-synthesized record for the same PID

- **GIVEN** a process record synthesized by an `exec` event, stamped with the exec's timestamp as its fork timestamp
- **WHEN** a `fork` event for the same host and PID arrives afterwards carrying an EARLIER timestamp
- **THEN** the exec-synthesized record is left open, because it did not start before the incoming fork and so is not a generation the fork displaces
- **AND** no process record has an exit timestamp earlier than its own fork timestamp
- **AND** a point-in-time lookup at the exec's timestamp resolves the exec-imaged record, not a bare fork record for the same PID
