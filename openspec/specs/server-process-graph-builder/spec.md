# Server Process Graph Builder Specification

## Purpose

The process graph builder is the materialization layer that converts the raw `fork`, `exec`, and `exit` event stream into a
per-host process forest. It is the canonical representation used by the detection engine, the host process tree UI, and the
per-process detail view; without it, every reader would have to reconstruct lineage from raw events on each query.

The capability owns the invariants of process identity over time: which fork started a process, which exec gave it its
current image, when it exited, how PID reuse is disambiguated across generations, and how a same-PID re-exec chain is
preserved so the UI can show the full transformation sequence rather than just the final image.

## Requirements

### Requirement: Timestamp-ordered batch processing

The system SHALL process events in non-decreasing timestamp order within a batch so that for any single PID the `fork` is
applied before any subsequent `exec` and any subsequent `exit`. The order in which the agent transmitted the events MUST
NOT alter the resulting process forest.

#### Scenario: Events arrive out of order in a batch

- **GIVEN** a batch containing a `fork`, an `exec`, and an `exit` for the same PID submitted in arbitrary order
- **WHEN** the builder processes the batch
- **THEN** the resulting process record reflects the fork's parent linkage, the exec's image and arguments, and the exit's
  code, as if the events had been processed strictly in timestamp order

### Requirement: Fork creates a process record

The system SHALL create a new process record on receipt of a `fork` event. The record MUST capture the host, the new PID,
the parent PID, and the fork timestamp.

#### Scenario: A daemon forks a worker

- **GIVEN** a `fork` event carrying child PID and parent PID
- **WHEN** the builder applies the event
- **THEN** a process record exists for the host and child PID with the parent PID and fork timestamp set
- **AND** the record has no exec metadata and no exit metadata yet

### Requirement: Exec updates image metadata

The system SHALL update the in-flight process record on receipt of an `exec` event by setting the image path, the argument
vector, the effective UID and GID, the code-signing identity, and the SHA-256 of the executed binary when the agent
provided them. The fork-time parent linkage MUST NOT be lost as a side effect.

#### Scenario: A user runs a shell command

- **GIVEN** a process record created by a prior `fork`
- **WHEN** an `exec` event arrives for the same host and PID
- **THEN** the process record carries the exec timestamp, image path, argument vector, UID, GID, code-signing identity, and
  binary hash from the event
- **AND** the parent PID and fork timestamp from the original `fork` are preserved

### Requirement: Exit closes the process record

The system SHALL set the exit timestamp and exit code on the in-flight process record on receipt of an `exit` event.

#### Scenario: A process exits normally

- **GIVEN** an in-flight process record for a host and PID
- **WHEN** an `exit` event arrives for the same host and PID
- **THEN** the process record carries the exit timestamp and the exit code from the event
- **AND** the record is no longer considered in-flight for subsequent events on the same PID

### Requirement: PID reuse creates a new generation

The system SHALL recognize that operating-system PIDs are reused. When a `fork` event arrives for a PID that already has a
non-exited record, the system MUST close the prior record and create a new record for the new generation so the two
generations remain distinguishable in the forest.

#### Scenario: A new fork lands on a stale PID

- **GIVEN** an existing process record for a host and PID whose original exit was never observed
- **WHEN** a `fork` event arrives for the same host and PID with a different parent
- **THEN** the prior record is closed at the new fork's timestamp
- **AND** a new process record is created for the new generation with its own fork metadata

### Requirement: Exec without prior fork is tolerated

The system SHALL synthesize a process record when an `exec` event arrives for a PID that has no in-flight record. This
covers extension-startup snapshots and processes that existed before the agent began capturing.

#### Scenario: An exec arrives for an unseen PID

- **GIVEN** no process record for a host and PID
- **WHEN** an `exec` event arrives for that host and PID
- **THEN** a new process record is created with the exec metadata and a fork timestamp set to the exec time as a best
  effort earliest-known moment

### Requirement: Same-PID re-exec chain

The system SHALL preserve the full sequence of exec generations on a single PID. When an `exec` event arrives for a PID
that already has an exec'd record, the system MUST close the prior generation and create a new linked record so that a
chain like `python -> sh -> bash -> payload` is visible in its entirety.

#### Scenario: A shell exec-optimization chain runs on one PID

- **GIVEN** a process record that has already been exec'd at least once
- **WHEN** another `exec` event arrives for the same host and PID without an intervening fork
- **THEN** the prior generation is closed at the new exec's timestamp
- **AND** a new process record is created carrying a back-reference to the prior generation
- **AND** the prior generations are retrievable in order as the re-exec chain for that process

### Requirement: Network and DNS events are linked to the process at event time

The system SHALL link `network_connect` and `dns_query` events to the process record that was alive on the originating host
and PID at the event's timestamp. A network or DNS event MUST NOT be associated with a stale generation that exited before
the event or with a future generation that had not yet forked.

#### Scenario: A short-lived process opens a connection

- **GIVEN** a process record with a known fork-to-exit lifetime on a host
- **WHEN** the per-process detail view is requested
- **THEN** the network and DNS events surfaced for that record are limited to those whose host and PID match and whose
  timestamps fall inside the process lifetime

### Requirement: Snapshot exec events are stitched but not treated as new activity

The system SHALL accept `exec` events flagged as snapshot (events synthesized by the agent at startup to materialize
processes that existed before subscription) and use them to populate the process forest, while signaling to downstream
consumers that they describe pre-existing state rather than new activity. The system MUST mark the resulting process
records as snapshot-originated and seed a freshness timestamp on them so the freshness-TTL reconciler can distinguish
them from organic rows.

#### Scenario: Extension restarts and replays the live process set

- **GIVEN** a batch containing one or more `exec` events with the snapshot flag set
- **WHEN** the builder applies the batch
- **THEN** the corresponding process records are created or updated so the UI can render Safari, Slack, Finder, and other
  pre-existing processes
- **AND** each created record carries a snapshot-originated marker
- **AND** each created record carries a freshness timestamp equal to its fork time so it is not eligible for immediate TTL
  reconciliation on the first pass after insert
- **AND** the snapshot flag is preserved on the underlying events so detection rules can distinguish historical state from
  newly observed activity

### Requirement: Snapshot heartbeat events extend the freshness window

The system SHALL accept `snapshot_heartbeat` events and, for each, update the freshness timestamp on the matching
snapshot-originated process record. The update MUST be scoped to records that are flagged snapshot-originated AND still
live, so a stray heartbeat for a recycled PID cannot resurrect an exited row and cannot apply to a non-snapshot row.

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

### Requirement: TTL reconciliation respects snapshot freshness

The system SHALL periodically force-close process records whose freshness window has elapsed without observed activity,
synthesizing an exit time and marking the row with a TTL-reconciliation reason code. The freshness window MUST use the
record's freshness timestamp when set (which the snapshot path seeds and heartbeats update) and fall back to the fork
timestamp otherwise, so heartbeated snapshot rows are exempt while ordinary rows whose exit events went missing remain
subject to the existing freshness-TTL safety net.

#### Scenario: Snapshot row with fresh heartbeats survives TTL

- **GIVEN** a snapshot-originated process record whose freshness timestamp was updated within the TTL window
- **WHEN** the TTL reconciliation pass runs
- **THEN** the record is NOT closed
- **AND** the record's exit fields remain unset

#### Scenario: Snapshot row without recent heartbeats is closed

- **GIVEN** a snapshot-originated process record whose freshness timestamp is older than the TTL window
- **WHEN** the TTL reconciliation pass runs
- **THEN** the record is force-closed with the TTL-reconciliation exit reason
- **AND** the synthesized exit timestamp lands at the freshness timestamp plus the TTL window, so the UI can render the
  reconciled exit at a meaningful moment rather than at the extension-startup snapshot moment

#### Scenario: Non-snapshot row with missing exit is closed (issue #6 regression guard)

- **GIVEN** a process record that originated from a fork event, whose fork timestamp is older than the TTL window, and
  whose freshness timestamp is unset
- **WHEN** the TTL reconciliation pass runs
- **THEN** the record is force-closed with the TTL-reconciliation exit reason
- **AND** the synthesized exit timestamp lands at the fork timestamp plus the TTL window

### Requirement: Exit-before-snapshot-exec race buffer

The system SHALL handle the race in which a kernel-observed `exit` event for a PID is processed BEFORE the snapshot
`exec` event for the same PID is processed. Because the snapshot exec arrives last but describes an earlier moment, the
exit's update would otherwise find no row and the later snapshot exec would synthesize a phantom alive row that survives
until TTL. The builder MUST buffer such unmatched exits briefly and consume them when the companion snapshot exec
arrives, producing a single record that is born already-exited.

#### Scenario: Exit arrives before its companion snapshot exec

- **GIVEN** an `exit` event for a host and PID with no existing record
- **AND** within a short bounded window the matching snapshot `exec` event for the same host and PID arrives
- **WHEN** the builder processes both
- **THEN** the resulting process record exists, is marked snapshot-originated, and is born with the exit timestamp, exit
  reason, and exit code from the buffered exit
- **AND** no phantom alive row is produced for that PID

#### Scenario: Exit arrives without a matching snapshot exec within the window

- **GIVEN** an `exit` event for a host and PID with no existing record
- **AND** no matching snapshot `exec` event arrives within the bounded buffer window
- **WHEN** the buffer window elapses
- **THEN** the buffered exit is discarded
- **AND** no record is synthesized for that PID
- **AND** a much-later snapshot exec for the same PID is treated as a fresh insert without inheriting the long-expired
  exit, so a recycled PID cannot pick up a stale exit

