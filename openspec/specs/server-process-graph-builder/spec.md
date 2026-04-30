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
consumers that they describe pre-existing state rather than new activity.

#### Scenario: Extension restarts and replays the live process set

- **GIVEN** a batch containing one or more `exec` events with the snapshot flag set
- **WHEN** the builder applies the batch
- **THEN** the corresponding process records are created or updated so the UI can render Safari, Slack, Finder, and other
  pre-existing processes
- **AND** the snapshot flag is preserved on the underlying events so detection rules can distinguish historical state from
  newly observed activity

