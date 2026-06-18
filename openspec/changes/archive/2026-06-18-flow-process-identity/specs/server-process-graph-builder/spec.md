# Server process graph builder: pidversion identity for flow correlation delta

## ADDED Requirements

### Requirement: Process records carry the kernel PID generation

The system SHALL store the originating process's kernel PID generation (`pidversion`) on the process record when an `exec` or `fork` event provides it, so that a process generation is identifiable by the exact `(host_id, pid, pidversion)` triple in addition to its fork-to-exit lifetime. The field is optional: an event that does not carry `pidversion` (a legacy agent, or a flow whose audit token was unavailable) MUST still materialize a process record, with the `pidversion` left unset. A re-exec generation on the same PID inherits the same `pidversion` as its predecessor, because the kernel generation does not change across `execve` without an intervening fork.

#### Scenario: An exec event carrying pidversion stores it on the record

- **GIVEN** the graph builder is processing a batch
- **WHEN** an `exec` event for a host and PID carries a `pidversion`
- **THEN** the materialized process record stores that `pidversion`
- **AND** the record is retrievable by the exact `(host_id, pid, pidversion)` triple

#### Scenario: An exec event without pidversion still materializes a record

- **GIVEN** the graph builder is processing a batch
- **WHEN** an `exec` event for a host and PID carries no `pidversion`
- **THEN** the materialized process record is created with its `pidversion` left unset
- **AND** the record remains retrievable by host, PID, and event-time lifetime as before

## MODIFIED Requirements

### Requirement: Network and DNS events are linked to the process at event time

The system SHALL link `network_connect` and `dns_query` events to the process record for the originating host and PID. When the event carries a `pidversion` and a process generation exists with the exact same `(host_id, pid, pidversion)`, the system MUST link the event to that generation by identity, independently of any clock-drift padding, and MUST NOT link it to a different generation merely because of timestamp proximity. When the event carries no `pidversion`, or no generation matches that exact identity, the system MUST fall back to linking the event to the process record that was alive on that host and PID at the event's timestamp, and a network or DNS event MUST NOT be associated with a stale generation that exited before the event or with a future generation that had not yet forked.

#### Scenario: A short-lived process opens a connection

- **GIVEN** a process record with a known fork-to-exit lifetime on a host
- **WHEN** the per-process detail view is requested
- **THEN** the network and DNS events surfaced for that record are limited to those whose host and PID match and whose timestamps fall inside the process lifetime

#### Scenario: A flow with pidversion correlates to the exact generation across PID reuse

- **GIVEN** two process generations on the same host and PID with distinct `pidversion`s, one exited and one alive
- **WHEN** a `network_connect` event carrying the alive generation's `pidversion` is correlated
- **THEN** the event is linked to the generation whose `pidversion` matches
- **AND** the link does not depend on the connect timestamp falling inside that generation's lifetime window

#### Scenario: A flow without pidversion falls back to the event-time window

- **GIVEN** a `network_connect` event that carries no `pidversion`
- **WHEN** the event is correlated to a process on the same host and PID
- **THEN** the system links it to the generation that was alive at the event's timestamp using the event-time lifetime rule
