# Server event ingestion: drop heartbeat persistence delta

## MODIFIED Requirements

### Requirement: Authenticated batch event submission

The system SHALL expose `POST /api/events` that accepts a JSON array of event envelopes from an enrolled agent. The caller MUST present a per-host bearer token in the `Authorization` header; the system MUST reject requests whose token does not resolve to an enrolled host.

A submitted event is durably persisted before the response is returned UNLESS it is a liveness-only event whose sole server-side effect is a process-freshness update (`snapshot_heartbeat`). Such an event is processed for its side effect and then dropped rather than written as a retained event row, but the response still reports it as accepted so the agent's at-least-once delivery contract is unchanged.

#### Scenario: A valid agent posts a batch

- **GIVEN** an enrolled host with a valid bearer token
- **WHEN** the agent submits a JSON array of well-formed event envelopes to `POST /api/events`
- **THEN** the system responds with HTTP 200 and a JSON body reporting the number of events accepted
- **AND** every submitted event that is not a liveness-only event is persisted before the response is returned

#### Scenario: A request without a host token is rejected

- **GIVEN** a client that omits or supplies an unrecognized bearer token
- **WHEN** the client submits any payload to `POST /api/events`
- **THEN** the system responds with HTTP 401 and does not persist any of the events

## ADDED Requirements

### Requirement: Liveness heartbeats are processed but not persisted

The system SHALL process `snapshot_heartbeat` events for their freshness side effect at ingest and MUST NOT write them as retained `events` rows. For each heartbeat the system applies the freshness update to the live, snapshot-originated process record matching the heartbeat's `(host_id, pid)`, identical in scope to the side effect previously applied by the process graph builder. A heartbeat whose payload cannot be decoded or carries no PID is skipped without failing the batch. Heartbeats still contribute to host liveness (the per-host last-seen and event-count counters advance) and are still reported in the accepted count.

#### Scenario: A heartbeat bumps freshness without creating an event row

- **GIVEN** an enrolled host with a live snapshot-originated process record for PID P
- **WHEN** the agent posts a batch containing a `snapshot_heartbeat` for PID P
- **THEN** the record's freshness timestamp is updated to the heartbeat's timestamp
- **AND** no `events` row is created for the heartbeat
- **AND** the response reports the heartbeat among the accepted events

#### Scenario: A batch mixing heartbeats and real events persists only the real events

- **GIVEN** an enrolled host
- **WHEN** the agent posts a batch of N events of which H are `snapshot_heartbeat`
- **THEN** exactly N minus H rows are persisted to `events`
- **AND** the response reports N events accepted
