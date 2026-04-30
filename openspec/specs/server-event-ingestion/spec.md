# Server Event Ingestion Specification

## Purpose

Server event ingestion is the write path that accepts telemetry batches posted by enrolled agents and durably persists them
for downstream processing. It is the only contractual entry point for raw endpoint events into the EDR backend; the process
graph builder, detection engine, and UI all read from the events that this capability commits.

The capability is deliberately stateless beyond the database write so that a deployment can scale it horizontally. The
ingestion service can run as its own binary (separate from the process that materializes the graph and evaluates rules) so
that traffic spikes from a fleet of agents do not block detection work or the read API.

## Requirements

### Requirement: Authenticated batch event submission

The system SHALL expose `POST /api/events` that accepts a JSON array of event envelopes from an enrolled agent. The
caller MUST present a per-host bearer token in the `Authorization` header; the system MUST reject requests whose token does
not resolve to an enrolled host.

#### Scenario: A valid agent posts a batch

- **GIVEN** an enrolled host with a valid bearer token
- **WHEN** the agent submits a JSON array of well-formed event envelopes to `POST /api/events`
- **THEN** the system responds with HTTP 200 and a JSON body reporting the number of events accepted
- **AND** every submitted event is persisted before the response is returned

#### Scenario: A request without a host token is rejected

- **GIVEN** a client that omits or supplies an unrecognized bearer token
- **WHEN** the client submits any payload to `POST /api/events`
- **THEN** the system responds with HTTP 401 and does not persist any of the events

### Requirement: Required field validation

The system SHALL validate that every event in a batch carries a non-empty `event_id`, `host_id`, and `event_type`, and a
non-zero `timestamp_ns`. If any event is missing one of these fields the system MUST reject the entire batch.

#### Scenario: A batch contains an event with a missing field

- **GIVEN** an authenticated agent posting a batch
- **WHEN** any event in the batch lacks `event_id`, `host_id`, `event_type`, or `timestamp_ns`
- **THEN** the system responds with HTTP 400 and a diagnostic message identifying the failing field or position
- **AND** no events from that batch are persisted

#### Scenario: A batch body is not valid JSON

- **GIVEN** an authenticated agent
- **WHEN** the request body is not a JSON array
- **THEN** the system responds with HTTP 400 and a diagnostic message indicating the body could not be parsed
- **AND** no events from that body are persisted

### Requirement: Host identity pinning

The system SHALL verify that every event in the batch carries a `host_id` matching the host identified by the bearer token.
A compromised or misbehaving agent MUST NOT be able to submit events that claim to originate from a different host.

#### Scenario: A batch contains a foreign host_id

- **GIVEN** an authenticated agent for host A
- **WHEN** the batch contains any event whose `host_id` is not A
- **THEN** the system responds with HTTP 400
- **AND** no events from that batch are persisted

### Requirement: Body size limit

The system SHALL cap the bytes it reads from the request body of `POST /api/events` at 10 MB. Bodies that exceed the
cap MUST result in HTTP 400 with a typed body-read diagnostic, and no events from that batch are persisted. A well-
behaved agent is expected to split larger telemetry into multiple batches under the cap rather than rely on the server
to reject oversized bodies.

#### Scenario: An oversized request body is rejected

- **GIVEN** an authenticated agent
- **WHEN** the request body exceeds 10 MB
- **THEN** the system responds with HTTP 400 and a typed body-read diagnostic
- **AND** no events from that batch are persisted

#### Scenario: A right-at-cap body is accepted

- **GIVEN** an authenticated agent submitting a JSON array whose serialized length is at or below 10 MB
- **WHEN** the batch is otherwise well-formed
- **THEN** the system reads the entire body, validates and persists every event, and returns HTTP 200

### Requirement: Idempotent submission by event_id

The system SHALL treat the `event_id` as the unique key for an event. A re-submission of an event with the same `event_id`
SHALL be silently dropped without raising an error so that an agent can safely retry a batch after a transient network
failure.

#### Scenario: An agent retries a batch after a network failure

- **GIVEN** a batch that was already persisted on a prior request
- **WHEN** the agent submits the same batch again
- **THEN** the system responds with HTTP 200
- **AND** the previously stored events are not duplicated and existing rows are not overwritten

#### Scenario: A batch mixes new and previously seen events

- **GIVEN** a batch where some `event_id` values were persisted before and some are new
- **WHEN** the agent submits the batch
- **THEN** the system responds with HTTP 200
- **AND** the new events are persisted while the previously seen events remain unchanged

### Requirement: Decoupled processing pipeline

The system SHALL persist incoming events with a status that marks them as not yet processed. A separate processing path
SHALL be responsible for materializing the process graph and running detection rules. The ingestion path MUST NOT block on
or fail because of downstream processing work.

#### Scenario: Ingestion accepts events while the processor is busy

- **GIVEN** the processor is actively materializing earlier batches
- **WHEN** an agent submits a new batch to `POST /api/events`
- **THEN** the system persists the new events and responds with HTTP 200 without waiting for any processing work
- **AND** the new events become visible to the processor in a subsequent processing cycle

### Requirement: Horizontally scalable ingestion service

The system SHALL support running the ingestion endpoint as a standalone service that shares only the database with the
processing service. Multiple replicas of the ingestion service MUST be able to accept agent traffic concurrently against the
same database without coordinating with each other.

#### Scenario: Two ingestion replicas run against the same database

- **GIVEN** two replicas of the ingestion service backed by the same database
- **WHEN** different agents post batches to each replica concurrently
- **THEN** every accepted event from both replicas is durably persisted
- **AND** neither replica observes errors caused by the other

### Requirement: Transparent persistence failure reporting

The system SHALL return HTTP 5xx when the underlying database write fails so that the agent retries the batch. The system
MUST NOT acknowledge a batch that was not durably persisted.

#### Scenario: The database is temporarily unavailable

- **GIVEN** an authenticated agent
- **WHEN** the database write for an otherwise valid batch fails
- **THEN** the system responds with HTTP 5xx and an opaque error code
- **AND** the agent is expected to retry the batch later

