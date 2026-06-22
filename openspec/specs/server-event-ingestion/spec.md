# Server Event Ingestion Specification

## Purpose

Server event ingestion is the write path that accepts telemetry batches posted by enrolled agents and durably persists them for downstream processing. It is the only contractual entry point for raw endpoint events into the EDR backend; the process graph builder, detection engine, and UI all read from the events that this capability commits.

The capability is deliberately stateless beyond the database write so that a deployment can scale it horizontally. The ingestion service can run as its own binary (separate from the process that materializes the graph and evaluates rules) so that traffic spikes from a fleet of agents do not block detection work or the read API.

## Requirements

### Requirement: Authenticated batch event submission

The system SHALL expose `POST /api/events` that accepts a JSON array of event envelopes from an enrolled agent. The caller MUST present a per-host bearer token in the `Authorization` header; the system MUST reject requests whose token does not resolve to an enrolled host. When the request carries `Content-Encoding: gzip` the system SHALL decompress the body before parsing; a request without that header is read as-is, so an uncompressed caller stays supported and no agent/server version lockstep is required.

#### Scenario: A valid agent posts a batch

- **GIVEN** an enrolled host with a valid bearer token
- **WHEN** the agent submits a JSON array of well-formed event envelopes to `POST /api/events`
- **THEN** the system responds with HTTP 200 and a JSON body reporting the number of events accepted
- **AND** every submitted event is persisted before the response is returned

#### Scenario: A request without a host token is rejected

- **GIVEN** a client that omits or supplies an unrecognized bearer token
- **WHEN** the client submits any payload to `POST /api/events`
- **THEN** the system responds with HTTP 401 and does not persist any of the events

#### Scenario: A gzip-encoded batch is accepted and persisted

- **GIVEN** an enrolled host with a valid bearer token
- **WHEN** the agent submits a well-formed batch gzip-compressed with `Content-Encoding: gzip`
- **THEN** the system decompresses the body, responds with HTTP 200, and persists every event identically to the uncompressed path

### Requirement: Required field validation

The system SHALL validate that every event in a batch carries a non-empty `event_id`, `host_id`, and `event_type`, and a non-zero `timestamp_ns`. If any event is missing one of these fields the system MUST reject the entire batch.

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

The system SHALL verify that every event in the batch carries a `host_id` matching the host identified by the bearer token. A compromised or misbehaving agent MUST NOT be able to submit events that claim to originate from a different host.

#### Scenario: A batch contains a foreign host_id

- **GIVEN** an authenticated agent for host A
- **WHEN** the batch contains any event whose `host_id` is not A
- **THEN** the system responds with HTTP 400
- **AND** no events from that batch are persisted

### Requirement: Body size limit

The system SHALL cap the bytes it reads from the request body of `POST /api/events` at 10 MB. Bodies that exceed the cap MUST result in HTTP 413 with a typed `body_too_large` diagnostic, and no events from that batch are persisted. The 413 status (RFC 9110 §15.5.14) is the canonical "your body exceeded the limit" signal and matches the shape Elastic Fleet, Datadog, Splunk HEC, and CrowdStrike's ingestion endpoints all use; an agent that sees 413 SHOULD split larger telemetry into multiple batches under the cap rather than retry the same body.

The system MUST enforce the cap before allocating a buffer for the body so a malicious or misconfigured caller cannot trigger an arbitrary-size allocation. When the request advertises `Content-Length` greater than 10 MB the system MUST respond with 413 without reading any of the body; when the request uses chunked transfer-encoding the system MUST enforce the cap via a streaming reader and respond with 413 as soon as the cap is crossed.

When the request is `Content-Encoding: gzip`, the 10 MB cap SHALL apply to the DECOMPRESSED bytes: the system MUST bound the compressed input AND the decompressed output independently, so a small compressed body that expands past 10 MB (a decompression bomb) is rejected with HTTP 413 `body_too_large` rather than allocated in full. A request whose body is not a valid gzip stream (bad header, truncated, or corrupt) MUST be rejected with HTTP 400 and a typed `invalid_gzip` diagnostic, distinct from the 413 oversize signal, so the size-versus-malformed split stays honest.

#### Scenario: An oversized request body is rejected

- **GIVEN** an authenticated agent
- **WHEN** the request body exceeds 10 MB
- **THEN** the system responds with HTTP 413 and the body is `{"error":"body_too_large"}`
- **AND** no events from that batch are persisted

#### Scenario: A right-at-cap body is accepted

- **GIVEN** an authenticated agent submitting a JSON array whose serialized length is at or below 10 MB
- **WHEN** the batch is otherwise well-formed
- **THEN** the system reads the entire body, validates and persists every event, and returns HTTP 200

#### Scenario: A gzip decompression bomb is rejected

- **GIVEN** an authenticated agent sending `Content-Encoding: gzip`
- **WHEN** the compressed body is itself under the cap but decompresses to more than 10 MB
- **THEN** the system responds with HTTP 413 `body_too_large` without allocating the full decompressed payload
- **AND** no events from that batch are persisted

#### Scenario: A malformed gzip body is rejected

- **GIVEN** an authenticated agent sending `Content-Encoding: gzip`
- **WHEN** the request body is not a valid gzip stream
- **THEN** the system responds with HTTP 400 and a typed `invalid_gzip` diagnostic
- **AND** no events from that body are persisted

### Requirement: Per-request event-count limit

The system SHALL cap the number of events the parser accepts in a single batch at 10000 (`MaxIngestEventsPerRequest`). Bodies whose event count exceeds the cap MUST result in HTTP 413 with a typed `too_many_events` diagnostic, and no events from that batch are persisted. The status is 413 (not 400) so the agent uploader routes the rejection through its split-and-retry recovery path: the bisection converges on halves that fit under the cap, so a misconfigured agent producing oversize batches recovers without quarantining any events. The body-byte cap and the event-count cap share the same wire status (413) but carry distinct `error` strings (`body_too_large` vs `too_many_events`) so operator-facing logs distinguish "too big in bytes" from "too many events."

The system MUST enforce the cap during streaming decode, so the over-cap event is never allocated. A naive `json.Unmarshal` followed by a `len(events)` check would let a 10 MB body of microscopic events allocate the full events slice (~60-80 MB of heap for ~140k api.Event structs) before the cap fires; the cap MUST be evaluated as the decoder advances through the array so the rejection happens before the (Max+1)th element is materialized.

#### Scenario: A batch with too many events is rejected

- **GIVEN** an authenticated agent submitting a JSON array with more than `MaxIngestEventsPerRequest` events
- **WHEN** the parser advances past the cap
- **THEN** the system responds with HTTP 413 and the body is `{"error":"too_many_events"}`
- **AND** no events from that batch are persisted

### Requirement: Idempotent submission by event_id

The system SHALL treat the `event_id` as the unique key for an event. A re-submission of an event with the same `event_id` SHALL be silently dropped without raising an error so that an agent can safely retry a batch after a transient network failure.

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

The system SHALL persist incoming events with a status that marks them as not yet processed. A separate processing path SHALL be responsible for materializing the process graph and running detection rules. The ingestion path MUST NOT block on or fail because of downstream processing work.

#### Scenario: Ingestion accepts events while the processor is busy

- **GIVEN** the processor is actively materializing earlier batches
- **WHEN** an agent submits a new batch to `POST /api/events`
- **THEN** the system persists the new events and responds with HTTP 200 without waiting for any processing work
- **AND** the new events become visible to the processor in a subsequent processing cycle

### Requirement: Horizontally scalable ingestion service

The system SHALL support running the ingestion endpoint as a standalone service that shares only the database with the processing service. Multiple replicas of the ingestion service MUST be able to accept agent traffic concurrently against the same database without coordinating with each other.

#### Scenario: Two ingestion replicas run against the same database

- **GIVEN** two replicas of the ingestion service backed by the same database
- **WHEN** different agents post batches to each replica concurrently
- **THEN** every accepted event from both replicas is durably persisted
- **AND** neither replica observes errors caused by the other

### Requirement: Transparent persistence failure reporting

The system SHALL return HTTP 5xx when the underlying database write fails so that the agent retries the batch. The system MUST NOT acknowledge a batch that was not durably persisted.

#### Scenario: The database is temporarily unavailable

- **GIVEN** an authenticated agent
- **WHEN** the database write for an otherwise valid batch fails
- **THEN** the system responds with HTTP 5xx and an opaque error code
- **AND** the agent is expected to retry the batch later

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

### Requirement: Event storage drops redundant indexes

The system SHALL NOT carry secondary indexes on the `events` table that are strictly subsumed by another index's left prefix or that serve no query, so index storage does not dominate disk on high-volume hosts. Specifically, an index on `host_id` alone and an index on `event_type` alone are redundant (the former is a left-prefix of an existing composite; the latter matches no query, since every event-type predicate is anchored by a leading `host_id`) and MUST NOT be present. Indexes that a query relies on MUST be retained, including the index backing the unprocessed-event claim (`processed, host_id, timestamp_ns`) and the index backing per-process network/DNS correlation.

#### Scenario: A duplicate event is still rejected after the index diet

- **GIVEN** the events table with the redundant `host_id`-only and `event_type`-only indexes removed
- **WHEN** an event with an already-stored `event_id` is submitted
- **THEN** the duplicate is silently dropped and no second row is created

#### Scenario: The unprocessed-event claim still works after the index diet

- **GIVEN** the events table with the redundant indexes removed
- **WHEN** the processor claims a batch of unprocessed events ordered by host and time
- **THEN** the claim is served by the retained `(processed, host_id, timestamp_ns)` index and returns the batch

### Requirement: Ingest acceptance is content-neutral

The authenticated event-ingest path SHALL decide acceptance solely on host-token authentication, structural request validation (JSON shape, per-request event count, body size, and host-id match), and server health. It SHALL NOT inspect event payload content for attack signatures, and SHALL NOT reject a batch because its captured command lines, file paths, or network indicators resemble an attack. Agent telemetry legitimately carries such strings, so content inspection belongs to no layer of a supported deployment. Concretely, the path returns `200` on success, `401` for a missing or invalid host token, `400` or `413` for a malformed or oversized batch, and `500`/`503` on a server or database error; it SHALL never return a `403` content-block. A `403` reaching an agent is therefore diagnosably produced by an edge in front of the server, not by the server.

#### Scenario: A batch whose contents resemble an attack is accepted

- **GIVEN** an enrolled host whose host token pins its `host_id`
- **WHEN** it submits a well-formed event batch whose payload fields contain attack signatures (a reverse-shell command line, a C2 URL, and a SQL-injection fragment)
- **THEN** the server accepts the batch with `200` and persists its events, identically to a benign batch of the same shape

#### Scenario: The ingest path never returns a content-block status

- **GIVEN** any request to the authenticated ingest path, across its success and validation-failure outcomes
- **WHEN** the server handles it
- **THEN** the response status is `200` (success), `401` (authentication), `400` or `413` (validation), or `500`/`503` (server), and never `403`
