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

The system SHALL, on accepting a batch, durably store every retained event in the event archive AND enqueue each event on a separate work queue that marks it not yet processed. A separate processing path SHALL claim queued work to materialize the process graph and run detection rules; it claims from the work queue, not from the archive. Claimed work SHALL be removed from the queue once processing completes, so the queue holds only the in-flight working set while the archive holds the retained history. The ingestion path MUST NOT block on or fail because of downstream processing work.

#### Scenario: Ingestion accepts events while the processor is busy

- **GIVEN** the processor is actively materializing earlier batches
- **WHEN** an agent submits a new batch to `POST /api/events`
- **THEN** the system persists the new events and responds with HTTP 200 without waiting for any processing work
- **AND** the new events become visible to the processor in a subsequent processing cycle

#### Scenario: An accepted batch is both archived and enqueued

- **GIVEN** an enrolled host with a valid bearer token
- **WHEN** the agent submits a well-formed batch
- **THEN** every retained event is durably stored in the event archive
- **AND** every retained event is enqueued on the work queue marked not yet processed
- **AND** the system responds with HTTP 200 only after both writes succeed

#### Scenario: Acknowledged work is pruned from the queue

- **GIVEN** events that have been claimed and acknowledged (fully processed) alongside others still unprocessed or in-flight
- **WHEN** the queue-prune sweep runs
- **THEN** the acknowledged events are removed from the work queue in bounded batches
- **AND** the unprocessed and in-flight events remain claimable
- **AND** the durable history in the event archive is unaffected

### Requirement: Horizontally scalable ingestion service

The system SHALL support running the ingestion endpoint as a standalone service that shares only its backing stores (the event archive and the work queue) with the processing service. Multiple replicas of the ingestion service MUST be able to accept agent traffic concurrently against the same backing stores without coordinating with each other.

#### Scenario: Two ingestion replicas run against the same backing stores

- **GIVEN** two replicas of the ingestion service backed by the same event archive and work queue
- **WHEN** different agents post batches to each replica concurrently
- **THEN** every accepted event from both replicas is durably persisted
- **AND** neither replica observes errors caused by the other

### Requirement: Transparent persistence failure reporting

The system SHALL return HTTP 5xx when a durable write fails so that the agent retries the batch. A batch SHALL be acknowledged only when every retained event has been durably written to BOTH the event archive AND the work queue; if either write fails the system MUST respond with 5xx and MUST NOT acknowledge the batch.

#### Scenario: A backing store is temporarily unavailable

- **GIVEN** an authenticated agent
- **WHEN** the write of an otherwise valid batch to either the event archive or the work queue fails
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

### Requirement: Durable event archive with bounded retention

The system SHALL retain every accepted, non-heartbeat event in a durable, queryable event archive that is the source of truth for per-process network/DNS correlation and for historical and hunting queries. The archive SHALL be deduplicated by `event_id`, so at-least-once delivery (a retried batch or a re-queued event) never surfaces a duplicate event in query results and a previously stored event's content is not altered by a re-submission. The archive SHALL age events out automatically once they are older than the configured retention window (time-based expiry), without an explicit per-event delete pass on the ingest path. Aging an event out of the archive SHALL NOT remove evidence that has been independently retained for an alert.

#### Scenario: An accepted event is queryable from the archive

- **GIVEN** an enrolled host that has posted a well-formed batch
- **WHEN** a per-process correlation or hunting read runs for that host within the retention window
- **THEN** the archive returns the host's events for the queried window

#### Scenario: A re-delivered event is not duplicated in the archive

- **GIVEN** an event already stored in the archive
- **WHEN** the same `event_id` is delivered again (an agent retry or a re-queued batch)
- **THEN** archive query results contain a single event for that `event_id`
- **AND** the previously stored content is unchanged

#### Scenario: An event older than the retention window ages out

- **GIVEN** events in the archive older than the configured retention window
- **WHEN** the time-based expiry runs
- **THEN** those events are no longer present in archive query results
- **AND** no explicit per-event delete pass was issued on the ingest path

### Requirement: Platform-tagged event envelope

The ingest path SHALL accept an optional `platform` field on each event, where a present value MUST be one of `darwin`, `windows`, or `linux`. The server SHALL reject an event whose platform is present but not one of those values. The server SHALL normalize an absent platform to `darwin`, the default for an agent predating this contract, so that every persisted event carries a concrete platform. The server SHALL persist the platform through both the work queue and the event archive so downstream processing, including rule evaluation, observes it.

#### Scenario: An event carrying a valid platform is accepted

- **GIVEN** an event whose `platform` is `windows`
- **WHEN** the ingest path validates the batch
- **THEN** the event is accepted and its platform is `windows`

#### Scenario: An event without a platform is normalized to darwin

- **GIVEN** an event that omits `platform`
- **WHEN** the ingest path validates the batch
- **THEN** the event is accepted and its platform is `darwin`

#### Scenario: An event with an unknown platform is rejected

- **GIVEN** an event whose `platform` is a value other than darwin, windows, or linux
- **WHEN** the ingest path validates the batch
- **THEN** the request is rejected with status 400 and the error code names the offending index

#### Scenario: Platform survives the queue to rule evaluation

- **GIVEN** a batch containing a windows event and an event with no platform
- **WHEN** the events are fanned out to the work queue the detection engine claims from
- **THEN** the queued windows event carries platform `windows` and the platform-less event carries the normalized `darwin`
