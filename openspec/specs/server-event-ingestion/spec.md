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

### Requirement: Acknowledgement requires still holding the claim

The system SHALL acknowledge a claimed batch only while the acknowledging attempt still holds the claim it was given, and SHALL report to that attempt whether it did.

Returning a batch to the queue SHALL require the same. An attempt that no longer holds a claim SHALL NOT return its events, count an attempt against them, or withdraw them from processing, and SHALL be told that it no longer held the claim, as an acknowledging attempt is told. Reporting only that nothing was withdrawn would not distinguish it from a held batch in which no event reached the bounds that withdraw it, which would make this the one way to lose a claim without anyone being able to see it; losing a claim is the only signal that leases are being exceeded at all. Identifying a claim by an event's STATE rather than by the claim it was issued for is not the same question: a superseded attempt then resets a claim the replacement holds, which makes the replacement's own acknowledgement fail so its work is redone, and counts a failure the replacement did not have against a bound that lives on the event and ends in the event being withdrawn.

Where an attempt names events it holds ALONGSIDE events it does not, every effect SHALL be confined to the events it holds. Checking ownership and then acting on what was asked for leaves the same defect in a narrower window, which is what a batch looks like after a lease expires under part of it.

A claim expires and is re-offered, so an attempt that takes longer than its lease runs alongside the attempt that reclaimed its work. An unconditional acknowledgement lets both succeed and tells neither that it lost, which makes the condition undetectable by construction: nothing downstream can distinguish a batch processed once from a batch processed twice, and nothing reports that a lease was exceeded at all.

Work that is not idempotent SHALL be done only by the attempt that still holds the claim. Folding events into the process graph and persisting alerts are both idempotent, by event identity and by alert deduplication respectively, so a replayed batch is harmless there. Anything additive is not, and belongs to whichever attempt holds the claim.

Losing a claim SHALL NOT be reported as an error. It is a normal outcome of a lease being exceeded, and treating it as a failure would make a caller retry work another attempt is already doing.

Losing a claim SHALL be reported to the operator, because it is the only signal that leases are being exceeded.

#### Scenario: An ack from a lost claim does not acknowledge

- **GIVEN** a batch whose claim expired and was re-claimed by another attempt
- **WHEN** the original attempt acknowledges it
- **THEN** the batch is not marked processed
- **AND** the original attempt is told it no longer held the claim, without an error

#### Scenario: An ack from the holding claim acknowledges

- **GIVEN** a batch whose claim is still held by the acknowledging attempt
- **WHEN** it acknowledges
- **THEN** the batch is marked processed
- **AND** the attempt is told it held the claim

#### Scenario: A nack from a lost claim withdraws nothing

- **GIVEN** an event whose claim expired and was re-claimed by another attempt
- **WHEN** the original attempt returns it to the queue
- **THEN** the event is left claimed by the attempt that holds it
- **AND** no attempt is counted against it
- **AND** the original attempt is told it no longer held the claim, without an error
- **AND** that is reported, since it is the only sign that a lease was exceeded
- **AND** the holding attempt can still acknowledge it

#### Scenario: A nack acts only on the events its claim holds

- **GIVEN** an attempt returning events of which it holds some and not others
- **AND** one of the events it does not hold has already reached the bounds that withdraw it
- **WHEN** it returns them
- **THEN** only the events it holds are returned to the queue
- **AND** the event at its bounds is not withdrawn, because this attempt never held it

### Requirement: A batch that cannot be processed does not stall its host

The system SHALL bound how long a failing batch of queued work is retried. Once a batch's events have both exceeded a bounded number of attempts AND been failing for longer than a bounded period, the system SHALL set those events aside so that the host's remaining work is claimed and processing resumes.

Unbounded retry is not merely wasteful here. The processing path claims a host's queued work in timestamp order, so a batch that fails returns to the front of that order, ahead of everything newer, and a batch that fails DETERMINISTICALLY is retried without end while nothing newer for that host is ever claimed. What stops is not the failing rule or the failing event: the process graph stops advancing for that host and every detection rule stops seeing its activity.

Both bounds SHALL apply, not either. A transient failure can produce a great many attempts in a short window, so an attempt count alone would set aside events that a moment's patience would have processed. A duration alone would set aside a batch that failed once and then waited for an unrelated reason.

Setting events aside SHALL NOT delete them, and SHALL NOT be described as data loss. The queue entry is retained, and separately the event archive is written before the work queue and retained on its own window under the "Durable event archive with bounded retention" requirement, so the event itself remains available for hunting queries and for alert evidence. What is given up depends on the stage the batch was withdrawn at: at the detection stage the event is in the graph already and what is lost is the remainder of detection, while at the process-graph stage its evaluation is lost and its contribution to the graph MAY be, since an earlier attempt may have folded it before a later one failed.

The system SHALL treat the resulting loss as the lesser harm, and the reasoning SHALL be recorded rather than left implicit. Claiming in timestamp order exists so a host's stream is folded in order, and skipping events breaks that for the events skipped when they never reached the graph: a later event whose predecessor was set aside at the graph stage without ever having been folded is itself folded as though the predecessor never arrived, which is a bounded hole in one host's process tree. A batch withdrawn at the detection stage leaves no such hole, and gives up detections on events already in the graph. The alternative to either is that the same host contributes nothing to the graph and raises no detections at all, for as long as the condition lasts.

Setting events aside SHALL be observable, both as a counter that dashboards and alerts can be authored against and as a log record naming the host. A stalled host is otherwise indistinguishable from a quiet one, and the only symptom is an absence of detections that nobody is watching for.

That record SHALL state the consequence that applies to the stage the events were withdrawn at, and SHALL NOT state a consequence that does not. Events can be set aside while the process graph is being built, where the fold that failed did not reach the graph, or during detection, where the batch was materialised before evaluation began and its process tree is intact. Reporting a process-graph gap for the second sends a responder to inspect healthy data, which is worse than reporting nothing: this record is the only prompt anyone gets, so a prompt that wastes the responder's attention teaches them to discount the next one.

The graph-building stage's consequence SHALL report a POSSIBLE gap rather than a certain one. The bounds that withdraw a batch accrue on its queue entry and count every attempt, whichever stage failed, so a batch can be folded into the graph on one attempt, fail at detection, and be withdrawn later on an attempt whose fold failed. Those events are already in the graph and nothing recorded that they got that far, so the system cannot distinguish that from a batch that never folded at all and SHALL NOT state a certainty it does not have.

The detection stage's consequence SHALL name what was lost rather than which step failed, and SHALL NOT claim the events went unevaluated. A rule's own failure is isolated and does not withdraw the batch at all; two other conditions do, and they are indistinguishable at the withdrawal: a failure to persist an alert, which stops the batch at the finding it happened on so the rules after it never run, and an evaluation that asked to be retried until its bounds ran out, where every rule ran. Naming rule evaluation would be false for the first and would point a responder at rule execution while the failure was in alert storage. For the same reason the consequence SHALL be that alerts those events would have raised MAY be missing rather than that they ARE: alerts written before the failure remain durable, and overstating the loss sends someone hunting for alerts that are already there.

The log MESSAGE SHALL be the same for every stage, with the consequence carried as an attribute. The record is found by searching for that line, and a message that varied by stage would leave any search, and any alert authored on it, matching some withdrawals and not others.

Events set aside SHALL NOT be counted as backlog by the processor-backlog signal that reports how much work is waiting. They are not waiting for anything, so counting them would hold that signal up permanently by a number that never drains, which is the shape an operator reads as a processor falling behind. The separate set-aside counter is what reports them, and any probe that validates the backlog signal SHALL use the same predicate so the two cannot disagree.

Events set aside SHALL age out under the deployment's retention window rather than accumulating in the work queue without bound, and that window SHALL be measured from when the events were WITHDRAWN rather than from when their batch first failed. The two diverge without bound, because attempts accrue only while a host is online: a batch that fails once, waits out an offline stretch longer than the whole retention window, and only then reaches the attempt bound would be withdrawn and swept on the next sweep, leaving no window to inspect it in. The retention window doubles as the period an operator has to look, so it SHALL start when there is something to look at.

#### Scenario: A deterministically failing batch stops blocking its host

- **GIVEN** a host whose oldest queued batch fails every time it is processed, and newer events queued behind it
- **WHEN** the batch has exceeded both the attempt bound and the duration bound
- **THEN** its events are set aside and the newer events are claimed and processed
- **AND** detections resume for that host

#### Scenario: A transient failure is retried rather than set aside

- **GIVEN** a batch that fails repeatedly in quick succession and would then succeed
- **WHEN** it has exceeded the attempt bound but not the duration bound
- **THEN** it is retried rather than set aside
- **AND** it is processed once the condition clears

#### Scenario: Setting events aside is counted and logged

- **GIVEN** a batch whose events are being set aside
- **WHEN** that happens
- **THEN** a counter is incremented by the number of events set aside
- **AND** a log record names the host, so the condition is visible without waiting for someone to notice missing detections

#### Scenario: The record states the consequence for its stage

- **GIVEN** a batch set aside while rules were being evaluated, after its events were folded into the process graph
- **WHEN** the record is read
- **THEN** it reports that detection did not complete for those events, so alerts they would have raised may be missing
- **AND** it does not report a gap in that host's process graph, which would send a responder to inspect an intact process tree
- **AND** it does not name rule evaluation as the step that failed, since the same withdrawal follows a failure to store an alert, in which no rule failed at all
- **AND** a batch set aside while the graph was being built reports a possible gap in that graph instead
- **AND** both carry the same log message, so one search finds either

#### Scenario: Setting an event aside does not delete it

- **GIVEN** an event whose queue entry has been set aside
- **WHEN** the queue is inspected
- **THEN** the entry is still present with its payload intact, withdrawn from processing rather than removed
- **AND** the entry names the event, so which events a host stopped contributing is recoverable

#### Scenario: A set-aside event stops counting as backlog

- **GIVEN** a host with one event set aside and no other queued work
- **WHEN** the processor-backlog signal is read
- **THEN** it reports no waiting work
- **AND** the set-aside entry is still present, reported by the set-aside counter instead

#### Scenario: Events set aside do not accumulate without bound

- **GIVEN** events set aside longer ago than the configured retention window
- **WHEN** the queue's retention sweep runs
- **THEN** those entries are removed
- **AND** entries set aside inside the window are kept

#### Scenario: The retention window starts when events are withdrawn

- **GIVEN** an entry whose batch first failed longer ago than the retention window but which was set aside only moments ago
- **WHEN** the queue's retention sweep runs
- **THEN** the entry is kept, because the window measures how long it has been available to inspect
