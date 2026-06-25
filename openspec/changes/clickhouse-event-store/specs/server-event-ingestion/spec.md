## MODIFIED Requirements

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

## REMOVED Requirements

### Requirement: Event storage drops redundant indexes

**Reason**: The relational `events` table is removed by the hard switch to the columnar event archive (see the added "Durable event archive with bounded retention" requirement), so a requirement governing that table's secondary indexes no longer applies. The unprocessed-event claim it referenced now runs against the work queue (the modified "Decoupled processing pipeline" requirement), and per-process network/DNS correlation is served by the event archive's storage ordering rather than a relational secondary index.

**Migration**: No operator action. The schema migration drops the `events` table and its indexes; the claim index is created on the work queue and the correlation access path becomes the archive's storage ordering. Pre-upgrade event history is discarded (hard switch); alerts and their self-contained evidence are preserved.

## ADDED Requirements

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
