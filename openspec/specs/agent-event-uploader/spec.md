# Agent Event Uploader Specification

## Purpose

The agent event uploader is the durable bridge between the agent's local event queue and the server's ingestion endpoint. Endpoint security telemetry is generated continuously, often at peak rates that exceed the prevailing network throughput, and the agent has no way to know in advance whether the server is reachable. The uploader's job is to take whatever the queue holds, ship it as efficiently as the server's contract allows, and tolerate transient network or server failures without losing events or duplicating them at rest.

The capability draws a clear boundary around delivery semantics. Events are at-least-once on the wire and exactly-once at rest because the server deduplicates by event identifier; the uploader holds events in the local queue until the server positively acknowledges them, retries with backoff on transient failure, and surfaces authentication failures to the enrollment subsystem so token-revocation events do not silently drop telemetry.

## Requirements

### Requirement: Upload uses the host bearer token

The system SHALL include the current host token as an Authorization Bearer header on every event upload request and the server SHALL reject requests that do not present a valid host token.

#### Scenario: Upload with a valid token

- **GIVEN** the agent holds a valid host token
- **WHEN** the uploader posts a batch of events to the events endpoint
- **THEN** the request carries an Authorization Bearer header with the current host token
- **AND** the server identifies the request as belonging to the token's host

#### Scenario: Upload with no token

- **GIVEN** the agent has not yet enrolled and holds no token
- **WHEN** the uploader posts events
- **THEN** the server returns 401
- **AND** the events are not removed from the local queue

### Requirement: Successful upload acknowledges events

The system MUST mark events as delivered in its local queue only after the server returns a 2xx status code, so a server-side failure during the response cannot cause silent event loss.

#### Scenario: Server returns 200 or 204

- **GIVEN** a batch of N events has been posted
- **WHEN** the server returns a 2xx status
- **THEN** all N events are marked uploaded and become eligible for removal from the local queue
- **AND** they are not re-sent on the next upload tick

#### Scenario: Server returns 5xx mid-batch

- **GIVEN** a batch of events has been posted
- **WHEN** the server returns 5xx or the connection is dropped before a 2xx is received
- **THEN** none of the events are marked uploaded
- **AND** the same batch is eligible to retry on the next attempt

### Requirement: Server-side deduplication makes replay safe

The system SHALL be free to retransmit any unacknowledged batch in full because the server deduplicates events on receipt using each event's unique identifier.

#### Scenario: Same batch is delivered twice

- **GIVEN** a batch was delivered, the server persisted the events, and the response was lost in transit
- **WHEN** the agent retries the same batch
- **THEN** the server inserts no new rows for events whose identifiers already exist
- **AND** the second response is also a 2xx so the agent can mark them uploaded

### Requirement: Bounded request size

The system MUST cap the size of each upload request and split larger queue contents across multiple requests so that any single HTTP request stays within the server's accepted body size and the network's practical MTU for streaming bodies. The system SHALL gzip-compress the request body and set `Content-Encoding: gzip`, because event batches are small, repetitive JSON that compress several-fold and the ingest path is bandwidth-bound; the uncompressed batch still drives the over-cap split-and-retry recovery, which bisects by event count and is unaffected by the wire encoding.

#### Scenario: Queue holds more events than fit in one request

- **GIVEN** the queue contains more events than the per-request batch limit
- **WHEN** the uploader runs an upload cycle
- **THEN** the uploader emits one or more requests of bounded size
- **AND** events that did not fit in the first request remain queued for subsequent requests

#### Scenario: The upload body is gzip-compressed

- **GIVEN** the uploader has a batch to send
- **WHEN** it posts the batch to the server
- **THEN** the request carries `Content-Encoding: gzip` and the body is a gzip stream that decompresses to exactly the JSON array of events the uploader marshalled

### Requirement: Over-cap server responses split-and-retry the batch

The system MUST handle HTTP 413 responses from the server by recursively splitting the in-memory batch in half and re-POSTing each half until either the half delivers (2xx) or a single-event batch still returns 413. The server emits 413 with two distinct diagnostics: `body_too_large` (body bytes exceed the server's request-size cap) and `too_many_events` (event count exceeds `MaxIngestEventsPerRequest`); both share the 413 status because both have the same recovery shape (bisect + retry). A single-event 413 is the only case where the event is dropped; in that case the uploader MUST emit a WARN log identifying the event id and increment a counter (`edr.agent.uploader.events_dropped_too_large`) so operators can dashboard the drop rate as a signal of misconfigured agents producing oversize events. The recursive split is bounded by `ceil(log2(N))` for a batch of N events, so a 10000-event batch recurses at most ~14 levels before reaching single-event leaves. The split-and-retry path is distinct from the quarantine path for generic 4xx responses (which counts consecutive drain-tick failures before sealing rows): a 413 is a size signal, not a "the event is malformed" signal, so it must not consume the quarantine budget. Matches the recovery shape Splunk HEC and Elastic Beats implement.

#### Scenario: Server returns 413 for a multi-event batch

- **GIVEN** the uploader POSTs a batch of N>1 events whose body exceeds the server's per-request cap
- **WHEN** the server returns HTTP 413 with the `body_too_large` diagnostic
- **THEN** the uploader splits the batch into two halves and POSTs each half independently before the next drain tick
- **AND** halves that deliver (2xx) are marked uploaded; halves that still return 413 recurse until a single-event leaf

#### Scenario: Server returns 413 for a single-event batch

- **GIVEN** the uploader POSTs a single-event batch and the event is itself larger than the server's per-request cap
- **WHEN** the server returns HTTP 413 with the `body_too_large` diagnostic
- **THEN** the event is dropped (marked uploaded so the queue stops surfacing it)
- **AND** a WARN log line includes the event id
- **AND** the `edr.agent.uploader.events_dropped_too_large` counter is incremented by one

### Requirement: Transient failures retry with backoff

The system SHALL retry transient failures (server 5xx, network errors, timeouts) with exponential backoff up to a configured maximum number of attempts before giving up on the current cycle.

#### Scenario: First attempt times out, second succeeds

- **GIVEN** the first upload attempt times out
- **WHEN** the uploader waits a backoff interval and retries
- **THEN** the retry uses the same batch
- **AND** a 2xx on the retry causes the events to be marked uploaded

#### Scenario: All retries exhausted

- **GIVEN** every retry within the configured maximum attempts has failed transiently
- **WHEN** the maximum is reached
- **THEN** the uploader stops retrying for this cycle
- **AND** the batch remains queued for a future cycle to attempt again

### Requirement: 401 triggers re-enrollment

The system MUST signal the enrollment subsystem when the server returns 401 so the agent can refresh its host token, and the batch SHALL remain in the queue to be retried under the refreshed token.

#### Scenario: 401 during upload

- **GIVEN** the uploader posts a batch and the server returns 401
- **WHEN** the response is observed
- **THEN** the uploader invokes the registered authentication-failure callback
- **AND** the batch is not marked uploaded
- **AND** the next upload cycle uses whatever token the enrollment subsystem currently holds

#### Scenario: 401 is treated as non-retryable within the cycle

- **GIVEN** the server returns 401
- **WHEN** the uploader handles the response
- **THEN** the uploader does not consume its retry budget on the same 401
- **AND** subsequent retries within the same call are not attempted; the batch waits for the next cycle

### Requirement: Permanent client errors are not infinitely retained

The system SHALL stop retrying batches that consistently produce an HTTP 400 (bad request) response after the configured maximum and SHALL emit an audit log entry so the operator can investigate why the server rejected those events. HTTP 400 is the only status the ingestion route emits to signal that a batch's content is bad (`invalid_json`, `host_id_mismatch`, `missing_fields_at_<i>`), so it is the only status that consumes the quarantine budget. A 401 (re-enroll) and a 413 (split-and-retry) keep their own recovery paths and do not consume the quarantine budget; any other status is handled as a blanket endpoint rejection (see "Blanket endpoint rejections keep the queue").

#### Scenario: Server consistently returns 4xx for a malformed event

- **GIVEN** the server returns HTTP 400 (the only malformed-content 4xx the ingest route emits) for a batch on every attempt
- **WHEN** the configured maximum retry budget is exhausted
- **THEN** the uploader records an audit log entry identifying the failure
- **AND** the batch is not retransmitted indefinitely

#### Scenario: A poison batch quarantines while sibling batches deliver

- **GIVEN** one batch consistently returns HTTP 400 while other batches return 2xx
- **WHEN** the poison batch crosses the quarantine threshold
- **THEN** only the poison batch is sealed
- **AND** the sibling batches are delivered and marked uploaded

### Requirement: Drain on shutdown

The system SHALL attempt one final upload cycle when the agent receives a shutdown signal so that any events the queue still holds get a last chance to reach the server before the process exits.

#### Scenario: Graceful shutdown

- **GIVEN** the queue is non-empty and the agent receives a cancellation signal
- **WHEN** the uploader's run loop observes the cancellation
- **THEN** the uploader executes one more upload attempt before returning
- **AND** any events that succeed in that attempt are marked uploaded before exit

### Requirement: Blanket endpoint rejections keep the queue

The ingestion route (`POST /api/events`) emits only 200, 400, 413 (intake handler) and 401, 503 (host-token middleware). Any other status the uploader observes (in particular 403, and likewise 404, 405, 408, 429, 451, and other non-2xx 4xx) is therefore not a per-batch content verdict from the EDR server but a blanket rejection injected by an edge/proxy/WAF or a wrong/unhealthy origin. The system MUST treat such a response as a transient endpoint rejection: it SHALL keep the batch queued (neither sealing it nor consuming the quarantine budget), back off to the next drain cycle, and resume delivery automatically when the endpoint returns 2xx. Retention during the rejection window is bounded only by the queue's `EDR_AGENT_QUEUE_MAX_BYTES` lossy cap. The system MUST emit a distinct WARN log and increment a dedicated counter labelled by status code so an operator can distinguish "the endpoint is rejecting every upload" from a quiet success.

#### Scenario: Sustained 403 preserves the queue and resumes on recovery

- **GIVEN** the endpoint returns HTTP 403 for every upload across many drain cycles
- **WHEN** the uploader drains repeatedly
- **THEN** no batch is sealed or dropped and the queued events remain (bounded only by the queue byte cap)
- **AND** the uploader emits the endpoint-rejection WARN and increments the endpoint-rejected counter
- **AND** when the endpoint later returns 2xx, the queued events are delivered and marked uploaded

#### Scenario: A non-400 4xx does not consume the quarantine budget

- **GIVEN** the endpoint returns HTTP 429 (or 404) for a batch on every attempt
- **WHEN** the uploader drains more times than the quarantine threshold
- **THEN** the batch is not sealed and remains queued for a future cycle
