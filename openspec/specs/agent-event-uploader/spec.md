# Agent Event Uploader Specification

## Purpose

The agent event uploader is the durable bridge between the agent's local event queue and the server's ingestion endpoint.
Endpoint security telemetry is generated continuously, often at peak rates that exceed the prevailing network throughput,
and the agent has no way to know in advance whether the server is reachable. The uploader's job is to take whatever the
queue holds, ship it as efficiently as the server's contract allows, and tolerate transient network or server failures
without losing events or duplicating them at rest.

The capability draws a clear boundary around delivery semantics. Events are at-least-once on the wire and exactly-once
at rest because the server deduplicates by event identifier; the uploader holds events in the local queue until the server
positively acknowledges them, retries with backoff on transient failure, and surfaces authentication failures to the
enrollment subsystem so token-revocation events do not silently drop telemetry.

## Requirements

### Requirement: Upload uses the host bearer token

The system SHALL include the current host token as an Authorization Bearer header on every event upload request and the
server SHALL reject requests that do not present a valid host token.

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

The system MUST mark events as delivered in its local queue only after the server returns a 2xx status code, so a server-side
failure during the response cannot cause silent event loss.

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

The system SHALL be free to retransmit any unacknowledged batch in full because the server deduplicates events on receipt
using each event's unique identifier.

#### Scenario: Same batch is delivered twice

- **GIVEN** a batch was delivered, the server persisted the events, and the response was lost in transit
- **WHEN** the agent retries the same batch
- **THEN** the server inserts no new rows for events whose identifiers already exist
- **AND** the second response is also a 2xx so the agent can mark them uploaded

### Requirement: Bounded request size

The system MUST cap the size of each upload request and split larger queue contents across multiple requests so that any
single HTTP request stays within the server's accepted body size and the network's practical MTU for streaming bodies.

#### Scenario: Queue holds more events than fit in one request

- **GIVEN** the queue contains more events than the per-request batch limit
- **WHEN** the uploader runs an upload cycle
- **THEN** the uploader emits one or more requests of bounded size
- **AND** events that did not fit in the first request remain queued for subsequent requests

### Requirement: Transient failures retry with backoff

The system SHALL retry transient failures (server 5xx, network errors, timeouts) with exponential backoff up to a configured
maximum number of attempts before giving up on the current cycle.

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

The system MUST signal the enrollment subsystem when the server returns 401 so the agent can refresh its host token, and the
batch SHALL remain in the queue to be retried under the refreshed token.

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

The system SHALL stop retrying batches that consistently produce non-401 4xx responses after the configured maximum and
SHALL emit an audit log entry so the operator can investigate why the server rejected those events.

#### Scenario: Server consistently returns 4xx for a malformed event

- **GIVEN** the server returns a non-401 4xx for a batch on every attempt
- **WHEN** the configured maximum retry budget is exhausted
- **THEN** the uploader records an audit log entry identifying the failure
- **AND** the batch is not retransmitted indefinitely

### Requirement: Drain on shutdown

The system SHALL attempt one final upload cycle when the agent receives a shutdown signal so that any events the queue still
holds get a last chance to reach the server before the process exits.

#### Scenario: Graceful shutdown

- **GIVEN** the queue is non-empty and the agent receives a cancellation signal
- **WHEN** the uploader's run loop observes the cancellation
- **THEN** the uploader executes one more upload attempt before returning
- **AND** any events that succeed in that attempt are marked uploaded before exit

