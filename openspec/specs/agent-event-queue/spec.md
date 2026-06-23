# Agent Event Queue Specification

## Purpose

The agent event queue is the durable buffer between the on-device capture pipeline and the upload to the EDR server. It exists because the upload path is fundamentally less reliable than the capture path: the device may be offline, the server may be temporarily unavailable, the agent may be restarted by the user, and the host may crash. Without durability the EDR loses telemetry every time any of those happen. With durability, captured events survive process exit and reboot, and the uploader can drain the queue on its own schedule.

This capability defines the queue's external contract: how events enter, how they are dequeued for upload, how their lifecycle is tracked from "captured" to "uploaded" to "pruned", how the queue stays bounded under sustained capture without bringing down the host, and what observable guarantees the rest of the agent depends on.

## Requirements

### Requirement: Durable enqueue

The queue SHALL persist every successfully enqueued event to non-volatile storage before returning success. An event that has been successfully enqueued MUST survive an immediate process exit or host reboot and remain available for later dequeue.

#### Scenario: Agent crashes after enqueue

- **GIVEN** an event has been enqueued and the enqueue call returned success
- **WHEN** the agent process exits abruptly before the uploader has run
- **AND** the agent process restarts and re-opens the queue
- **THEN** the enqueued event is still present in the queue
- **AND** it can be dequeued for upload

### Requirement: FIFO dequeue of pending events

The queue SHALL return pending (not-yet-uploaded) events in insertion order when the uploader requests a batch. The uploader MAY request up to a caller-supplied batch size; the queue MUST return at most that many pending events.

#### Scenario: Uploader requests a batch

- **GIVEN** the queue contains five pending events enqueued in order A, B, C, D, E
- **WHEN** the uploader requests a batch of three events
- **THEN** the queue returns events A, B, C in that order
- **AND** the queue does not return D or E in this batch

#### Scenario: Uploader requests more than is available

- **GIVEN** the queue contains two pending events
- **WHEN** the uploader requests a batch of ten events
- **THEN** the queue returns the two pending events
- **AND** the queue does not block waiting for more

### Requirement: Acknowledgement marks events uploaded

After the uploader successfully posts a batch to the server, it SHALL acknowledge the batch back to the queue by event ID. Acknowledged events MUST NOT be returned by subsequent dequeue calls. Acknowledgement of a non-existent ID MUST be a no-op rather than an error: the cap-eviction path described under "Bounded storage with operator-visible lossy fallback" can drop a pending row out from under an in-flight uploader, so an uploader that holds dequeued event IDs and later acknowledges them MUST tolerate the case where some IDs no longer exist. Dequeue does not lock or pin rows against eviction; the queue remains a single durable source of truth and the uploader treats acknowledgement as best-effort cleanup.

#### Scenario: Successful upload is acknowledged

- **GIVEN** the uploader has dequeued and posted a batch of events
- **WHEN** the uploader marks those events uploaded
- **THEN** subsequent dequeue calls do not return those events
- **AND** the queue's depth metric (pending events) decreases by the size of the acknowledged batch

#### Scenario: Upload fails and the events are retried

- **GIVEN** the uploader dequeued a batch but the post to the server failed
- **WHEN** the uploader does not acknowledge the batch
- **THEN** the next dequeue call returns those same events again
- **AND** the events remain durable until they are successfully uploaded or pruned

#### Scenario: Cap eviction races an in-flight upload

- **GIVEN** the uploader has dequeued a batch and the queue subsequently evicts the oldest pending rows under the byte cap, including some IDs from that in-flight batch
- **WHEN** the uploader posts the batch to the server and then acknowledges the IDs it dequeued
- **THEN** acknowledgement is a no-op for the IDs the eviction already removed
- **AND** the eviction is reported through the lossy-drop metric so operators can see that telemetry was lost

### Requirement: Bounded storage with operator-visible lossy fallback

The queue SHALL enforce an operator-configurable byte cap on its persistent storage. When the cap would be exceeded the queue SHALL first drop already-uploaded rows (lossless cleanup), and only when no uploaded rows remain MAY it drop the oldest pending rows. Lossy drops of pending events MUST be reported to operators (log warning and a metric) so sustained backpressure is visible.

#### Scenario: Cap is reached but uploaded rows can absorb the pressure

- **GIVEN** the queue is at its byte cap and contains a mix of uploaded and pending rows
- **WHEN** a new event is enqueued
- **THEN** the queue drops the oldest already-uploaded rows to make space
- **AND** no pending events are lost
- **AND** the new event is accepted

#### Scenario: Cap is reached with no uploaded rows to drop

- **GIVEN** the queue is at its byte cap and every row is still pending upload
- **WHEN** a new event is enqueued
- **THEN** the queue drops the oldest pending events to make space
- **AND** the queue logs a warning identifying how many rows were dropped and the configured cap
- **AND** the queue records the drop in its metrics with a flag indicating the drop was lossy

#### Scenario: Cap is disabled

- **GIVEN** the queue is configured with the cap disabled
- **WHEN** events are enqueued faster than they are uploaded
- **THEN** the queue does not drop any events on cap grounds
- **AND** the queue grows unbounded, subject only to underlying storage capacity

### Requirement: Pruning of old uploaded events

The queue SHALL provide a prune operation that deletes already-uploaded events older than a caller-supplied duration. Prune MUST NOT delete events that have not yet been uploaded.

#### Scenario: Prune removes old uploaded rows

- **GIVEN** the queue contains uploaded events older than the prune threshold and pending events of any age
- **WHEN** the agent invokes prune with that threshold
- **THEN** the queue deletes the old uploaded events
- **AND** the queue does not delete any pending events

#### Scenario: Prune with no eligible rows

- **GIVEN** the queue contains only recent uploaded events and pending events
- **WHEN** the agent invokes prune
- **THEN** the queue deletes nothing
- **AND** the prune call reports zero rows removed

### Requirement: Idempotent re-enqueue of identical event identifiers

Because the agent may emit reconciliation events whose identifiers can be re-derived after a restart, the queue MUST NOT reject a fresh enqueue solely because an event with the same `event_id` was previously enqueued. Server-side idempotency is the single source of truth for de-duplication.

#### Scenario: An event with a duplicate event_id is enqueued

- **GIVEN** an event with a particular `event_id` has been enqueued and uploaded
- **WHEN** the agent enqueues another event carrying the same `event_id`
- **THEN** the queue accepts the second enqueue
- **AND** the second event becomes pending and is later eligible for upload

### Requirement: Queue depth is observable

The queue SHALL expose the count of currently-pending (not-yet-uploaded) events on demand so operators and the agent shutdown path can report how much backlog exists.

#### Scenario: Depth after several enqueues

- **GIVEN** five events have been enqueued and three have been acknowledged uploaded
- **WHEN** the agent reads the queue depth
- **THEN** the depth is two

### Requirement: Storage I/O errors surface to the caller

The queue SHALL return an error from enqueue and dequeue when the underlying storage is unavailable (for example, when the disk is full). The caller MUST be able to back off, retry, or shed load on the basis of that error rather than silently losing data.

#### Scenario: Disk is full during enqueue

- **GIVEN** the host's disk has no free space
- **WHEN** the agent attempts to enqueue an event
- **THEN** the enqueue call returns an error
- **AND** the caller is responsible for backoff or load shedding

### Requirement: Synthetic reconciliation events use the same queue

The queue SHALL accept reconciliation events (synthetic exit events emitted by the agent, snapshot exec events emitted by the extension, and snapshot heartbeat events emitted by the agent for still-alive snapshot-originated processes) on the same path as kernel-observed events, and MUST NOT distinguish them from organic events for the purposes of durability, ordering, or upload.

#### Scenario: Reconciliation exit event is queued and uploaded

- **GIVEN** the agent has synthesized a reconciliation `exit` event
- **WHEN** the agent enqueues the synthetic event
- **THEN** the queue persists it the same as any other event
- **AND** the uploader returns it from a normal dequeue
- **AND** the server receives the event with `exit_reason = host_reconciled` intact

#### Scenario: Snapshot heartbeat event is queued and uploaded

- **GIVEN** the agent has synthesized a `snapshot_heartbeat` event for a still-alive snapshot-originated process
- **WHEN** the agent enqueues the synthetic event
- **THEN** the queue persists it the same as any other event
- **AND** the uploader returns it from a normal dequeue
- **AND** the server receives the event with its `snapshot_heartbeat` event type intact

### Requirement: Pre-enqueue coalescing of repetitive network and DNS telemetry

The agent SHALL coalesce repetitive `network_connect` and `dns_query` events within a bounded time window before they are enqueued, so that a process repeatedly connecting to the same destination or repeatedly resolving the same name is uploaded as a representative event plus an occurrence count rather than one row per occurrence. Coalescing MUST apply only to `network_connect` and `dns_query`; every other event type MUST be enqueued immediately with no added latency.

Within a window, events that share an identity key are merged into one representative. The key is `(pid, pidversion, protocol, direction, remote_address, remote_port)` for `network_connect` and `(pid, pidversion, query_name, query_type)` for `dns_query`. The representative MUST preserve detection-relevant fidelity:

- its envelope timestamp MUST be the earliest occurrence's timestamp, so a downstream correlation window measured backward from a later event is never shortened;
- it MUST carry an occurrence count and the latest occurrence's timestamp so the span and frequency are recoverable;
- for `dns_query` its resolved-addresses set MUST be the union of all addresses observed across the merged events, so a later connection to any resolved address still correlates.

A representative MUST NOT be held longer than one window. The agent MUST flush all buffered representatives on shutdown so a clean stop loses no buffered telemetry. The window is operator-configurable, and a window of zero MUST disable coalescing entirely, restoring per-occurrence enqueue.

#### Scenario: Repeated identical connections collapse to one representative

- **GIVEN** coalescing is enabled with a non-zero window
- **WHEN** a process emits several `network_connect` events with the same identity key within one window
- **THEN** exactly one representative event is enqueued for that key
- **AND** its timestamp equals the earliest occurrence's timestamp
- **AND** its occurrence count equals the number of merged events

#### Scenario: A DNS query and its response merge, preserving all answers

- **GIVEN** coalescing is enabled with a non-zero window
- **WHEN** a process resolves a name and the proxy emits the query event and a follow-on response event for the same key within one window
- **THEN** one representative `dns_query` is enqueued
- **AND** its `response_addresses` is the union of every resolved address observed for that key

#### Scenario: Non-network events are never delayed by coalescing

- **GIVEN** coalescing is enabled
- **WHEN** an `exec`, `fork`, `exit`, `snapshot_heartbeat`, or application-control event is handled
- **THEN** it is enqueued immediately, unchanged, without being buffered

#### Scenario: Buffered representatives are flushed on shutdown

- **GIVEN** coalescing is enabled and one or more representatives are buffered
- **WHEN** the agent is asked to shut down
- **THEN** every buffered representative is enqueued before shutdown completes

#### Scenario: A zero window disables coalescing

- **GIVEN** the coalescing window is configured to zero
- **WHEN** any `network_connect` or `dns_query` event is handled
- **THEN** it is enqueued immediately and unchanged, exactly as without coalescing
