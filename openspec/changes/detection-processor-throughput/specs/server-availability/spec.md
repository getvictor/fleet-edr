## MODIFIED Requirements

### Requirement: The processor scales across replicas via SKIP LOCKED

The system SHALL claim event batches for processing with row-level `SELECT ... FOR UPDATE SKIP LOCKED` so the event processor runs concurrently both across every replica and across multiple worker goroutines within a single replica, each claimer receiving a disjoint set of unprocessed events, and no event row claimed by more than one claimer at a time. This is the deliberate counterpart to the leader-gated periodic tasks: throughput-bound event processing scales horizontally across the replica fleet and vertically across the cores of one replica, rather than running on a single elected replica or a single goroutine. The intra-replica worker count is a fixed compiled constant, not an operator knob, and the in-process workers share one process-graph builder and one detection engine so cross-batch builder state stays coherent.

#### Scenario: Two replicas claim disjoint event batches

- **GIVEN** unprocessed events in the shared store and two replicas claiming batches concurrently
- **WHEN** both run the SKIP LOCKED claim
- **THEN** each replica receives a batch of events
- **AND** no event appears in both replicas' batches

#### Scenario: Concurrent workers within one replica claim disjoint event batches

- **GIVEN** unprocessed events in the shared store and multiple processor workers in one replica claiming batches concurrently
- **WHEN** the workers run the SKIP LOCKED claim
- **THEN** each worker receives a disjoint batch and no event is claimed by more than one worker
- **AND** the materialized process forest is the same as if the events had been claimed by a single worker

## ADDED Requirements

### Requirement: The shared database connection pool is bounded

The system SHALL bound the shared MySQL connection pool with a fixed maximum number of open connections, so that intra-replica processor-worker concurrency multiplied across the replica fleet cannot exhaust the database server's connection limit. The ceiling is a compiled constant sized to the worker count with headroom for request-path queries, not an operator-configurable knob, and it is applied when the process-wide pool is opened.

#### Scenario: Worker concurrency cannot exhaust database connections

- **GIVEN** a replica running its processor workers plus request-path query load
- **WHEN** the workers and request handlers acquire connections concurrently
- **THEN** the total open connections the replica holds is capped at the compiled pool ceiling
- **AND** demand above the ceiling waits for a pooled connection rather than opening an unbounded number
