# server-availability delta: event claims are serialized per host

## MODIFIED Requirements

### Requirement: The processor scales across replicas via SKIP LOCKED

The system SHALL claim event batches for processing with row-level `SELECT ... FOR UPDATE SKIP LOCKED` so the event processor runs concurrently both across every replica and across multiple worker goroutines within a single replica, each claimer receiving a disjoint set of unprocessed events, and no event row claimed by more than one claimer at a time. This is the deliberate counterpart to the leader-gated periodic tasks: throughput-bound event processing scales horizontally across the replica fleet and vertically across the cores of one replica, rather than running on a single elected replica or a single goroutine. The intra-replica worker count is a fixed compiled constant, not an operator knob, and the in-process workers share one process-graph builder and one detection engine so cross-batch builder state stays coherent.

A claim SHALL be scoped to a single host, returning that host's claimable events in timestamp order. Disjointness alone is not sufficient for the process-graph builder: it resolves each `exec` against the rows already flushed, so an `exec` folded while its `fork` is still unflushed in another claimer's batch is indistinguishable from an `exec` with no `fork`, and the builder materializes a duplicate generation with a fabricated fork time and no back-reference to the image it replaced. The system SHALL therefore serialize the processing of one host's events, so that at most one claimer at a time is claiming, folding, and flushing for a given host, while different hosts continue to be processed in parallel. Serialization SHALL be coordinated through the same MySQL advisory locking the periodic tasks use, so it holds across replicas and releases automatically when a holder's connection drops. A claimer that finds a host already held SHALL proceed to another host with pending work rather than waiting on it.

The serialized region SHALL cover claiming, folding, and flushing, and SHALL NOT extend over rule evaluation, which only reads the materialized graph.

Because a claimer inside that region occupies two database connections at once, the connection the advisory lock pins and the connection its claim and flush use, the system SHALL bound its worker count so that the workers cannot exhaust the connection pool: exceeding the pool does not degrade throughput gracefully but stalls the pipeline with every worker holding a lock connection while waiting for a claim connection. When no advisory-lock coordinator is available the system SHALL run a single worker, which upholds the per-host ordering guarantee without a lock.

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

#### Scenario: Events for one host are folded in causal order under concurrency

- **GIVEN** one host's queued stream in which several pids each fork, exec, re-exec, and exit
- **AND** several processor workers claiming concurrently with a batch size small enough that each event is claimed separately
- **WHEN** the workers drain the queue
- **THEN** the materialized forest is identical to the forest a single worker produces from the same stream
- **AND** each generation is materialized once, with the fork time the fork event reported rather than its own exec timestamp
- **AND** each re-exec references the generation it replaced, and that generation is closed

#### Scenario: A claim never spans hosts

- **GIVEN** queued events for two hosts
- **WHEN** a claimer claims for one of them
- **THEN** it receives only that host's events, in timestamp order
- **AND** a claim for the other host is disjoint from the first

#### Scenario: Serializing one host does not stall the others

- **GIVEN** queued events for two hosts and several processor workers
- **AND** one worker parked inside its claim-fold-flush region for the first host
- **WHEN** the remaining workers continue claiming
- **THEN** the second host's events are materialized to completion while the first host is still held
- **AND** the first host's events are materialized once the holder proceeds

#### Scenario: Worker count is bounded by the connection pool

- **GIVEN** a configured worker count that would need more database connections than the pool allows
- **WHEN** the processor starts
- **THEN** it runs a reduced number of workers that the pool can serve
- **AND** it reports the reduction so the operator can see that the configured count was not honored
