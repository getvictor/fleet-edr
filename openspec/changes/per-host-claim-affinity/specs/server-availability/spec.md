# server-availability delta: event claims are serialized per host

## MODIFIED Requirements

### Requirement: The processor scales across replicas via SKIP LOCKED

The system SHALL claim event batches for processing with row-level `SELECT ... FOR UPDATE SKIP LOCKED` so the event processor runs concurrently both across every replica and across multiple worker goroutines within a single replica, each claimer receiving a disjoint set of unprocessed events, and no event row claimed by more than one claimer at a time. This is the deliberate counterpart to the leader-gated periodic tasks: throughput-bound event processing scales horizontally across the replica fleet and vertically across the cores of one replica, rather than running on a single elected replica or a single goroutine. The intra-replica worker count is a fixed compiled constant, not an operator knob, and the in-process workers share one process-graph builder and one detection engine so cross-batch builder state stays coherent.

A claim SHALL be scoped to a single host, returning that host's claimable events in timestamp order. Disjointness alone is not sufficient for the process-graph builder: it resolves each `exec` against the rows already flushed, so an `exec` folded while its `fork` is still unflushed in another claimer's batch is indistinguishable from an `exec` with no `fork`, and the builder materializes a duplicate generation with a fabricated fork time and no back-reference to the image it replaced. The system SHALL therefore serialize the processing of one host's events, so that at most one claimer at a time is claiming, folding, and flushing for a given host, while different hosts continue to be processed in parallel. Serialization SHALL be coordinated through the same MySQL advisory locking the periodic tasks use, so it holds across replicas and releases automatically when a holder's connection drops. A claimer that finds a host already held SHALL proceed to another host with pending work rather than waiting on it.

The serialized region SHALL cover claiming, folding, and flushing, and SHALL NOT extend over rule evaluation, which only reads the materialized graph. A batch whose folding failed SHALL be returned to the queue before the host's serialization is released, so the next claimer cannot take that host's later events and fold them ahead of the events being retried.

A claim SHALL NOT reach past an event that another claimer still holds. An in-flight event is invisible to the claimable predicate rather than blocking it, so without this bound a claimer that died between claiming a `fork` and flushing it would leave a hole the following `exec` pours through, reintroducing the exec-with-no-fork fold that scoping the claim to one host exists to prevent. When a host has an unexpired in-flight event, the system SHALL offer only that host's events strictly older than the oldest in-flight one, and SHALL offer nothing for that host when none are older. A host may therefore have no claimable work until an abandoned claim's lease expires, which is bounded by the lease and is preferable to folding its stream out of order. Claimers SHALL NOT reclaim another claimer's unexpired in-flight events. Queue timestamps originate in agent payloads, so the bound SHALL hold for any timestamp value an agent can send: no timestamp SHALL be reserved as a sentinel, since a reserved value either strands an event stamped with it or, through arithmetic on it, silently removes the bound.

Because a claimer inside that region occupies two database connections at once, the connection the advisory lock pins and the connection its claim and flush use, the system SHALL size its worker count to the connection pool so that the workers cannot exhaust it: exceeding the pool does not degrade throughput gracefully but stalls the pipeline with every worker holding a lock connection while waiting for a claim connection. The pool is process-wide and shared with the request path and the background sweeps, so the workers SHALL be sized to a share of it rather than to all of it. A pool too small to serve even one worker SHALL be refused at startup, naming the pool size the deployment needs, because a single worker there would pin the only connection for its lock and then wait forever for a claim connection: that is the stall the sizing exists to prevent, and a deployment that refuses to boot states its problem where one that boots and silently processes nothing does not.

When no advisory-lock coordinator is available the system SHALL run a single worker and SHALL report that its per-host ordering then holds only within that replica. One worker per replica is not host serialization: another replica's worker can claim the same host concurrently, so the guarantee is available only where a coordinator is configured. The coordinator-less mode is for single-replica and test deployments.

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

- **GIVEN** a configured worker count that would need more database connections than its share of the pool allows
- **WHEN** the processor starts
- **THEN** it runs a reduced number of workers that the pool can serve
- **AND** it reports the reduction so the operator can see that the configured count was not honored

#### Scenario: A pool too small for one worker is refused at startup

- **GIVEN** a connection pool smaller than the connections one serialized worker holds
- **WHEN** the processor is constructed with an advisory-lock coordinator
- **THEN** construction fails rather than starting a worker that would stall on the pool
- **AND** the failure names the pool size the deployment needs

#### Scenario: A failed batch is requeued before the host is released

- **GIVEN** a claimed batch whose folding fails
- **WHEN** the claimer handles the failure
- **THEN** the batch is returned to the queue before the host's serialization is released
- **AND** the batch is not acknowledged

#### Scenario: A claim stops at a host's oldest in-flight event

- **GIVEN** a host whose oldest queued event is held by another claimer under an unexpired claim
- **AND** later events queued for that same host
- **WHEN** a claimer claims for that host
- **THEN** it receives no events for that host rather than the later ones
- **AND** once the abandoned claim's lease expires, that host's events are offered again in timestamp order starting from the oldest
#### Scenario: A claim bound cannot be defeated by an extreme timestamp

- **GIVEN** a queued event whose timestamp is the maximum representable value
- **WHEN** its host is claimed
- **THEN** that event is offered like any other, rather than being permanently unclaimable
- **GIVEN** instead a host whose oldest in-flight event carries the minimum representable timestamp
- **WHEN** that host is claimed again while the claim is unexpired
- **THEN** nothing is offered for it, because no event is strictly older, and the bound is not removed by arithmetic on that value

