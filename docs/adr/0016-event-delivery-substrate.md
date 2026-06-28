# 0016. Event delivery: database-backed work queue now, streaming substrate at scale

- Status: Accepted
- Date: 2026-06-28
- Deciders: getvictor

## Context

After the ClickHouse cutover (ADR-0015), ingestion fans out each batch to the ClickHouse event archive plus a MySQL `event_queue` work queue. The detection processor claims from that queue with `SELECT ... FOR UPDATE SKIP LOCKED` (ADR-0011), processes the batch (process-graph materialization plus rule evaluation), acks it (`processed = 1`), and a leader-gated sweep prunes acked rows. This is the "database as a work queue" pattern: no message broker, all delivery state lives in MySQL.

A scale test (#203) on one server replica against an isolated stack characterized the ceiling. Ingest itself scaled cleanly to 500 simulated hosts (p99 136ms, zero errors, server RSS flat). The detection processor did not keep pace: the `event_queue` backlog grew linearly (0 to ~37k pending) at 500 hosts on one replica, while 200 hosts stayed bounded, so the single-replica breakeven is roughly 300 hosts at a deliberately detection-heavy synthetic mix (20% of hosts running attack scenarios continuously). Running the same 500-host load across three replicas behind a balancer kept the backlog bounded under ~500: the processor is not leader-gated and scales out linearly via SKIP LOCKED.

A pprof pass on a saturated single replica showed the processor is I/O-round-trip bound, not compute bound: only 25% CPU utilization over the sample window, ~74% of on-CPU time in syscalls and netpoll (waiting on the DB), and the wall-time concentrated in the graph builder doing per-event `SELECT` then `UPDATE`/`INSERT` round-trips (`GetProcessByPID` then `UpdateProcessExec`), one event at a time on a single goroutine. A 500-event batch is ~1000 to 1500 sequential DB round-trips.

The forward question this raises: a high-scale EDR ultimately wants servers to consume from a streaming log (Kafka, Redpanda, NATS JetStream) rather than poll a database. Do we adopt a streaming backbone now, and is the throughput work worth doing on the DB-queue model if streaming replaces it later?

## Decision

Keep the database-backed work queue (`event_queue` plus the ADR-0011 SKIP LOCKED claim) as the event-delivery substrate for the current pilot envelope (10 to 500 endpoints, single-VM and quickstart deployment). Invest in detection-processor throughput now (batch the per-event DB round-trips in the graph builder and rule evaluation; add intra-replica processing concurrency) rather than introducing a streaming backbone. Adopt a streaming substrate only when we outgrow DB-as-queue (thousands or more endpoints, or multi-tenant SaaS), and when we do, favor a single-binary substrate (Redpanda or NATS JetStream) over a full Kafka plus ZooKeeper deployment so the self-hosted deployment story survives.

The throughput work is the right near-term spend because the dominant cost (per-event processing in the graph builder and rule evaluator) is independent of how events are delivered, so it lands in the part that a streaming migration keeps. The lever transfer:

| Lever (today) | Under a streaming substrate | Survives the migration? |
| --- | --- | --- |
| Batch the per-event DB round-trips (set-based `GetProcessByPID`, batched writes, one transaction per batch) | Unchanged: the processor still builds the graph and evaluates rules per event regardless of delivery | Yes, and it becomes the dominant lever once queue overhead is gone |
| Intra-replica processing concurrency (N worker goroutines) | Becomes partition-parallelism: one consumer goroutine per assigned partition; partition count is the scaling knob | Yes, reframed and cleaner (no SKIP LOCKED contention) |
| Horizontal replicas | Add consumers to the consumer group, bounded by partition count | Yes, same idea, different mechanism |
| `event_queue` plus `Claim`/`Ack`/`Nack`/`PruneProcessed` plus the `claimed_at_ns` lease | Replaced by the log's offsets, retention, and consumer-group rebalance | No: superseded by the substrate |
| Server-backlog gate (sampled `event_queue` pending depth, #203) | Becomes consumer lag; same gate, the broker reports the number | Yes (concept transfers; only the metric source changes) |

## Consequences

Easier or cheaper now: no new operational dependency; the quickstart stays a single compose file (relevant to #534); the processor improvements pay off in both architectures because they target the delivery-independent processing path; the per-host ordering the builder already tolerates (concurrent, arrival-order-resolved by parent ID) means intra-replica concurrency is no more dangerous than the cross-replica concurrency the design already runs in production.

Harder or accepted as debt: MySQL does work-queue duty it is not ideal at (the claim, ack, and prune round-trips, plus the `PruneProcessed` sweep and its backlog gate, are overhead a log would not need); per-host ordering relies on `Claim ... ORDER BY host_id, timestamp_ns` plus builder tolerance rather than partition-native ordering; the eventual streaming migration is real work (stand up the substrate, re-key events by host to a partition, move the archive sink to a log consumer, swap the processor's claim loop for a consumer loop). The `event_queue` claim, ack, and prune machinery is explicitly interim and will be superseded.

Backpressure today is the queue growing in MySQL (visible as the #203 backlog gate); a log would absorb spikes more gracefully and give replay for free. We accept the weaker backpressure story at the pilot scale because the queue is durable and the archive is complete, so a processing spike drains rather than loses data.

## Alternatives considered

Adopt Kafka now. Attractive because it is the industry-standard EDR-scale answer and would settle the delivery substrate once. Rejected: the operational weight (brokers, ZooKeeper or KRaft, partitions, a sink connector) breaks the single-VM quickstart deployment model the product is built around, and it is premature for a 10-to-500-endpoint pilot that one or two small replicas already serve.

Adopt Redpanda or NATS JetStream now. Attractive because both ship as a single binary and would preserve the lightweight deployment story while giving real log semantics. Rejected for now only on timing: it is still a new dependency, and the DB-queue plus processor improvements cover the target envelope. This is the leading option for the scale move and is named here so the next maintainer starts from it rather than reaching for Kafka by reflex.

ClickHouse-only, no separate work queue (poll the archive for unprocessed rows). Attractive because it removes the second store. Rejected: ClickHouse is append-and-scan optimized and is a poor work queue (no row-level claim or lease, expensive point deletes), so the claim, ack, and re-delivery semantics ADR-0011 depends on would be hard and slow to emulate.

Stay on DB-as-queue indefinitely and only scale by adding replicas. Attractive for its simplicity. Rejected as the end state because DB-as-queue has a real ceiling (MySQL contention on the claim, prune cost, no native partitioned ordering or replay), but accepted as the correct choice for now: scale out with replicas plus the throughput work, and revisit when the fleet outgrows it.

## References

- ADR-0011 (HA architecture, SKIP LOCKED claim semantics)
- ADR-0015 (ClickHouse visibility store)
- ADR-0010 (stateless server, multi-replica behind a load balancer)
- #203 (soak, chaos, and 500-agent scale testing): the measurements that motivated this decision
- #427 (ClickHouse event-store migration) and #534 (operator ClickHouse deployment)
- The detection-processor throughput issue filed alongside this ADR
- pprof finding (2026-06-28): single-replica processor 25% CPU, I/O-round-trip bound in `graph.Builder.ProcessBatch` per-event `GetProcessByPID` plus `UpdateProcessExec`
