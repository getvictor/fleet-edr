# Serialize event claims per host

## Why

The processor's four workers claim with `FOR UPDATE SKIP LOCKED`, which respects row locks but not causal grouping. `SKIP LOCKED` hands each concurrent claimer whatever rows are not locked at that instant, so two workers scanning one ordered set interleave across it and a single host's fork/exec stream is split between them (issue #717).

The graph builder resolves each exec against the rows already flushed, so an exec folded while its fork sits unflushed in another worker's batch is indistinguishable from an exec with no fork at all. It takes the exec-without-fork path and writes a duplicate row whose `fork_time_ns` is fabricated from its own exec timestamp, leaves `previous_exec_id` NULL, and strands the real fork row carrying a path inherited for the wrong process.

Measured against the running dev server with one POST of eight envelopes describing three processes. At the shipped concurrency of 4: eight rows instead of five, `previous_exec_id` NULL on every row, `exec_time_ns = fork_time_ns` on every exec row, no generation ever closed, and three orphaned fork rows with unrelated inherited paths. At concurrency 1 the same POST produced five rows, re-execs linked, prior generations closed, and real fork times.

This requirement's own scenario already promised that concurrent workers produce "the same materialized process forest as if the events had been claimed by a single worker". Nothing tested it: the only concurrency test seeded independent forks, whose forest is identical under any ordering, which is exactly why the defect went unnoticed.

The consequences reach past the duplicated rows. `GetExecChain` returns nil when `previous_exec_id` is nil, so `suspicious_exec`'s re-exec fallback is dead for anything materialized this way, and the pidversion rule from #715 is unreachable for a fork/exec pair arriving in one POST, which is the normal shape of an agent flush.

## What changes

- A claim is scoped to one host. `PendingHosts` picks the host, `ClaimForHost` takes its oldest claimable events in timestamp order. The queue still does not make a host exclusive to a claimer; scoping is what keeps one lock's critical section to one host's work.
- The processor serializes each host on that host's MySQL advisory lock, reusing the existing coordinator's non-blocking try-acquire. A worker that loses the race moves to another candidate host instead of queueing, so serializing a host does not serialize the fleet.
- The lock spans claim, fold, and flush, and nothing else. That is the exact window in which a second claimer breaks the builder's ordering assumption. Detection stays outside it: it only reads the graph, and the coordinator's one-shot acquire has no keep-alive, so a long critical section risks MySQL closing the idle lock connection.
- A claim stops at the host's oldest in-flight event. An event another claimer holds does not match the claimable predicate, so it is a hole rather than a stop sign: a claimer that died between claiming a fork and flushing it would let the next claimer take the following exec and fold it as an exec with no fork, which is the same defect the host scoping fixes. The claim now bounds itself below any unexpired in-flight event for that host, so a host can be quiet until an abandoned claim's lease expires. That wait is bounded by the lease and preferable to an out-of-order fold. Nothing reclaims another live worker's rows.
- A failed batch is requeued inside the lock, not after it. Releasing the host first would let the next claimer take that host's later events and fold them ahead of the ones still awaiting requeue.
- The worker fleet is sized to a share of the connection pool. A worker inside the critical section holds two pooled connections at once, the one `GET_LOCK` pins plus the one the claim and flush use, so a pool smaller than twice the worker count lets every worker hold a lock connection while waiting for a claim connection that no one will release. That failure mode is a silent stall with nothing logged. The pool is process-wide and shared with the request path and the sweeps, so the fleet takes a share of it rather than all of it, and the reduction is logged. A pool too small for even one worker is refused at construction, naming the pool size to raise it to: clamping to one worker there would preserve exactly the stall the sizing prevents, and a deployment that will not boot states its problem where one that boots and processes nothing does not.
- With no coordinator wired the processor runs a single worker and says so. One worker per replica is NOT host serialization: another replica's worker can claim the same host at the same time, so the ordering guarantee holds only within a replica and the warning says that rather than implying otherwise. Coordinator-less operation is for single-replica and test deployments.

## Non-goals

- The builder is not made order-insensitive. An out-of-order arrival can still reach it from an agent-side retry or a re-delivered claim, and reconciling a late fork against an existing exec row is a separate change.
- The `GetParentPath` lifetime bug in issue #714 is untouched. Serializing the claim removes the orphaned fork rows that made it visible, but the unbracketed parent lookup is independently wrong.
- The intra-replica worker count stays a compiled constant rather than becoming an operator knob.
