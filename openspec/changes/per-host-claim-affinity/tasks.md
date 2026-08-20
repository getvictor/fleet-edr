# Tasks

## 1. Scope the claim to one host

- [x] 1.1 Replace the queue's cross-host `Claim` with `PendingHosts` plus `ClaimForHost`, and state in the contract that the queue does not provide per-host exclusivity.
- [x] 1.2 Order `PendingHosts` by each host's oldest claimable event so a long-waiting backlog is not starved by a busier host.
- [x] 1.3 Keep the READ COMMITTED isolation and bounded deadlock retry that issue #544 added, and the claim-lease expiry that makes delivery at-least-once.

## 2. Serialize the processor per host

- [x] 2.1 Take the host's advisory lock through the existing coordinator's non-blocking try-acquire; move to another candidate host when it is held.
- [x] 2.2 Scope the critical section to claim, fold, and flush; run detection and the ack outside it.
- [x] 2.3 Rotate each worker's scan by its worker index so simultaneous ticks do not contend on one host.
- [x] 2.4 Clamp concurrency to half the connection pool and log the reduction; fall back to a single worker when no coordinator is wired.

## 3. Prove the ordering property

- [x] 3.1 Assert concurrent workers produce the same normalized forest as a single worker over one host's fork/exec/re-exec/exit stream, at batch size 1 and across ten child pids so an unserialized fleet would have to get every order-sensitive pair right by chance to pass.
- [x] 3.2 Assert the resulting shape directly: one row per generation, re-execs linked, prior generations closed, no fabricated fork time.
- [x] 3.3 Assert a worker parked inside one host's critical section does not stop another worker from finishing a different host.
- [x] 3.4 Confirm the pre-existing multi-host drain test still passes, which is the throughput half of the property.
- [x] 3.5 Verify the equivalence test fails when the per-host lock is removed while concurrency is kept.
