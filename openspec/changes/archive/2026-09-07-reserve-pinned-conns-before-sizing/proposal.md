# Size the worker fleet against connections that are actually available

## Why

Two defects in the processor's connection-budget guard, both found by Copilot in the #719 review and deliberately deferred there because neither is reachable at the shipped defaults (issue #722).

**The guard admitted budgets its own error message rejected.** It refused below `connsPerWorker` (2) while telling the operator to raise the pool to `connsPerWorker * workerPoolShareDivisor` (4). Budgets of 2 and 3 passed a check whose own advice called them insufficient, and the `max(..., 1)` floor then manufactured a worker the pool could not serve: it pins the only connection for `GET_LOCK` and waits forever for a claim connection. That is precisely the stall the guard exists to prevent.

**Affordability ignored the leader loops.** In full mode three `RunIfLeader` loops each pin a pooled connection for the whole process lifetime. Confirmed empirically rather than from source: a dev server logs `acquired leadership` for exactly `edr_process_ttl`, `edr_queue_prune` and `edr_retention`. The worker sizing counted those three connections as available, so a small pool could be consumed entirely by the leader locks plus one worker's `GET_LOCK`, with the claim waiting on a connection nobody will release.

Neither is reachable today because `dbMaxOpenConns` is a fixed 25: three leader connections plus four workers at two each is 11 of 25. Both become reachable the moment the pool size becomes configurable or concurrency rises far enough.

## What changes

Connections that are pinned for the process lifetime are subtracted before anything is sized. The count is injected (`ProcessorOptions.ReservedConns`) rather than assumed, because the processor should not encode how many background sweeps its caller starts; the bootstrap that wires those loops is the only thing that knows. The number itself lives next to the lock names it counts, as `pipeline.LeaderGatedLoops`, with a test pinning the two together.

The refusal threshold and the error message now quote one number instead of two that disagreed, and the message includes the reservation so the figure an operator is told to raise the pool to is the figure actually enforced. With an honest threshold the `max(..., 1)` floor stops being a fiction and is gone: the refusal already guarantees at least one worker is affordable, so a floor could only ever manufacture one the pool cannot serve.

## Not a behaviour change at the shipped defaults

Deliberately verified rather than assumed, because a sizing fix that quietly shrank the production fleet would be a worse bug than the one being fixed: 25 budget, 3 reserved, 4 configured still yields 4 workers, and there is a test case that fails if that ever stops being true.

## Why a new requirement

The natural home is `The processor scales across replicas via SKIP LOCKED`, which owns the existing sizing scenarios. It already carries an in-flight MODIFIED delta from `per-host-claim-affinity`, and two in-flight deltas against one requirement is a known archive hazard here: the second to archive silently drops the first's scenarios. The existing scenarios also remain true as written; what is new is the reservation, which is a separable property.
