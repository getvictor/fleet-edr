# Serialize the acknowledgement window against a host's claimers

## Why

`Ack`'s conditional update can let a concurrent claimer fold a later event before its predecessor (#863), which is the ordering guarantee the claim's in-flight floor exists to protect, reached by a route the floor cannot see.

The statement takes row locks as it scans, so an earlier event of a batch is locked while a later one is not. A claimer arriving in that window finds the locked row through `FOR UPDATE SKIP LOCKED`, skips it, and takes the later one. The floor does not bound it: the floor counts only claims that are still LIVE, and this window is reached precisely when the claim has outlived its lease, which is what makes the rows claimable at all. The host advisory lock does not cover it either: it serializes claimers against each other, and the processor releases it before evaluation, so the acknowledgement runs outside it.

#859 did not introduce the interleaving. A single `UPDATE` always took row locks incrementally. What changed is the outcome: the partial update used to COMMIT, so the earlier event was acknowledged and only the later one was reprocessed. Rolling back to avoid half-acknowledging was the right fix, and this is its residual.

## What changes

The acknowledgement takes the host's claim lock for the duration of the call, and so does the requeue on a detection failure, which is the same statement shape reached by the other exit from evaluation. The builder-stage requeue was already inside the lock.

This is #863's option 3, a separate short window rather than extending the claim's. Rule evaluation still runs outside any lock, which is the property the processor deliberately has: a slow rule must not hold a host.

Both paths take the advisory lock before any row lock, the same order the claim path uses, so the two cannot deadlock against each other.

## Impact

- One additional advisory-lock round trip per batch, on a path that already measured 39ms p50 for 100 events (#837). The window is one statement long.
- No change without a coordinator: `NewProcessor` forces a single worker there, so there is no second claimer on the replica to race. That mode already disclaims per-host ordering across replicas.
- `Ack`'s documentation now states that it does not serialize itself and that the caller must, so the guarantee is not re-derived by the next reader.
