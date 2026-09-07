# Acknowledging a batch requires still holding its claim

Fixes #817.

## The defect

`Ack` was an unconditional `UPDATE event_queue SET processed = 1 WHERE event_id IN (?)` whose affected-row count was ignored.

A claim expires after its lease and is re-offered to the next claimer. The lease comment described itself as "set well above the longest expected per-batch processing time so a live worker is never double-served", which is a design intent with nothing enforcing it: no code detected the case where it was exceeded.

So an evaluation that outlived its lease ran alongside its own reclaimer, and BOTH attempts acknowledged successfully. Neither learned it had lost.

## Why it mattered, and why it had not bitten

Alert persistence is immune: `InsertAlert` deduplicates on `(source, host_id, rule_id, subject)`, so a doubly-processed batch produces the same alerts. That is why this went unnoticed.

The per-rule monitor-match counter added in #816 is an additive upsert written AFTER the ack, with no equivalent unique key, so a doubly-acknowledged batch counted twice. #816 documented that as a residual inaccuracy, correctly noting the gap belonged to the queue contract rather than to the counter. Anything else that came to depend on exactly-once inherited it.

## Fix

The claim's `claimed_at_ns` becomes its identity. `ClaimForHost` returns the stamp it wrote, `Ack` requires it, and the transition is conditional:

```sql
UPDATE event_queue SET processed = 1 WHERE event_id IN (?) AND processed = 2 AND claimed_at_ns = ?
```

The affected-row count then tells the caller whether it still held the claim. A caller that lost skips whatever it does after acknowledging, because the attempt that owns the rows will do it, and logs that it lost, which is also the first visibility anyone has that leases are being exceeded at all.

Reusing `claimed_at_ns` rather than adding a token column: it is already written at claim time, a re-claim necessarily overwrites it, and that overwrite is exactly the condition to detect. No migration.

## Residuals, stated rather than claimed away

**Two claims in the same nanosecond** would both match. That needs a clock coarser than the one this runs on, and it is a residual rather than a guarantee.

**A partial match is treated as lost.** If a subset of the claim's rows still match, another attempt has taken the rest, so this attempt cannot claim to have processed the batch exactly once, which is the only thing the result is used for.

## Not in this change

Shortening the lease. The lease exists so a live claimer's rows are never stolen, and the claim's in-flight bound depends on it; making it shorter trades this problem for out-of-order folding, which #717 exists to prevent.
