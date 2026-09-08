# Carry a batch's monitor matches across its own retries

## Why

Monitor-mode match counts are recorded on whichever transition ends a batch's life: its acknowledgement, or its withdrawal from the queue once its retry bounds are passed (#843). The withdrawal half only works when the attempt that withdrew the batch is also the one that evaluated it, and that is not guaranteed. Retry bounds accrue on the queue entry and count every attempt, whichever stage failed. So a batch can fold, evaluate, resolve matches and fail at detection, be retried, and then fail at the FOLD on the attempt whose nack passes the bounds and withdraws it. The withdrawing attempt never evaluated and has no matches of its own; the evaluating attempt's were discarded when it was nacked, correctly, because a batch that is coming back produces them again. Nobody records them, and the batch is gone.

`#843` documented this as a residual rather than closing it, on the grounds that closing it would need either telemetry state in the work queue or per-replica state a stateless app tier cannot keep. The second is genuinely ruled out by ADR-0010: state a peer replica would need is exactly what would be lost on the restarts that produce these failures. The first turns out to cost nothing, because the nack that has a tally is ALREADY writing those queue rows.

The bias is one-directional and lands on the hosts that had the most trouble. A rule whose recorded volume is too low reads as quiet, which is what persuades an operator to promote it, and promoting a noisy rule is the alert flood monitor mode exists to prevent.

## What changes

- The event queue's `Nack` takes an opaque `[]byte` from the caller, keeps it with the returned events, and gives it back to whoever WITHDRAWS them. A nack with no bytes leaves what is kept alone, so a later attempt that failed before evaluation cannot erase what an earlier one resolved.
- The bytes are stored on ONE row of the batch, in the same `UPDATE` the nack already runs, so this costs no additional write on the drain path.
- The queue does not interpret them. An event queue that knew what a monitor match was would be a detection concern living in visibility, so the detection pipeline encodes and decodes its own tally in a versioned wire shape.
- The detection pipeline hands its tally over when it nacks after evaluating, and records the carried tally when it withdraws a batch at the fold.
- The residual is removed from the `observability-instrumentation` requirement and its scenario replaced with one asserting the carry, and the queue contract gains a requirement of its own in `server-event-ingestion`.

## Impact

- Affected specs: `observability-instrumentation`, `server-event-ingestion`
- Affected code: `server/visibility/api/eventlog.go`, `server/visibility/internal/eventlog/store.go`, `server/visibility/migrations/`, `server/detection/internal/pipeline/`
- One additive forward-only migration adds a nullable `BLOB` column to `event_queue`. No backfill: NULL is the ordinary state and means no attempt has evaluated the batch yet. A `JSON` column was measured and rejected: it parses and normalizes what it stores, so the bytes handed to the queue are not the bytes that come back, and bytes it cannot parse have their write refused, which fails the nack.
