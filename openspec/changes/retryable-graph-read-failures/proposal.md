# A failed graph read retries the batch instead of being isolated like a broken rule

Fixes #798.

## The defect

`Engine.evaluateRule` swallows every non-retryable rule error:

```go
findings, err := evaluate(ctx, rule, scoped, e.store, scope)
if err != nil {
    span.RecordError(err)
    if !errors.Is(err, rulesapi.ErrRetryBatch) {
        e.logger.WarnContext(ctx, "detection rule evaluation failed", "rule", rule.ID(), "err", err)
        return nil          // the processor then acks
    }
```

Per-rule isolation is deliberate and correct for a rule that is BROKEN: one defective rule must not stop detection for the others. But it does not distinguish that from a rule whose DEPENDENCY was unavailable. Every rule that reads the process graph returns an ordinary error when that read fails, so a transient database problem silently costs detections on every event in flight, leaving a WARN line as the only trace.

The two conditions want opposite handling. A broken rule cannot be helped by retrying and would hot-spin. A failed read is not a rule problem at all: the answer is simply not available yet, the events are still in the work queue, and every rule in the batch that touches the graph is equally affected.

This is pre-existing and shared. `shell_from_office`, `suspicious_exec` and the rest all wrap graph read failures with `fmt.Errorf` and none with `ErrRetryBatch`.

## Approach

Classify at the READ BOUNDARY, not in the rules.

The engine hands rules a `GraphReader`. It will hand them a decorator that wraps any non-nil error from the six read methods with `ErrRetryBatch`. The isolation branch then keeps its intended meaning: it catches rules that are wrong, not dependencies that are down.

At the boundary rather than in each rule because a contract that depends on every rule remembering to mark its own read failures retryable is one that an added rule silently breaks, and the resulting loss is invisible. There is nothing to remember this way: a rule that wraps the error with `fmt.Errorf` still matches `errors.Is`.

The decorator does NOT embed the interface. It holds it in a named field and implements all six methods explicitly, with a compile-time assertion that it satisfies `GraphReader`. That is the opposite of the right choice for a test fake, and deliberately so: embedding makes a fake survive interface growth, which is what a fake wants, and makes a decorator pass a newly added method through UNWRAPPED, which is exactly the drift this change exists to prevent. Adding a method to `GraphReader` will now fail the build until the decorator handles it.

Not wrapped inside the store itself: the same store serves the graph builder and the process-detail reads, and neither should inherit a rules-context retry sentinel.

## Why this is safe to do now, and was not before

Making a read failure retryable means a read that fails PERMANENTLY (a schema mismatch, say, rather than a dropped connection) would retry forever. The claim selects a host's work in timestamp order, so that batch would sit at the front of its host's queue and nothing newer for that host would ever be claimed.

That is issue #836, and it is now bounded: a batch that exceeds both the attempt bound and the duration bound is set aside so the host's queue advances. So the worst case of this change is a bounded delay and a bounded gap on one host, with a counter and an ERROR log naming it, rather than an unbounded stall. Sequencing #836 first is what makes this change's failure mode acceptable, and it is worth recording that the two issues are related that way.

## A distinct sentinel, not the generic one

The first cut wrapped read failures with `ErrRetryBatch` directly. That was wrong in three places at once, and wrong quietly, which is worse:

- **`pendingMiss.absorb` absorbed them.** That function continues the batch past a retryable per-event miss on purpose (issue #661: one permanently orphaned event must not mask every event behind it). A failed read is not that condition. Its own doc comment already said so ("retrying the remaining events against a broken reader would just multiply the failure"); routing read failures through the generic sentinel made the code stop matching its comment, and turned one outage into a read per event per rule on every retry.
- **The engine kept evaluating the batch's other rules**, each repeating the same doomed read.
- **The processor logged it at DEBUG**, a branch that exists so a rule which deliberately WAITS (sensor_tamper waits out a recovery window) cannot flood the logs. DEBUG is generally not emitted in production, so an outage costing detections across every host in flight would have been visible only as an absence of alerts.

`ErrRuleReadUnavailable` wraps `ErrRetryBatch`, so everything asking "should this batch be retried" still matches, while the per-event loops can tell a failed read from a wait.

Two of those three fixes were then over-corrections, and review caught both:

- **Stopping the batch's other rules was wrong**, because the reads do not share one dependency. The process and exec-chain lookups read MySQL; the event lookups delegate to the ClickHouse archive. An archive outage would have skipped every rule that reads only MySQL, and once the queue sets the batch aside those detections are lost rather than late. Only the per-event multiplier is removed now, which is where the batch-size factor actually lives.
- **Warning per attempt was wrong**, because at the processing cadence that is a continuous stream for as long as the condition lasts, which is the amplification the quiet treatment of deliberate waits already exists to avoid. It is surfaced by consequence instead: a retry that succeeds costs nothing and needs no line, and when retries are exhausted the set-aside record is at ERROR and now carries the failure as its cause.

Propagating also had to stop discarding the findings a rule had already resolved from earlier events, which is what `evalEachEvent`'s contract promises and what the engine persists alongside a retryable error. Discarding them loses detections outright once a permanently failing batch is set aside, since nothing re-derives them.

The sentinel is named for the READ rather than for a store, for the same reason: naming "the process graph" would tell an operator the wrong thing whenever it is the archive that is down.

## Distinguishing a failed read from an empty one

Only errors are wrapped. A read that legitimately matches no row returns a nil row and a nil error, which rules already treat as an answer, and that path is untouched. `resolveSubjectProcess` composes with this without change: it already passes store errors through unchanged and only synthesizes `ErrProcessNotYetMaterialized` for a MISS inside the grace window, so a read failure now arrives as retryable and a miss keeps its existing narrower contract.

## Also in this change

`server/rules/api/types.go` claims an audit "confirms these three methods are the entire surface" the rules consume. `GraphReader` has six. The count matters here specifically, because a stale one is how a decorator ends up missing a method.

## Rejected

**Classify transient versus permanent read failures.** Retry only on a connection error, a deadlock or a timeout, and isolate a malformed query. More precise, and it needs a taxonomy of driver errors that is a maintenance burden and wrong on the first unfamiliar error. #836's bound already caps the permanent case at roughly fifteen minutes, which buys most of the benefit for none of the fragility. Worth revisiting only if that bound turns out to be reached in practice.

**Have each rule mark its own read failures.** Rejected above: silently broken by the next rule added.
