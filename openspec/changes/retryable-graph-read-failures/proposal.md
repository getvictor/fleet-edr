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

## Distinguishing a failed read from an empty one

Only errors are wrapped. A read that legitimately matches no row returns a nil row and a nil error, which rules already treat as an answer, and that path is untouched. `resolveSubjectProcess` composes with this without change: it already passes store errors through unchanged and only synthesizes `ErrProcessNotYetMaterialized` for a MISS inside the grace window, so a read failure now arrives as retryable and a miss keeps its existing narrower contract.

## Also in this change

`server/rules/api/types.go` claims an audit "confirms these three methods are the entire surface" the rules consume. `GraphReader` has six. The count matters here specifically, because a stale one is how a decorator ends up missing a method.

## Rejected

**Classify transient versus permanent read failures.** Retry only on a connection error, a deadlock or a timeout, and isolate a malformed query. More precise, and it needs a taxonomy of driver errors that is a maintenance burden and wrong on the first unfamiliar error. #836's bound already caps the permanent case at roughly fifteen minutes, which buys most of the benefit for none of the fragility. Worth revisiting only if that bound turns out to be reached in practice.

**Have each rule mark its own read failures.** Rejected above: silently broken by the next rule added.
