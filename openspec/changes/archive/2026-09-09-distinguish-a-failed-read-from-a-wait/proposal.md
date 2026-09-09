# Distinguish a failed graph read from a rule that is deliberately waiting

## Why

Since #798 the engine wraps every read a rule performs so a FAILED read carries `ErrRetryBatch` and the batch is nacked rather than acked. That fixed the detection loss and left the read failure looking exactly like a rule that cannot decide yet, and the two want opposite handling.

`pendingMiss.absorb` continues the batch past a retryable per-event error on purpose (#661: one permanently orphaned event must not mask every event behind it). A failed read is not that condition. The next event's read reaches the same unavailable dependency, so continuing multiplies one outage by the batch size. `absorb`'s own comment says exactly that, and stopped describing its code the moment read failures started carrying the generic sentinel.

At the claim limit and the 500ms processor cadence, one outage becomes a read per event per rule, on every retry, until the queue's bound sets the batch aside (#836). Roughly fifteen minutes of that against a dependency already in trouble, which delays the recovery the retry is waiting for.

## What changes

- A distinct `ErrRuleReadUnavailable` sentinel that WRAPS `ErrRetryBatch`, so every consumer asking "retry this batch?" still matches while the divergence becomes expressible. Named for the READ, not for a store: `GraphReader` spans MySQL and the ClickHouse archive, so a sentinel naming "the process graph" would misdescribe an archive outage.
- `absorb` propagates it instead of absorbing it, stopping that rule's pass over the batch. It does NOT stop the batch's other RULES, because those two dependencies are independent and stopping would let an archive outage skip every MySQL-only rule.
- Propagation keeps the findings the rule already resolved, through a single `fatalResult` helper. Nine per-event loops each decided this for themselves and each got it wrong; a test that reads the package's own source guards against the tenth.
- The batch's reported retry cause JOINS distinct sentinels instead of first-wins, so a rule that merely waits cannot mask a read failure, and the set-aside record names the real reason a host has a gap.
- The public `Rule.Evaluate` contract documents all three error classes. It previously told authors to finish the batch on the retryable one, which writes the amplification back in for the new class.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/rules/api/types.go`, `server/rules/internal/catalog/`, `server/detection/internal/engine/`
- No migration, no wire change. Behaviour under a healthy dependency is unchanged.
