# Tasks

- [x] `retryableGraphReader` decorator: all six `GraphReader` methods, explicit field rather than embedding, compile-time interface assertion, non-nil errors wrapped with `ErrRetryBatch`.
- [x] Engine holds the decorator, built once at construction, and `evaluate` takes the interface rather than the concrete store.
- [x] Correct the "three methods" claim in `server/rules/api/types.go`; the interface has six.
- [x] Tests: each of the six methods wraps a failure; a nil-row-nil-error miss is NOT wrapped; a failing reader makes `Evaluate` return an error rather than swallow it; a rule that fails for a NON-read reason is still isolated.
- [x] Mutation-test the classification: unwrap one method and confirm a test fails; make the decorator embed the interface and confirm the compile-time assertion no longer protects a newly added method.
- [x] `ErrRuleReadUnavailable` as a distinct sentinel wrapping `ErrRetryBatch`, so a failed read is separable from a deliberate wait where they diverge: `absorb` propagates rather than absorbs. Named for the read, not for a store, since the reads span MySQL and the ClickHouse archive.
- [x] Propagation keeps the findings earlier events already resolved, per `evalEachEvent`'s contract; a non-retryable failure still discards them. The policy lives in one `fatalResult` and all NINE per-event loops return through it, since fixing only the shared helper left the eight hand-rolled loops discarding. Guarded by a source-level test so a tenth loop cannot regress it.
- [x] Do NOT stop the batch's other rules, and do NOT report per attempt. Both were first-cut over-corrections: the reads span two independent dependencies, and a per-attempt line is a continuous stream at the processing cadence. Surfaced by consequence via the set-aside record instead.
- [x] The set-aside record carries the failure that caused it, not only that a gap exists.
- [ ] QA: drive a read failure against the dev server and confirm the batch is nacked rather than acked, and that #836's bound then sets it aside with the cause named in that record. Not the per-attempt log, which is deliberately quiet. The first attempt could not reach `dns_c2_beacon`'s archive read with synthetic queue rows; retry now that #836 is on main.
