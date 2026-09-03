# Tasks

- [x] `retryableGraphReader` decorator: all six `GraphReader` methods, explicit field rather than embedding, compile-time interface assertion, non-nil errors wrapped with `ErrRetryBatch`.
- [x] Engine holds the decorator, built once at construction, and `evaluate` takes the interface rather than the concrete store.
- [x] Correct the "three methods" claim in `server/rules/api/types.go`; the interface has six.
- [x] Tests: each of the six methods wraps a failure; a nil-row-nil-error miss is NOT wrapped; a failing reader makes `Evaluate` return an error rather than swallow it; a rule that fails for a NON-read reason is still isolated.
- [x] Mutation-test the classification: unwrap one method and confirm a test fails; make the decorator embed the interface and confirm the compile-time assertion no longer protects a newly added method.
- [x] `ErrGraphUnavailable` as a distinct sentinel wrapping `ErrRetryBatch`, so a failed read is separable from a deliberate wait in the three places they behave oppositely: `absorb` propagates rather than absorbs, the engine stops the rule loop, and the processor logs at WARN rather than DEBUG. Each with a paired test that the ordinary-wait path is unchanged.
- [x] The set-aside record carries the failure that caused it, not only that a gap exists.
- [ ] QA: drive a read failure against the dev server and confirm the batch is nacked rather than acked, the WARN line appears, and #836's bound sets it aside rather than stalling the host. The first attempt could not reach `dns_c2_beacon`'s archive read with synthetic queue rows; retry now that #836 is on main.
