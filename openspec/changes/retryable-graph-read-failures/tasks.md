# Tasks

- [ ] `retryableGraphReader` decorator: all six `GraphReader` methods, explicit field rather than embedding, compile-time interface assertion, non-nil errors wrapped with `ErrRetryBatch`.
- [ ] Engine holds the decorator, built once at construction, and `evaluate` takes the interface rather than the concrete store.
- [ ] Correct the "three methods" claim in `server/rules/api/types.go`; the interface has six.
- [ ] Tests: each of the six methods wraps a failure; a nil-row-nil-error miss is NOT wrapped; a failing reader makes `Evaluate` return an error rather than swallow it; a rule that fails for a NON-read reason is still isolated.
- [ ] Mutation-test the classification: unwrap one method and confirm a test fails; make the decorator embed the interface and confirm the compile-time assertion no longer protects a newly added method.
- [ ] QA: drive a read failure against the dev server and confirm the batch is nacked rather than acked, and that #836's bound sets it aside rather than stalling the host indefinitely.
