# Tasks

## 1. Atomic rule-set swap (this PR)

- [x] `ruleSet` bundles the rules and the three derived indices, immutable once built.
- [x] The engine holds it in an `atomic.Pointer`; `Register` and `LoadActive` build a replacement and swap.
- [x] `Evaluate` loads the snapshot ONCE and uses that view throughout, so dispatch indices and rule indices cannot come from different sets.
- [x] A test that drives `Evaluate` itself: block inside the first rule of set A, swap to set B mid-batch, assert the batch was evaluated against A throughout. Catches the wrong-rule and missed-rule outcomes by asserting the exact invocation list.
- [x] A separate `-race` stress test for the plain memory race only, honest about covering just that half. Reinstating the in-place mutation produces 12 data races there; a mid-batch re-read of the snapshot is caught only by the `Evaluate` test above.

## 2. Pack storage (next PR)

- [ ] Migration for pack documents plus a version counter, mirroring `detection_config_meta`.
- [ ] Whole-pack parse and validate, all-or-nothing, reusing the catalog machinery.
- [ ] Idempotent seed from the embedded corpus on first boot, so behaviour is identical to today.

## 3. Reload and convergence (final PR)

- [ ] `Reload` plus a `RefreshLoop` on the cheap version counter, following `detectionconfig`.
- [ ] A load failure keeps the previous good set.
- [ ] Active version surfaced for operators; two replicas converge, proven by integration test.
