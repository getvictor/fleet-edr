# Tasks

## 1. Atomic rule-set swap (this PR)

- [x] `ruleSet` bundles the rules and the three derived indices, immutable once built.
- [x] The engine holds it in an `atomic.Pointer`; `Register` and `LoadActive` build a replacement and swap.
- [x] `Evaluate` loads the snapshot ONCE and uses that view throughout, so dispatch indices and rule indices cannot come from different sets.
- [x] Concurrency test under `-race`: swap repeatedly while evaluating, asserting no torn view and no missed rule. Reinstating the in-place mutation produces 12 data races; the new implementation is clean.

## 2. Pack storage (next PR)

- [ ] Migration for pack documents plus a version counter, mirroring `detection_config_meta`.
- [ ] Whole-pack parse and validate, all-or-nothing, reusing the catalog machinery.
- [ ] Idempotent seed from the embedded corpus on first boot, so behaviour is identical to today.

## 3. Reload and convergence (final PR)

- [ ] `Reload` plus a `RefreshLoop` on the cheap version counter, following `detectionconfig`.
- [ ] A load failure keeps the previous good set.
- [ ] Active version surfaced for operators; two replicas converge, proven by integration test.
