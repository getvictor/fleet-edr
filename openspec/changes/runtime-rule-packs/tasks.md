# Tasks

## 1. Atomic rule-set swap (this PR)

- [x] `ruleSet` bundles the rules and the three derived indices, immutable once built.
- [x] The engine holds it in an `atomic.Pointer`; `Register` and `LoadActive` build a replacement and swap.
- [x] `Evaluate` loads the snapshot ONCE and uses that view throughout, so dispatch indices and rule indices cannot come from different sets.
- [x] A test that drives `Evaluate` itself: block inside the first rule of set A, swap to set B mid-batch, assert the batch was evaluated against A throughout. Catches the wrong-rule and missed-rule outcomes by asserting the exact invocation list.
- [x] A separate `-race` stress test for the plain memory race only, honest about covering just that half. Reinstating the in-place mutation produces 12 data races there; a mid-batch re-read of the snapshot is caught only by the `Evaluate` test above.

## 2. Carve `rulecontent` and give the corpus storage (this PR)

ADR-0021 assigns the carve to #766: rule content acquires storage here, which is what makes it an aggregate rather than a
projection of the catalog. Scoped to the vendored CORPUS; the per-detection parameter pack stays compiled in, because shipping
parameters without the code that reads them delivers no new detection.

- [x] `rulecontent` context: `api`, `bootstrap`, `internal/mysql`, `migrations`, its own goose tracking table, and an arch-go
      stanza with the narrowest allow-list of any context (it evaluates nothing, so it needs no other context's api).
- [x] Corpus storage: documents keyed by the path the loader reads them under, plus a version counter mirroring
      `detection_config_meta`. Replacement is whole-corpus and atomic, with the version bump in the same transaction.
- [x] `rules` consumes the corpus through `rulecontent/api`, the supplier seam the ADR defines.
- [x] Reuse the existing Sigma loader by presenting stored documents as an `fs.FS`, rather than writing a second parser against a
      document slice. All-or-nothing validation comes with it.
- [x] Idempotent seed from the embedded corpus, guarded on an EMPTY corpus so it can never overwrite authored content.
- [x] Seed only what the loader reads, with one definition of that shared by both. Found in live QA: the vendored directory also
      carries a README and a checksum manifest, and a manifest of hashes beside editable content invites misplaced trust.
- [x] Fall back to the embedded corpus when storage is empty, unreachable, or unloadable, so a storage problem costs the ability
      to change detections rather than the detections themselves.
- [x] Mutation-tested: the seed's empty guard, whole-corpus replacement, and the load order. The first attempt at the guard mutant
      did not compile, so it was redone rather than counted.
- [x] Live QA: first boot seeds 69 documents and loads 66 rules with 3 refused, matching the embedded counts exactly; a second
      boot re-seeds nothing and authored content survives; a malformed document rejects the whole corpus and falls back with the
      offending file named; removing it recovers on the next boot.

## Deferred, with reasons

- Moving the vendored corpus FILES into `rulecontent` (the ADR assigns them there). Mechanical, 55 files, and doing it here would
  bury the carve. Until then cmd/main passes the embedded FS to the seed, so `rulecontent` depends on nothing in `rules`.
- Moving `rules/internal/export` into `rulecontent` (also assigned by the ADR). Unrelated to storage.
- Untrusted-content validation. Belongs with #767, where untrusted input actually arrives; the seeded corpus is vendored.

## 3. Reload and convergence (final PR)

- [ ] `Reload` plus a `RefreshLoop` on the cheap version counter, following `detectionconfig`.
- [ ] A load failure keeps the previous good set.
- [ ] Active version surfaced for operators; two replicas converge, proven by integration test.
