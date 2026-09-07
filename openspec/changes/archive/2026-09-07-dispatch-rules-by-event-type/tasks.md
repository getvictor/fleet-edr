# Tasks

- [x] Engine indexes rules by the event types they declare
- [x] A rule is invoked only for batches carrying a type it consumes, and receives the whole batch
- [x] A rule declaring no event types is invoked unconditionally
- [x] Platform and index checks run before the per-rule span
- [x] Catalog guard: every shipped rule declares at least one real event type
- [x] Catalog guard: no rule finds anything in a batch made only of types it does not declare
- [x] Benchmark across catalog sizes, before and after
- [ ] Derive event types for imported rules from their logsource category (#763)
