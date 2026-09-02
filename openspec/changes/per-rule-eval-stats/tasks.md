# Tasks

- [x] Add the `detection_rule_eval_stats` migration, keyed (rule_id, day), with a day-leading index for the prune sweep.
- [x] Add the api types and the recorder interface in the rules context, mirroring `MonitorMatchRecorder`'s narrow write surface.
- [x] Accumulate per-rule attempts, duration and retryable misses in the engine, counted from the point the span opens so the durable figures and the trace agree on what "this rule ran" means.
- [x] Record from a defer on every exit path, including the nack, since a batch ending in a retryable outcome is never acknowledged.
- [x] Implement the store: folded multi-row upsert with a MAX on the worst case, windowed read computing the mean in SQL, and a batched retention prune.
- [x] Extend the existing counter sweep to prune both tables rather than adding a second ticker.
- [x] Wire the recorder through both bootstraps, main, and the cross-context integration stack.
- [x] Tests: durability through a second store, every attempt counted including the nacked one, a rule left with nothing in scope not counted, a write failure not failing the batch, the fold's drops and its max, and the prune boundary from both sides.
- [x] Mutation-test each guard (five mutants, all compiling and all caught).
- [ ] Read the statistics over HTTP and render them in the detection-config UI. Deliberately the NEXT change, so this one stays reviewable.
