# Tasks

## 1. Bound per-rule evaluation time (this PR)

- [ ] Compare each evaluation's already-measured elapsed time against a budget, in the defer that records it.
- [ ] Skip a rule only after repeated overruns within a window, following #836's twin bounds.
- [ ] The skip is per-replica and in-process, carrying ADR-0010's `per-replica perf cache, safe to lose` annotation verbatim.
- [ ] An overrun records and CONTINUES: no error, so the batch is not nacked and does not retry into the same slow rule.
- [ ] The condition is reported as a counter and a log naming the rule and its measured cost, not as a mode change.
- [ ] Mutation-tested: the budget removed, one bound removed, and the overrun reported as an error instead of recorded.
- [ ] The hot path stays lock-free: clearing a rule's overrun run is gated on a published length, so an under-budget evaluation (the case that always runs) never takes the mutex. Asserted by holding the mutex and requiring `record` to return anyway, rather than by a timing proxy.
- [x] Graph-read time is attributed to the rule that TRIGGERED the read, not the one whose reader performed it. The Sigma adapter memoizes each event's lookups for the whole batch and those closures hold the reader of whichever rule built the memo, so a wait total living on the reader credited the wrong rule and left the waiting one charged in full. The total now rides the context, which is already rebound per rule.
- [x] Mutation-tested by restoring the reader-held design faithfully: the new test fails, and the pre-existing single-rule waiting test does NOT, which is the evidence that the bug was reachable and untested rather than hypothetical.

