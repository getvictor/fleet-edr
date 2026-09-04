# Tasks

## 1. Bound per-rule evaluation time (this PR)

- [ ] Compare each evaluation's already-measured elapsed time against a budget, in the defer that records it.
- [ ] Skip a rule only after repeated overruns within a window, following #836's twin bounds.
- [ ] The skip is per-replica and in-process, annotated as an ADR-0010 cache that is safe to lose.
- [ ] An overrun records and CONTINUES: no error, so the batch is not nacked and does not retry into the same slow rule.
- [ ] The condition is reported as a counter and a log naming the rule and its measured cost, not as a mode change.
- [ ] Mutation-tested: the budget removed, one bound removed, and the overrun reported as an error instead of recorded.
