# Tasks

- [x] 1.1 Add `ErrRuleReadUnavailable`, wrapping `ErrRetryBatch`, named for the read rather than for a store.
- [x] 1.2 Wrap graph reads with it instead of the bare retry sentinel.
- [x] 2.1 Propagate it from `absorb` rather than absorbing it, without stopping the batch's other rules.
- [x] 2.2 Add `fatalResult` so the findings-preservation policy lives in one place, and route all nine per-event loops through it.
- [x] 2.3 Guard the routing with a test that reads the package's own source, since a hand-written branch reintroduces the bug per rule.
- [x] 3.1 Join distinct retry causes instead of first-wins, so a wait cannot mask a read failure.
- [x] 4.1 Document the three error classes on `Rule.Evaluate`.
- [x] 5.1 Restate the requirement with the four new scenarios, keeping the four it already had.
