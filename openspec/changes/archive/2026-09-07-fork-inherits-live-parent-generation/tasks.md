# Tasks

## 1. Bound the inherited-path lookup by the child's fork time

- [x] 1.1 Give `GetParentPath` the instant to resolve at, and add `fork_time_ns <= ?` so a generation that forked after the child can never be its parent.
- [x] 1.2 Replace the store doc comment, which claimed an aliveness filter the query never had, with what the fork bound is for and why no aliveness test joins it.
- [x] 1.3 Apply the same bound in the batch overlay.
- [x] 1.4 Pass the fork event's own timestamp from `handleFork`.
- [x] 1.5 Re-state why the bulk preload still loads exited rows: every overlay read is bounded by the reading event's timestamp, not by now.

## 2. Keep the two pid-plus-instant lookups deliberately different

- [x] 2.1 Measure the aliveness variant before choosing: 21,084 corrected and 5 blanked with the fork bound alone, against 17,671 and 29,880 with aliveness added.
- [x] 2.2 Do NOT share a predicate between the overlay's `GetProcessByPID` and `GetParentPath`. They differ because only the fork instant carries a guarantee that the target was alive.
- [x] 2.3 Record that reason at both call sites and in the store docstring, with the numbers, so the apparent inconsistency is not "fixed" back into the regression.

## 3. Pin the behavior

- [x] 3.1 Reproduce issue #714: a fork materialized after its parent's PID was recycled inherits the generation that had forked by then, not the recycling one.
- [x] 3.2 Cover the same case where the prior generation was closed by the PID-reuse sweep rather than by an observed exit.
- [x] 3.3 Cover a parent with no observed exit.
- [x] 3.4 Pin the absence of an aliveness test: a parent recorded as exited long before the child forked MUST still supply the path. This case fails under the rejected variant, which is the point of it.
- [x] 3.5 Cover the one give-up case: no generation of the parent PID had forked yet yields an empty path.
- [x] 3.6 Assert the store predicate and the overlay agree, over one seeded PID history read at each boundary instant of its generations. The existing differential test cannot catch a divergence here, because both of its arms drive the overlay.
