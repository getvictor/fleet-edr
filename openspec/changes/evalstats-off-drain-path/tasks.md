# Tasks

- [x] The engine's per-batch call accumulates in memory and performs no database write, behind the same interface it already consumed so nothing in the detection context changes.
- [x] Totals stay exact: sums add, the worst single evaluation takes the larger, and a flush writes what the per-batch writes would have accumulated. Stated as a property test over any sequence of batches, not just a table.
- [x] A failed flush returns its counts and the next one retries them, so only an ungraceful shutdown loses anything. The pending set is keyed by rule id, so a database that stays down cannot grow it.
- [x] A graceful shutdown flushes. The final write gets its own short budget rather than the cancelled context, which would fail it immediately.
- [x] Per-rule evaluation duration is an OTel histogram, with buckets chosen against the measured distribution and a top bucket above the evaluation budget so a rule approaching a skip is visible before it is skipped.
- [x] The instrument name and its rule attribute are pinned against the concrete recorder, since a fake proves only that a method was called.
- [x] Measured before and after with per-call percentiles, and the harness is committed so the claim can be re-checked rather than taken on trust.
- [x] Total per-batch processing time measured, which #837 notes was never established, so the write's cost is stated as a fraction of the batch.
- [x] The wiring is asserted against a real database, because both ways this can be silently undone (the accessor handing out the store again, the flush loop dropped from Run) leave every unit test passing. Mutation-tested: both killed.
- [x] `ADR-0010`'s `per-replica perf cache, safe to lose` annotation carried verbatim.
- [x] The prior doc comment describing the write as synchronous on the drain path corrected, with the new numbers, rather than left to contradict the code.
