# Tasks

- [x] The engine's per-batch call accumulates in memory and performs no database write, behind the same interface it already consumed so nothing in the detection context changes.
- [x] Totals stay exact: sums add, the worst single evaluation takes the larger, and a flush writes what the per-batch writes would have accumulated. Stated as a property test over any sequence of batches, not just a table.
- [x] A failed flush discards that window and reports it, rather than retrying an additive write that is at-least-once. The pending set is keyed by rule id, so it stays bounded by the rule count regardless. Every loss condition is stated once in the requirement; #868 tracks the idempotent write that would remove them.
- [x] A graceful shutdown flushes. The final write gets its own short budget rather than the cancelled context, which would fail it immediately.
- [x] Per-rule evaluation duration is an OTel histogram, with buckets chosen against the measured distribution and a top bucket above the evaluation budget so a rule approaching a skip is visible before it is skipped.
- [x] The instrument name and its rule attribute are pinned against the concrete recorder, since a fake proves only that a method was called.
- [x] Measured before and after with per-call percentiles, and the harness is committed so the claim can be re-checked rather than taken on trust.
- [x] Total per-batch processing time measured, which #837 notes was never established, so the write's cost is stated as a fraction of the batch.
- [x] The wiring is asserted against a real database, because both ways this can be silently undone (the accessor handing out the store again, the flush loop dropped from Run) leave every unit test passing. Mutation-tested: both killed.
- [x] `ADR-0010`'s `per-replica perf cache, safe to lose` annotation carried verbatim.
- [x] The prior doc comment describing the write as synchronous on the drain path corrected, with the new numbers, rather than left to contradict the code.
- [x] Shutdown actually WAITS for the flush. `rulesCtx.Run` was started detached in main and nothing joined it, so the shutdown flush ran on a goroutine the process did not wait for: the guarantee held in tests, which drive Run directly, and not in production. Bounded so a shutdown still ends, and a timeout is logged.
- [x] The histogram measures the same duration the durable table records, INCLUDING graph reads. An earlier cut used the budget's narrower number, which made two surfaces answer one question differently. The budget still excludes that time for its own purpose, and the pair is pinned in one test.
- [x] A failed flush discards that window and the error says how many rules' statistics went with it, since the buffer can no longer be asked afterwards. Retrying an additive write was tried and rejected: it is at-least-once, so it can double a window and move the derived mean, and neither choice is exact once the database is failing.
- [x] The loss conditions are the three that exist and are stated once, in the requirement: a failed flush including the final one, an ungraceful shutdown, and work recorded after the final flush since the evaluation workers are not joined to it. Each is bounded by one window.
- [x] The measurement includes the histogram the change also adds. Measured with a REAL SDK meter, since a bare recorder holds a nil instrument and would have measured nothing while looking fine: 114us per 73-rule batch, 1.56us per rule. The honest per-batch comparison is about 115us after against 1.48ms to 12.98ms before, or about 0.3% of a batch against 4% to 33%.

