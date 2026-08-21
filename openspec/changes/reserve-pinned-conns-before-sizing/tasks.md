# Tasks

- [x] Add `ProcessorOptions.ReservedConns` and subtract it before both the refusal check and the affordability calculation.
- [x] Make the refusal threshold and its error message quote the same number, reservation included.
- [x] Drop the `max(..., 1)` floor, now that the refusal guarantees one affordable worker.
- [x] Export `pipeline.LeaderGatedLoops` next to the lock names, and pin it to that list with a test.
- [x] Set the reservation from the detection bootstrap, which is what wires the loops, and only when a coordinator gates them.
- [x] Cover: budgets of 2 and 3 refused rather than clamped, a pool consumed by the leader loops refused, reserved connections excluded from sizing, and the shipped default unchanged.
