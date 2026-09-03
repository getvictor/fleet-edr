# Tasks

- [x] Migration: `attempts` and `first_failed_at_ns` on `event_queue`, plus a state-leading index for the retention sweep. INPLACE / LOCK=NONE verified against the pinned engine.
- [x] Name the four `processed` states in a doc block. Not constants: no Go expression reads them, so they would be unused identifiers.
- [x] `Nack` counts the attempt, stamps the first failure, and sets the batch aside once both bounds are exceeded, returning how many.
- [x] `PruneSetAside` ages entries out on the retention window, sharing one batched-delete loop with `PruneProcessed` rather than adding a fourth copy (#818 covers the cross-package case).
- [x] `CountPending` excludes set-aside rows, which are not backlog and would otherwise hold the gauge up permanently.
- [x] `edr.events.set_aside` with a `host_id` attribute, plus an ERROR log naming the host and the failing stage.
- [x] Restate `Stable counter names` identically across all three in-flight changes that touch it (#838's gate).
- [x] Tests: the host resumes, a transient failure is retried, an old failure with few attempts is retried, the entry is retained, the sweep ages entries out from both sides, the claim never offers a set-aside row, and the report fires only when something was set aside.
- [x] Mutation-test both bounds and the claim exclusion. Dropping the attempt bound was initially UNCAUGHT, which is what prompted the old-failure-with-few-attempts test.
- [x] Live QA: migration applied on a dev server, then a set-aside row planted at the head of a host's queue while newer events processed past it.
