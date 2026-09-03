# Tasks

- [x] Migration: `attempts`, `first_failed_at_ns` and `set_aside_at_ns` on `event_queue`, plus a state-leading index for the retention sweep. INPLACE / LOCK=NONE verified against the pinned engine.
- [x] Name the four `processed` states in a doc block. Not constants: no Go expression reads them, so they would be unused identifiers.
- [x] `Nack` counts the attempt, stamps the first failure, and sets the batch aside once both bounds are exceeded, returning how many.
- [x] `PruneSetAside` ages entries out on the retention window, measured from WITHDRAWAL rather than first failure, sharing one batched-delete loop with `PruneProcessed` rather than adding a fourth copy (#818 covers the cross-package case).
- [x] `CountPending` excludes set-aside rows, which are not backlog and would otherwise hold the gauge up permanently.
- [x] `edr.events.set_aside` with a `host_id` attribute, plus an ERROR log naming the host and the failing stage.
- [x] Restate `Stable counter names` identically across all three in-flight changes that touch it (#838's gate).
- [x] Tests: the host resumes, a transient failure is retried, an old failure with few attempts is retried, the entry is retained, the sweep ages entries out from both sides, the claim never offers a set-aside row, and the report fires only when something was set aside.
- [x] Mutation-test both bounds, the claim exclusion, the retention clock, the counter name and its attribute. Two mutants were initially UNCAUGHT: dropping the attempt bound (which prompted the old-failure-with-few-attempts test) and dropping the withdrawal stamp entirely (which prompted an end-to-end assertion joining `Nack` to the sweep, since the two were tested apart and the sweep test planted its own stamps).
- [x] Record the stale-lease claim-ownership window in `Nack`'s doc comment and track it as #840, rather than leaving the code reading as though it were closed.
- [x] Live QA: migration applied on a dev server, then a set-aside row planted at the head of a host's queue while newer events processed past it.
