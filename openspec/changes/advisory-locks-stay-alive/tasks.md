# Tasks

- [x] Extract the keep-alive into a form that reports whether the lock was lost, leaving `RunIfLeader`'s contract unchanged (it already re-acquires).
- [x] Route `DoOnceIfLeader` and `WithLock` through it, mapping a lost lock to `ErrLockLost` without masking the callback's own error.
- [x] Give `Lock` a keep-alive stopped by its release func, and document that it cannot abort its caller.
- [x] Drop the short-critical-section caller-beware notes from the interface docs.
- [x] Distinguish "could not acquire" from "lost mid-batch" in the processor's log, since only the second means work may have been partially done.
- [x] Test against a real killed connection, resolved via `IS_USED_LOCK` so exactly the lock holder dies.
