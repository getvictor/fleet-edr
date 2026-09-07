# Keep advisory locks alive for as long as they are held

## Why

`RunIfLeader` pings its lock connection so MySQL cannot close it as idle. The one-shot and scoped forms, `DoOnceIfLeader`, `WithLock` and `Lock`, did not, and their doc comments passed the hazard to callers as a constraint: keep the critical section short, because the lock connection sits idle while your work runs on a different pooled connection, and an idle-timeout close silently frees the lock (issue #721).

Two things make that worth fixing rather than documenting.

The safety of the arrangement rested on a MySQL server variable no code asserts. `wait_timeout` defaults to 28800s against critical sections measured in milliseconds, which is a margin of roughly six orders of magnitude, but tuning it down is a normal thing for an operator to do and nothing in the product would notice. `wait_timeout` is also not the only way that connection dies: a proxy idle timeout, a failover, or an operator `KILL` produces the same result.

And the failure is invisible. The callback keeps running on its own connection, finishes, and reports success, having lost its exclusivity partway through. For the per-host claim that means two claimers folding one host's stream concurrently, which is the exact corruption the lock was added to prevent.

## What changes

The one-shot and scoped acquire paths get the same keep-alive `RunIfLeader` already had, so no caller has to reason about `wait_timeout` again, and the caller-beware notes come out of the doc comments.

Losing the lock is now reported rather than absorbed. `DoOnceIfLeader` and `WithLock` cancel the callback's context and return a new `ErrLockLost` when the lock went while the callback ran, so a caller that ignores cancellation and returns nil cannot be mistaken for one that held the lock throughout. A callback's own error still wins, because it is the more specific diagnosis.

`Lock`, the bare release-func form, gets the keep-alive but cannot abort its caller: there is no callback context to cancel. That asymmetry is now stated in its doc comment, with a pointer to prefer `WithLock` where the section fits in a closure.

## Notes

Reading `wait_timeout` at boot, which the issue also suggested, is not included. Once the connection is pinged every keep-alive interval the server's value stops being load-bearing, so a derived warning would report on a hazard that no longer exists.
