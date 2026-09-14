# One ordering for pushed sets: epoch, then version

Issue #1018. The extension receives two kinds of set from the server: an application-control policy snapshot and the watched-path set. Commands reach a host out of order, so the extension keeps the newest set by comparing a `version`, which the server increments, and an `epoch`, the set's update time, which survives a database restore that sends versions backwards.

Both sets were accepted when either value was ahead. That is not a total order, and it left one stated exception: a set already on its way to a host when the database is restored, arriving after a set saved since, is ahead on version and was applied, putting the pre-restore rules back until the next change.

## What changes

- **Sets are ordered by epoch, then version.** A set is applied only when its `(epoch, version)` is ahead of the last one accepted. The pre-restore set in the exception is behind on epoch and is refused. A server that sends no epoch is ordered by version alone, as before. This is how Raft terms and Kafka leader epochs order entries across a leader change: one total order, so a stale entry can never win.
- **The application-control policy epoch is forced forward.** Ordering by epoch first is only safe if the epoch never goes backwards. The watched-path set's update time is already set to `GREATEST(NOW(6), previous + 1µs)`. An application-control policy's was the column's own `ON UPDATE CURRENT_TIMESTAMP(6)`, so a step back in the database clock could give a newer policy an older epoch and have hosts refuse it. Every policy mutation now forces it forward the same way.
- The watched-path requirement in `watched-paths-sensor`, still in flight, states the new rule and drops the exception.

## Out of scope

Coverage across a restart after a mute failure (the other half of #1018) stays as specified: the retained mute targets hold for the running process, and a restarted extension watches the persisted set. The extension logs every failed mute at error level, which is the evidence that would reopen it.
