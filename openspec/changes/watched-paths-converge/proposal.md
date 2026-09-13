# Hosts that miss the watched-path push get the set

Issue #998 (ADR-0008 step 4). The server pushes a changed watched-path set to every host enrolled at the moment of the change. That misses three hosts: one that enrolls afterwards and was never sent it, one that stays offline past a command's one-hour delivery window so its copy ages out, and one that reinstalls, which removes the extension's persisted set while its command history still shows the set delivered.

## What changes

- **A catch-up every five minutes.** For each host with an active enrollment, the server looks at that host's latest `set_watched_paths` command and queues the current set again when there is none, when it carried an older version, when it was queued before the host last enrolled, when it expired or was cancelled, or when it failed more than six hours ago. It sends the same payload as the push, epoch included, so the extension orders it exactly as it would the original.
- **No churn for offline or old hosts.** A pending command counts as on its way: an offline host keeps it until it reconnects, when the control stream delivers it or a poll ages it out and the next sweep queues a fresh copy. A failure, usually an agent that predates the command, is retried every six hours rather than every sweep, which still reaches a host whose agent was upgraded.
- **Nothing while the set was never changed.** Version 0 is the empty set every host already watches.
- **Not leader-gated.** Replicas sweeping at once can queue the set twice for one host; the extension turns the second copy away as not newer. That costs a duplicate command row, where a leader lock would hold a pooled connection for the life of the process (#722).
- The response context gains `LatestOfType`, the latest command of a type per host; the rules context reads it, and the endpoint context's enrollment list, through closures cmd/main wires.

## Out of scope

- The console editor for the set.
- Ordering questions tracked in #1018.
