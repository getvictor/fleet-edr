# Rules tolerate a process stamped after an event that followed it

## Why

Consumer half of issue #710. The producer half stamps ESF events with the kernel's event time, which removes the cause, but it only helps a host once its agent is upgraded, and some handler latency always remains.

Measured on a dogfood host: a process's recorded `exec_time_ns` ran 701ms behind the true exec, and the flow event for the process it spawned landed 689ms BEFORE that recorded exec. `suspicious_exec`'s network arm then resolved no shell and returned nothing, silently.

Two independent things dropped the finding, and both had to give. Neither alone is sufficient, which the tests pin by mutation:

1. The ancestor lookups bracket on `fork_time_ns <= atTimeNs`, so a late-stamped shell resolved to no row at all.
2. `shellWithinWindow`'s lower bound requires the trigger to follow the shell, which a late stamp inverts.

## What changes

- The network arm walks from the connecting process the caller already resolved, instead of resolving that PID again at the raw event timestamp. For a flow carrying a pidversion that start is an exact identity match rather than a time-window guess, and it removes a duplicate lookup.
- Ancestor lookups reuse the existing exact-first, then-padded helper, so a recycled PID still resolves to the right generation and only a missed lookup is widened.
- The shell window's LOWER bound is padded. The upper bound is untouched: that direction is a real limit, not skew.
- The shared pad is renamed to `agentStampSkewPadNs` and its rationale corrected. It has claimed since issue #7 that the network extension and Endpoint Security carry different clocks which drift. They do not: both sample `CLOCK_REALTIME` on one host. The cause is handler latency, which matters because it means the error grows with host load rather than wandering randomly. The same wrong explanation had been copied into `graph/query.go`, and is corrected there too.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/rules/internal/catalog/suspicious_exec.go`, `dns_c2_beacon.go`, `server/detection/internal/graph/query.go` (comment only)
- Helps every host immediately, including those still running an agent that stamps at handler time.
