# ESF events carry the kernel's event time

## Why

`EventSerializer.serialize` stamped every event with `clock_gettime_nsec_np(CLOCK_REALTIME)` at serialization time, so the envelope recorded when the handler finished rather than when the kernel saw the event. For exec that is after the handler's synchronous sha256 and code-signing extraction.

Measured on a dogfood host against in-process ground truth (`time.time_ns()` bracketing `subprocess.Popen`, bounding the true exec inside a 1.25ms window): the recorded `exec_time_ns` was **701ms** after the true exec, and the curl flow event was stamped **689ms before the server's own `exec_time_ns` for that same curl process**.

The server correlates a flow to the process that made it by timestamp, and `GetProcessByPID` brackets on `fork_time_ns <= atTimeNs`. A negative delta means no row, so `suspicious_exec`'s network arm resolved no shell and returned nothing, with no error and no log line. Two runs of the same shape 23 seconds apart differed only in this delta: the one at +11ms alerted, the one at -812ms did not (issue #710).

The failure is load-dependent, which makes it worse than random: handler latency grows exactly when the host is busy, so the rule favours slow interactive chains and misses fast scripted ones. That is backwards for detection.

## What changes

- `serialize` takes the kernel event time and uses it for `timestamp_ns`. Every ESF-derived event passes `es_message_t.time`: exec, fork, exit, open, BTM launch-item add, and both application-control audit events.
- Callers with no kernel message behind them (the application-control resync, the boot-time process snapshot) keep the produced-at clock, which is the honest stamp for a state read rather than a kernel event.
- No wire-format change. The field's type and units are unchanged; what changes is which instant it reports.

The network extension is untouched. It has no kernel-supplied event time to read, and its handler path is short enough that its stamps were already close, which the measurement above shows: the flow stamp was the accurate one and the exec stamp was the late one.

## Impact

- Affected specs: `endpoint-event-collection`
- Affected code: `extension/edr/extension/EventSerializer.swift`, `ESFSubscriber.swift`, `ESFSubscriber+AuthExec.swift`, `ESFSubscriber+BTM.swift`, `FileTamperSubscriber.swift`
- Requires an agent upgrade to take effect. The server-side skew tolerance for hosts still running an older agent is tracked separately.
