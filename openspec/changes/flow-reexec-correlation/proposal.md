# Select the re-exec generation by event time within a matching pidversion

## Why

Issue #403 made flow-to-process correlation join on `(host_id, pid, pidversion)`, which correctly disambiguates PID reuse: distinct fork lifetimes get distinct kernel PID generations. But `execve` keeps the same `proc`, so a same-PID re-exec chain (`bash` to `sh` to `curl` to `cleanup`) shares one `pidversion` across every generation. Verified on a live host: 15074/15074 re-exec links share their predecessor's `pidversion`.

`GetProcessByPIDVersion` returns a single row with `ORDER BY (exit_time_ns IS NULL) DESC, id DESC` (live, else newest) and `resolveFlowProcess` ignores the event timestamp on that path. So a flow opened by an earlier generation (`curl`) that then re-execs into another image (`cleanup`) is mis-attributed to the live/newest generation. That is a forensic-attribution regression versus the pre-#403 window path. Two PR #428 reviewers (Gemini, Qodo) independently flagged it.

## What changes

- **Select by event time within the identity set.** `GetProcessByPIDVersion` gains an `atNs` anchor. When the `(host_id, pid, pidversion)` identity matches exactly one generation it is returned regardless of the timestamp (PID reuse stays skew-immune). When it matches more than one generation (a re-exec chain), the lookup selects the generation that was the running image at `atNs`, bracketing on `COALESCE(exec_time_ns, fork_time_ns) <= atNs` and `(exit_time_ns IS NULL OR atNs <= exit_time_ns)` (an inclusive upper bound, matching `GetProcessByPID`). Re-exec generations share `fork_time_ns` (the chain preserves the original fork time) but carry distinct `exec_time_ns`, so the exec time is the boundary that orders them; at the exact re-exec instant the newer generation wins because its `exec_time_ns` equals that instant and the `COALESCE` tiebreak prefers it. The link never crosses a `pidversion` boundary on timestamp proximity.
- **Caller passes the anchor.** `resolveFlowProcess` forwards the flow's `atNs` to the identity lookup. The no-pidversion and identity-miss paths fall back to the existing `GetProcessByPID` time window unchanged.
- **Spec.** The "Network and DNS events are linked to the process at event time" requirement is updated to state the within-identity timestamp selection, with a new scenario for the re-exec chain.
- **Tests.** The real-MySQL `GetProcessByPIDVersion` test gains a re-exec chain where a flow during the earlier generation links to that generation, not the live one, plus a check that a single-match (reuse) lookup stays timestamp-independent.

### Not in this change

- **The no-pidversion fallback (`GetProcessByPID`).** It brackets on `fork_time_ns`, which re-exec generations share, so it is also ambiguous for re-exec chains. That path serves legacy/token-less flows only and is left as-is; widening it is a separate change.
- **Parent-edge identity (`ppidversion`).** Still out of scope, as in #403.

## Resolved decisions

1. **Single identity match stays timestamp-independent.** With one matching generation the row is returned even if `atNs` falls outside its window, preserving the #403 PID-reuse guarantee that identity beats clock skew. The timestamp only disambiguates when the identity set has more than one member.
2. **Bracket on `exec_time_ns`, not `fork_time_ns`.** A re-exec chain preserves the original `fork_time_ns` on every generation, so `fork_time_ns` cannot order them; `exec_time_ns` (the image-replacement instant) is the running-image boundary. `COALESCE(exec_time_ns, fork_time_ns)` handles a pre-exec (pure fork) generation that has no exec time yet.
