# Correlate network/DNS flows to processes by audit-token identity (pid + pidversion)

## Why

The on-device network extension reduces a stable kernel process identity to a bare PID, and the server then re-correlates `network_connect` / `dns_query` flows back to a process by a time window. Both halves throw away an identity the platform already hands us on both event streams.

Concretely, today:

- `extension/edr/networkextension/ProcessInfo.swift` extracts only `pid` + `euid` from the flow's `sourceAppAuditToken` (`audit_token_to_pid` / `audit_token_to_euid`). The `pidversion` field of the same audit token is discarded.
- The ES side already reads `target.audit_token` in `extension/edr/extension/ESFSubscriber.swift` for exec/fork, but likewise takes only `pid` via `audit_token_to_pid`; `pidversion` is dropped.
- Server-side, `server/detection/internal/mysql/processes.go` resolves a flow to a process generation with `GetProcessByPID(host, pid, atTimeNs)`, which brackets `fork_time_ns <= atTimeNs <= exit_time_ns` and picks the latest fork. The detection rules add forward skew padding (`dns_c2_beacon.go` `processLookupSkewPadNs = 5s`, `ingestLookupPadNs = 10s`) purely to absorb ES/NE clock drift (issue #7).

Two problems follow directly:

- **PID reuse can mis-correlate a flow to the wrong process generation.** The kernel recycles PIDs; the field that disambiguates a recycled PID is exactly the `pidversion` we drop. A flow that lands near a fork/exit boundary can bracket to the neighbouring generation.
- **The clock-drift padding exists only because we join on a window instead of on identity.** A stable shared identity already exists on both sides: ES `es_process_t.audit_token` and the NE flow's `sourceAppAuditToken`, both carrying the same kernel `pidversion` for a given live process. Carrying `(pid, pidversion)` through the wire turns the join into an exact lookup with no time window.

These are self-inflicted: the platform gives us the identity on both ES and NE; we just are not carrying it through. Fixing it also earns the standing to raise the residual proxied-flow gap with Apple credibly, which is out of scope here (see below).

## What changes

- **Capture `pidversion` on the device, on both event sources.** The ES exec/fork handlers add `audit_token_to_pidversion(target.audit_token)` (and the child token for fork) alongside the existing PID extraction. The NE `extractProcessInfo` returns `pidversion` from the flow's audit token, and the `network_connect` / `dns_query` serializers include it.
- **Carry `pidversion` through the wire format.** `schema/events.json` gains an optional `pidversion` (unsigned integer) on the `exec`, `fork`, `network_connect`, and `dns_query` payloads. The field is optional so an older agent that does not send it still ingests cleanly.
- **Store `pidversion` on the process record.** A migration adds a nullable `pidversion INT UNSIGNED` column to `processes` plus a `(host_id, pid, pidversion)` index. The graph builder reads `pidversion` from `exec`/`fork` payloads and stores it on the generation it creates or updates.
- **Join flows to processes on identity, with a time-window fallback.** A new store lookup resolves a process by exact `(host_id, pid, pidversion)`. When the triggering `network_connect` / `dns_query` event carries a `pidversion` and a matching process generation exists, correlation uses the exact identity and drops the forward skew pad. When either side lacks `pidversion` (older agent, or a flow whose audit token was unavailable), correlation falls back to the existing `GetProcessByPID` time-window path unchanged. This keeps mixed-version fleets correct during rollout.
- **Tests.** A property-based round-trip for the new wire field; a unit test pinning the identity-vs-window lookup precedence; an integration test that materializes two process generations on the same PID with distinct `pidversion`s and asserts a flow tagged with one `pidversion` correlates to the correct generation (and that a flow with no `pidversion` still resolves by window).

### Not in this change

- **Proxied / delegated flows where `sourceAppAuditToken` names the delegating daemon (`nehelper` / `nesessionmanager` / a system proxy) or is `nil`.** Those carry no usable originator identity and remain a future Apple ask, which the issue explicitly defers. This change is a prerequisite for raising it.
- **`sourceProcessAuditToken` as a distinct originator.** Whether the macOS 26 SDK exposes a per-process flow token that is more precise than `sourceAppAuditToken` is an implementation-time investigation (see design.md). If it is available and more precise we prefer it; if not, `sourceAppAuditToken` is the identity we carry and behaviour is unchanged from today apart from being exact on `(pid, pidversion)`.
- **Parent-edge identity (`ppidversion`).** The process forest still links parent to child on bare `ppid`. Making parent edges exact on `pidversion` is a separate graph-builder change; this issue is scoped to flow-to-process correlation.
- **Removing the `ingested_at_ns` clock-drift columns or the within-process dns-to-connect temporal window.** The identity join removes the need for the forward *process-lookup* pad; the within-process correlation in `dns_c2_beacon` (a `dns_query` preceding a `network_connect` for the same process within 30s) stays a temporal relationship and is unchanged.

## Resolved decisions

1. **Optional, additive wire field rather than a breaking change.** `pidversion` is nullable end to end (payload omitted, DB column NULL). A present value of `0` is a valid identity; absence is "no identity, use the window". This is why the column and payload field are nullable rather than zero-sentinel, and why mixed-version fleets keep working through rollout.
2. **Identity is preferred, window is the fallback, never the reverse.** When both sides carry `pidversion` the exact lookup wins and the skew pad is not applied. The window path is retained verbatim for events that lack `pidversion`, so this change adds precision without removing the existing correctness guarantee for legacy events.
