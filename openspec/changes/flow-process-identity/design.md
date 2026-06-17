# Design notes: flow-to-process identity correlation

## Why a design doc

Three decisions are non-obvious and cut across the Swift extension, the wire format, and the Go server. They are recorded here so the implementation and review have one reference.

## 1. Which audit token, and is `sourceProcessAuditToken` available

The NE reads `sourceAppAuditToken` today: `NEFilterFlow.sourceAppAuditToken` for the socket filter (`NetworkFilter.swift`) and `NEAppProxyFlow.metaData.sourceAppAuditToken` for the DNS proxy (`DNSProxyProvider.swift`). `sourceAppAuditToken` is the audit token of the app *responsible* for the flow, which for a helper process can be the parent app rather than the process that actually opened the socket.

`pidversion` is a field of the audit token, so whatever token we read, the `(pid, pidversion)` pair is internally consistent with the PID we already report: extracting `pidversion` from the same `sourceAppAuditToken` cannot make correlation worse than today, it only makes the existing attribution exact against PID reuse.

The issue asks us to also consider `sourceProcessAuditToken`. Action at implementation time: check the macOS 26 SDK on the build VM for a per-process flow token (`sourceProcessAuditToken` or equivalent on `NEFlowMetaData`). If it exists and resolves a more precise originator than `sourceAppAuditToken`, read it and prefer it, falling back to `sourceAppAuditToken` when nil. If it does not exist as public API, we ship with `sourceAppAuditToken` and record the proxied-originator gap as the documented Apple ask. Either way the wire/server design below is unchanged: the device emits one `(pid, pidversion)` per flow.

The ES/NE agreement that makes the join sound: both ES (`es_process_t.audit_token`) and the NE flow token carry the kernel's `p_idversion` for the same live process, so a process materialized from an ES exec/fork and a flow attributed to that same process share `(pid, pidversion)`.

## 2. Nullable end to end, never a zero sentinel

`audit_token_to_pidversion` returns a `UInt32`. `0` is a legitimate value for some kernel-managed processes, so we cannot use `0` to mean "absent". The field is therefore:

- Swift: an optional, encoded with `encodeIfPresent` (omitted from JSON when the token was unavailable).
- Wire: an optional `pidversion` integer in `schema/events.json`.
- DB: `pidversion INT UNSIGNED NULL` on `processes`.
- Server payload structs: `*uint32` (`PIDVersion *uint32 \`json:"pidversion"\``).

"Absent" routes correlation to the existing time-window path; "present" (including `0`) routes to the exact identity lookup.

## 3. Join precedence and the skew pad

New store method (`server/detection/internal/mysql/processes.go`):

```
GetProcessByPIDVersion(ctx, hostID, pid, pidversion) (*api.Process, error)
```

Exact match on `(host_id, pid, pidversion)`, backed by a new `idx_processes_host_pid_pidversion` index. Returns the single generation or nil.

Correlation call sites (`dns_c2_beacon.go`, `suspicious_exec.go`, and `GetProcessDetail` in `graph/query.go`) resolve the triggering event's process as:

1. If the event payload carries `pidversion`, call `GetProcessByPIDVersion`. On a hit, use it; the forward skew pad (`processLookupSkewPadNs`) is not applied because identity does not drift.
2. On a miss, or when the payload has no `pidversion`, fall back to the existing `lookupProcessSkewTolerant` / `GetProcessByPID(atTimeNs)` window path, unchanged.

This is a pure precision add: every existing event continues to resolve exactly as it does today, and only events that carry the new field gain the exact, reuse-immune, drift-free path. `GetNetworkEventsForProcess` (the within-process dns-to-connect scan) is left on `payload_pid` + ingest window; scoping it further by `pidversion` is unnecessary because it is already constrained to one PID within a 30s window, and the dominant mis-correlation risk is the flow-to-generation lookup, not the intra-process scan.

## Rollout safety

Mixed-version fleets are the normal state during an agent rollout. Because the field is optional and the window path is retained, a v0.2.x agent (no `pidversion`) and a v0.3.0 agent (with `pidversion`) both correlate correctly against the same server. The server requires no flag day; the migration is additive (nullable column + index).
