## Why

Host identity (hostname, OS version, agent version) is captured at enrollment and refreshed only when a 401 forces a re-enroll, so a macOS upgrade, a hostname rename, or an agent upgrade on a healthy host is never reflected in the console, possibly for the host's whole life. The agent's status check-in (#572) already posts a host-token-authed, additive snapshot every 60 seconds and even carries `agent_version` on the wire, but the server drops it. This change makes the host record a living document by carrying inventory on that existing channel (issue #579, epic #577; absorbs the design of the former #437).

## What Changes

- The status check-in payload (`POST /api/status`) gains an optional `inventory` object: `hostname`, `os_name`, `os_version`, `os_build`, `agent_version`. Older agents that omit it are unaffected.
- The agent collects inventory (hostname from the kernel, OS fields from `SystemVersion.plist`, its own build version) and includes it in every status post, so inventory refreshes on startup, on every health transition, and at the periodic 60-second floor.
- The server persists inventory from the check-in into the host's enrollment row, which gains `os_name` and `os_build` columns; the enrollment row becomes "latest known identity", not "identity at enroll time". Reports carrying no inventory leave the row untouched.
- The agent's enrollment request now also sends the friendly OS fields (it currently reports `runtime.GOOS`, the literal string `darwin`, as `os_version`).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `agent-status-reporting`: the status report additionally carries host inventory (new requirement, ADDED; the capability is declared by the in-flight `agent-health-reporting` change).
- `server-host-status`: the server persists inventory from an accepted status report into the host's identity record (new requirement, ADDED; same in-flight capability).

## Impact

- `server/endpoint/api/status.go`: `Inventory` struct on `StatusReport` (PBT round-trip per repo policy).
- `server/endpoint/internal/service/service.go` (`RecordStatus`), `server/endpoint/internal/mysql/store.go`, new migration adding `os_name`/`os_build` to `enrollments`.
- `agent/health/` (report struct + poster payload), `agent/hostinfo` or equivalent collector, `agent/cmd/fleet-edr-agent/main.go` wiring, enrollment request fields.
- No UI change in this PR (the host detail header consuming this data is the follow-up PR of #579).

Rollback: revert the agent change and the server ignores nothing new (inventory is optional); revert the server change and agents' inventory field is decoded and dropped exactly as `agent_version` is today. The migration is additive columns with defaults, safe to leave in place.
