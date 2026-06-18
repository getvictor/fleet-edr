# Correlate network/DNS flows to processes by audit-token identity: tasks

Sequencing decision: server-first. PR 1 (this branch, `flow-process-identity`) lands the wire field handling, schema, migration, store, builder, correlation precedence, and tests, all dev-DB testable and a no-op for current agents (they emit no pidversion). PR 2 adds the Swift ES + NE emission and the live VM + SigNoz + Chrome verification.

## 1. Wire format

- [x] `schema/events.json`: optional `pidversion` (`integer`, `minimum: 0`) added to `exec`, `fork`, `network_connect`, `dns_query` payloads. Not `required`.

## 2. Server: model, migration, store

- [x] `server/detection/migrations/00004_processes_pidversion.sql`: `ADD COLUMN pidversion INT UNSIGNED NULL` + `CREATE INDEX idx_processes_host_pid_pidversion (host_id, pid, pidversion)`. Forward-only Down.
- [x] `server/detection/api/types.go`: `Process.PIDVersion *uint32` (`db:"pidversion"`, `omitempty`).
- [x] `server/detection/internal/mysql/processes.go`: pidversion threaded through `InsertProcess`, `ReExec` insert, `UpdateProcessExec` (via `COALESCE(?, pidversion)` so a fork-set value is never clobbered to NULL), and all process SELECT column lists. New `GetProcessByPIDVersion(host, pid, pidversion)` exact lookup; `GetProcessByPID` unchanged.
- [x] `server/detection/api/service.go`: `GetProcessByPIDVersion` added to the `GraphReader` interface; test stubs updated.

## 3. Server: graph builder

- [x] `server/detection/internal/graph/builder.go`: `pidversion` parsed from `forkPayload` (child generation) and `execPayload`; stored on fork, exec-without-fork, and re-exec rows. `pickPIDVersion` inherits the prior generation's value on re-exec (execve keeps the kernel generation). NULL preserved for legacy events.

## 4. Server: correlation precedence

- [x] `server/rules/internal/catalog/dns_c2_beacon.go`: `resolveFlowProcess` prefers `GetProcessByPIDVersion` when the `network_connect` carries `pidversion` (no skew pad), else falls back to `lookupProcessSkewTolerant`. Wired into `evalEvent`.
- [x] `server/rules/internal/catalog/suspicious_exec.go`: `pidversion` added to the shared `networkConnectPayload`; the network arm now resolves the connecting process via `resolveFlowProcess` (identity-first) for finding attribution.
- [ ] DEFERRED to a follow-up: the ancestor walk (`findShellWithNonShellAncestor`) still resolves the shell and its parent by bare `ppid` + time window. Making parent edges identity-aware (`ppidversion`) is out of scope (proposal "Not in this change").
- [x] `GetProcessDetail` (`graph/query.go`) intentionally unchanged: its per-process network/DNS scan stays on `payload_pid` + ingest window (the `payload_pidversion` events generated column is explicitly deferred). This is the spec's documented window fallback; the UI does not yet pass `pidversion`.

## 7. Tests (with spectrace markers)

- [x] PBT round-trip for the wire field, present + absent: `networkConnectPayload` (`flow_identity_test.go`), `execPayload` / `forkPayload` (`builder_pidversion_test.go`). Absent key decodes to nil; present 0 preserved.
- [x] Unit test: identity-vs-window precedence in `resolveFlowProcess` (`flow_identity_test.go`), markers on the two correlation scenarios.
- [x] Integration test (real MySQL): `TestGetProcessByPIDVersion` (`processes_pidversion_test.go`) covers PID reuse (distinct pidversion per lifetime), NULL-pidversion non-match + window reachability, no-match nil, and re-exec-chain current-generation selection. Markers on the storage + correlation scenarios.
- [x] `go test ./server/detection/... ./server/rules/...` green; `task lint:go` (custom binary) clean; `openspec validate flow-process-identity --strict` passes.
- [x] PR 2: Swift unit tests (`PIDVersionTests.swift`): `extractProcessInfo` returns pidversion from a token (nil for absent/short), and `ExecPayload`/`ForkPayload` emit `pidversion` when set + omit when nil. `ProcessInfo.swift` moved into the SwiftPM logic target (pure Darwin) with a `bsm` link so `swift test` resolves the audit-token accessors. Full suite: 148 tests pass.

## 8. Docs

- [x] `docs/architecture.md`: network-extension capture, `network_connect` fields, and the `processes` table now note `pidversion` + identity correlation.

## 5. Extension: Endpoint Security (exec/fork): PR 2

- [x] `ESFSubscriber.swift`: `audit_token_to_pidversion(target.audit_token)` on exec, `audit_token_to_pidversion(child)` on fork, threaded into the payloads.
- [x] `EventSerializer.swift`: optional `pidVersion` (CodingKey `pidversion`) on `ExecPayload` (explicit `encodeIfPresent` in its custom encoder) + `ForkPayload` (synthesized encoder auto-omits nil).

## 6. Extension: Network Extension (network_connect/dns_query): PR 2

- [x] `ProcessInfo.swift`: `extractProcessInfo` returns `(pid, uid, pidversion)`; pidversion nil when the token is absent. `sourceProcessAuditToken` investigation RESOLVED (design.md item 1): exists on `NEFilterFlow` only.
- [x] `NetworkFilter.swift`: prefers `sourceProcessAuditToken ?? sourceAppAuditToken` (the flow-creating process); `DNSProxyProvider.swift`: `sourceAppAuditToken` (only token on `NEFlowMetaData`). Both thread pidversion through.
- [x] `NetworkEventSerializer.swift`: optional `pidVersion` (CodingKey `pidversion`, synthesized encoder omits nil) on `NetworkConnectPayload` + `DNSQueryPayload`.

## 9. Manual testing + telemetry verification: PR 2 (needs the emitting extension)

- [ ] Build + deploy the updated extension to `edr-dev`; run real traffic (DNS C2 beacon trigger + ordinary activity).
- [ ] Confirm `pidversion` populated on exec/fork/network_connect/dns_query at the dev server (DB + rows).
- [ ] Force PID reuse; confirm a flow correlates to the correct generation by identity.
- [ ] SigNoz MCP: no new ingest/parse errors; `dns_c2_beacon` still fires end to end.
- [ ] Chrome MCP: host process graph + a DNS C2 beacon alert render with the new field present.

## 10. Archive (after BOTH PRs merge)

- [ ] `openspec archive flow-process-identity` (no `--skip-specs`).
