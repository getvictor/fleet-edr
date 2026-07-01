## 1. Wire format

- [ ] 1.1 Define `StatusReport` (agent version, reported-at, `[]ComponentHealth`) and `ComponentHealth` (`type`, `status`, `reason`, `message`, `last_transition_ns`) in `server/endpoint/api/types.go` with JSON tags; `status` documented as the closed set `healthy|degraded|unhealthy|unknown`
- [ ] 1.2 PBT round-trip (`Marshal ∘ Unmarshal == identity`) with `pgregory.net/rapid`, plus an example-based wire pin of the endpoint-security + network-extension snapshot shape
- [ ] 1.3 `Scan ∘ Value == identity` for the JSON `components` column type

## 2. Server persistence and check-in (endpoint context)

- [ ] 2.1 Migration `server/endpoint/migrations/00005_host_health.sql` (`+goose Up`/`Down`): `host_health` (host_id PK, overall_status VARCHAR(16), components JSON, reported_at_ns BIGINT, updated_at TIMESTAMP), index on `overall_status`; Down drops the table
- [ ] 2.2 Store: last-writer-wins upsert keyed on `host_id`; read latest snapshot for one host; read overall status for the host list
- [ ] 2.3 Service: validate `status` against the closed set at the boundary (reject unknown status, accept unknown `type`/`reason`); compute the worst-of rollup (`unhealthy` > `degraded` > `healthy`; empty -> `unknown`)
- [ ] 2.4 Handler `POST /api/status` behind the host-token middleware (`server/endpoint/internal/middleware/hosttoken.go`); optionally bump `last_seen_ns` as a liveness side effect without removing the command-poll heartbeat
- [ ] 2.5 Table-driven + integration tests (real MySQL via `testdb/full.Open`): upsert replaces prior, unknown type stored verbatim, invalid status rejected, unauthenticated rejected, rollup matrix

## 3. Host API surface

- [ ] 3.1 Add `OverallStatus` to `HostSummary` (`server/detection/api/types.go`) and a `LEFT JOIN host_health` with `COALESCE(overall_status,'unknown')` in `ListHosts` (`server/detection/internal/mysql/hosts.go`), mirroring the existing enrollments join
- [ ] 3.2 Add the full component list to the single-host detail response
- [ ] 3.3 Integration test: post a snapshot, then the host list carries `overall_status` and the detail carries the components; a host with no snapshot lists as `unknown`

## 4. Agent health registry

- [ ] 4.1 `agent/health/`: concurrency-safe registry mapping component type to condition; `Set(type, status, reason, message)` stamps `last_transition_ns` only on a real status change
- [ ] 4.2 Track per extension whether a session has ever been established, to distinguish `never_connected` from `connection_lost`
- [ ] 4.3 Wire the ESF and network-extension receiver loops into the registry via the existing connect/disconnect paths and `OnConnected`/`OnDisconnected` hooks (`agent/receiver/loop.go`)
- [ ] 4.4 Unit tests: connected -> healthy/activated; never-connected before first session; connection-lost after a drop; transition-timestamp stability

## 5. Agent status poster

- [ ] 5.1 `agent/status/`: build a `StatusReport` from the registry and POST it to `POST /api/status` with the host token, reusing the enrollment HTTP client
- [ ] 5.2 Cadence: post on startup, on transition (debounced ~2s), and on a ~60s periodic floor; clean ctx-cancel shutdown following the `RunRefresh` loop shape
- [ ] 5.3 Wire the poster into `agent/cmd/fleet-edr-agent/main.go`
- [ ] 5.4 Unit tests: startup post, transition-triggered post, debounce collapses a retry burst

## 6. UI

- [ ] 6.1 `ui/src/types.ts`: extend `HostSummary` with `overall_status`; add `ComponentHealth` and the host-detail health shape
- [ ] 6.2 `ui/src/components/HostList.tsx`: health badge column driven by `overall_status`, reusing `Badge`, distinct from the online/offline pill; neutral badge for `unknown`
- [ ] 6.3 Host detail conditions panel (in `ProcessTree.tsx` header or a small new component): per-component status badge, message, and "since" relative time from `last_transition_ns`
- [ ] 6.4 vitest siblings (`*.test.tsx`) covering the badge-variant mapping, the unknown/empty states, and the conditions panel

## 7. Spec and QA

- [ ] 7.1 Add spectrace markers from the new tests to the scenario IDs in the three delta specs
- [ ] 7.2 `openspec validate agent-health-reporting --strict`; prose + dash + markdown lints
- [ ] 7.3 Live QA on edr-qa: fresh install with the extensions not activated shows the host as needs-attention in the UI within a check-in interval, then activation flips it to healthy (the 2026-06-12 scenario #359 came from)

## 8. Follow-ups (not in this change)

- [ ] 8.1 Tamper-detection alert rule for a component transitioning to `connection_lost` while the agent keeps checking in
- [ ] 8.2 Additional components: DNS proxy, event-queue depth and drops, applied policy version and staleness, agent CPU/memory, disk pressure, clock skew, cloud connectivity
- [ ] 8.3 Fold the check-in in as the single liveness source in place of the inferred command-poll and heartbeat side-channels
