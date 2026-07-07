## 1. Wire format

- [x] 1.1 Define `StatusReport` (agent version, reported-at, `[]ComponentHealth`) and `ComponentHealth` (`type`, `status`, `reason`, `message`, `last_transition_ns`) in `server/endpoint/api/status.go` with JSON tags; `status` is the closed `HealthStatus` set `healthy|degraded|unhealthy|unknown` with a `Valid()` boundary check
- [x] 1.2 PBT round-trip (`Marshal ∘ Unmarshal == identity`) with `pgregory.net/rapid`, plus an example-based wire pin of the endpoint-security + network-extension snapshot shape
- [x] 1.3 `Scan ∘ Value == identity` for the `Components` JSON column type

## 2. Server persistence and check-in (endpoint context)

- [x] 2.1 Migration `server/endpoint/migrations/00005_host_health.sql` (`+goose Up`/`Down`): `host_health` (host_id PK, overall_status VARCHAR(16), components JSON NULL, reported_at_ns BIGINT, updated_at TIMESTAMP), index on `overall_status`; Down drops the table
- [x] 2.2 Store `UpsertHostHealth`: last-writer-wins upsert keyed on `host_id`, guarded by an IF/GREATEST on `reported_at_ns` so a stale post cannot clobber a fresher snapshot (`server/endpoint/internal/mysql/health.go`)
- [x] 2.3 Service `RecordStatus`: validate `status` against the closed set at the boundary (reject unknown status wholesale, accept unknown `type`/`reason`); compute the worst-of rollup via `api.Rollup` (`unhealthy` > `degraded` > `healthy`; empty -> `unknown`)
- [x] 2.4 Handler `POST /api/status` behind the host-token middleware, reading the pinned host_id; mounted in the host-token mux in `cmd/main`
- [x] 2.5 Table-driven (`Rollup`), handler unit (all branches), and integration tests (real MySQL): upsert replaces prior, last-writer-wins, unknown type stored verbatim, invalid status 400, unauthenticated 401

## 3. Host API surface

- [x] 3.1 Add `OverallStatus` to `HostSummary` (`server/detection/api/types.go`) and a `LEFT JOIN host_health` with `COALESCE(overall_status, HostHealthUnknown)` in `ListHosts` (`server/detection/internal/mysql/hosts.go`), mirroring the existing enrollments join
- [x] 3.2 Add `GET /api/hosts/{host_id}/health` returning the full component list via a `HostHealthReader` seam on the operator handler (mirrors the `WebhookAdmin` seam so `api.Service` and its mocks stay untouched); store `HostHealth` read passes components through as raw JSON
- [x] 3.3 Integration test: seed a snapshot, then the host list carries `overall_status` and the detail carries the components; a host with no snapshot lists + reads as `unknown`

## 4. Agent health registry

- [x] 4.1 `agent/health/`: concurrency-safe registry mapping component type to condition; `Set(type, status, reason, message)` stamps `last_transition_ns` only on a real status change
- [x] 4.2 Track per extension whether a session has ever been established, to distinguish `never_connected` from `connection_lost`
- [x] 4.3 Wire the ESF and network-extension receiver loops into the registry via the existing connect/disconnect paths and `OnConnected`/`OnDisconnected` hooks (`agent/receiver/loop.go`)
- [x] 4.4 Unit tests: connected -> healthy/activated; never-connected before first session; connection-lost after a drop; transition-timestamp stability

## 5. Agent status poster

- [x] 5.1 `agent/health` Poster: build the snapshot from the registry and POST it to `POST /api/status` with the host token, reusing the agent HTTP client
- [x] 5.2 Cadence: post on startup, on transition (debounced ~2s), and on a ~60s periodic floor; clean ctx-cancel shutdown following the `RunRefresh` loop shape
- [x] 5.3 Wire the poster into `agent/cmd/fleet-edr-agent/main.go`
- [x] 5.4 Unit tests: startup post, transition-triggered post, debounce collapses a retry burst

## 6. UI

- [x] 6.1 `ui/src/types.ts`: extend `HostSummary` with `overall_status`; add `ComponentHealth` and the host-detail health shape
- [x] 6.2 `ui/src/components/HostList.tsx`: health badge column driven by `overall_status`, reusing `Badge`, distinct from the online/offline pill; neutral badge for `unknown`
- [x] 6.3 Host detail conditions panel (in `ProcessTree.tsx` header or a small new component): per-component status badge, message, and "since" relative time from `last_transition_ns`
- [x] 6.4 vitest siblings (`*.test.tsx`) covering the badge-variant mapping, the unknown/empty states, and the conditions panel

## 7. Spec and QA

- [x] 7.1 Add spectrace markers from the new tests to the scenario IDs in the three delta specs
- [x] 7.2 `openspec validate agent-health-reporting --strict`; prose + dash + markdown lints
- [ ] 7.3 Live QA on edr-qa: fresh install with the extensions not activated shows the host as needs-attention in the UI within a check-in interval, then activation flips it to healthy (the 2026-06-12 scenario #359 came from)

## 8. Follow-ups (not in this change)

- [ ] 8.1 Tamper-detection alert rule for a component transitioning to `connection_lost` while the agent keeps checking in
- [ ] 8.2 Additional components: DNS proxy, event-queue depth and drops, applied policy version and staleness, agent CPU/memory, disk pressure, clock skew, cloud connectivity
- [ ] 8.3 Fold the check-in in as the single liveness source in place of the inferred command-poll and heartbeat side-channels
