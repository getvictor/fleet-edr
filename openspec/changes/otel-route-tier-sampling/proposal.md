## Why

OTel trace export is unbounded: no sampler is configured, so the SDK default (parent-based, always-on) records and exports every span. The production server is already failing exports with `traces export: exporter export timeout: ... 502 (Bad Gateway)` against a constrained collector, and the volume only grows with the fleet. Operators have no way to dial telemetry down (to survive an export incident) or up (to debug) without a redeploy. We need head sampling to cap baseline volume and a runtime control to adjust it live.

## What Changes

- Add a route-aware head sampler (`ParentBased(RouteTierSampler)`) to the server and ingest TracerProviders, replacing the implicit always-on SDK default.
- Classify every HTTP span into a sampling tier:
  - **HighVolume**: high-frequency agent data-plane traffic (`POST /api/events`, the agent `GET /api/commands` poll, `POST /api/token/refresh`). Heavily sampled. (Rare load-bearing agent routes like `POST /api/enroll` stay Full.)
  - **Standard**: API/user read traffic (operator and UI `GET` endpoints). Moderately sampled.
  - **Full**: everything else (writes, admin mutations, unclassified routes). Sampled at 100%, safe-by-default.
  - **Drop**: liveness/health/version probes. Never recorded or exported, and this wins over `force_full`.
- Add a `force_full` incident toggle that lifts every non-drop tier to 100% for a debug window without a redeploy (probes stay dropped).
- Persist the two ratios plus `force_full` in a dedicated `trace_sampler_settings` singleton MySQL table with `CHECK` constraints bounding each ratio to `[0, 1]`. Seed the row with the sampler's compile-time defaults. No new environment variables.
- Each replica polls the row every 60s and atomically swaps the live sampler state, so changes propagate across the stateless app tier without a restart (ADR-0010).
- Expose `GET` and `PATCH /api/settings/tracing` (admin + super_admin, like the SSO settings API) to read and update the settings.
- Document that under sampling, p99 and alerting must read from metrics (counter- and histogram-based, never sampled), not from sampled spans.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `observability-instrumentation`: adds requirements for route-tier head sampling, runtime-adjustable sampler settings (persistence, per-replica polling, admin API, force-full override), and the constraint that aggregate latency/alerting signals derive from metrics rather than sampled spans.

## Impact

- **Code**:
  - New shared package `internal/observability/tracing` (Tier, Registry, RouteTierSampler, Settings, StartSettingsPoller), mirroring Fleet's `server/platform/tracing` mechanism/policy split.
  - `internal/observability/observability.go`: `Init` wires `ParentBased(RouteTierSampler)` into the TracerProvider via `Options`.
  - `server/cmd/fleet-edr-server/main.go` and `server/cmd/fleet-edr-ingest/main.go`: construct the sampler + registry, register the route-tier policy, start the poller. Both mount `POST /api/events`.
  - New `observability` bounded context (a sixth context, ADR-0004 amendment): `trace_sampler_settings` table + migration, store, and the `GET`/`PATCH /api/settings/tracing` handler. It consumes `identity/api` for the authz chokepoint + audit recorder, and exposes the store as the poller's `tracing.SettingsReader`. The sampler mechanism stays in the agent-safe `internal/observability/tracing` infra package.
- **APIs**: new admin + super_admin endpoints `GET`/`PATCH /api/settings/tracing`. No change to the agent protocol, the events schema, or the persisted host token, so no rollback steps are required for those surfaces.
- **Database**: one additive migration creating `trace_sampler_settings`. Rollback is dropping the table; the sampler falls back to compile-time defaults if the row is unreadable.
- **Observability**: trace volume drops to the configured ratios; dashboards/alerts that read p99 from spans must move to metrics.
- **Docs**: operator doc for the new endpoint and the metrics-are-authoritative-under-sampling note.
