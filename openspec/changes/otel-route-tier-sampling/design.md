## Context

The TracerProvider in `internal/observability/observability.go` is built with `WithBatcher` + `WithResource` and no sampler, so the SDK default (`ParentBased(AlwaysSample)`) records and exports every span. Production already fails trace export with `502 (Bad Gateway)` against the collector, and the dominant volume is the agent data plane (`POST /api/events`). The server is stateless and multi-replica behind a load balancer (ADR-0010), so any runtime control must propagate to every replica without shared in-process state. Cross-context calls go through the imported `api/` package only (ADR-0004).

Fleet solves the same problem in `server/platform/tracing`: a `RouteTierSampler` whose ratios live in an `atomic.Pointer`, a `Registry` that classifies span names into tiers (the policy seam each context populates), and a `StartSettingsPoller` that re-reads a singleton settings row every 60s and atomically swaps the sampler state. We mirror that mechanism/policy split.

One EDR-specific constraint: `otelhttp.NewHandler` is the outermost middleware (`server/httpserver/httpserver.go`), so the span is created before `net/http` route matching and the span name is the raw `method + URL.Path`, not the route template. This is workable because the routes that drive volume have literal paths.

## Goals / Non-Goals

**Goals:**

- Cap baseline trace volume with route-aware head sampling, three tiers (HighVolume / Standard / Full).
- Let an operator change the two ratios and a force-full toggle at runtime, propagated to every replica within one poll interval, no redeploy.
- Keep aggregate latency/alerting signals correct under sampling by anchoring them to metrics.

**Non-Goals:**

- Runtime log-level control (deferred; out of scope for this change).
- New environment variables (defaults are compile-time constants seeded into the migration row).
- Tail sampling in the collector (possible follow-up).
- A UI control surface (API-only for now).

## Decisions

### Three tiers, classified by span name

`Tier` is `Full | Standard | HighVolume | Drop`, with `Full` as the zero value so any unregistered span is safe-by-default at 100% until someone deliberately downsamples it.

- **HighVolume**: agent data-plane routes that dominate volume without being individually interesting: `POST /api/events`, the agent `GET /api/commands` poll, `POST /api/token/refresh`, `POST /api/enroll`.
- **Standard**: operator/UI read traffic (the dashboard `GET` endpoints).
- **Full**: everything else (writes, admin mutations, unclassified).
- **Drop**: liveness/health/version probes. Classified to `NeverSample`, and this check runs before the force-full branch so probe spans are never exported even during a debug window. Pure load-balancer noise with zero diagnostic value, matching Fleet's `TierNever`.

The `Registry` maps `"METHOD /path"` to a tier; `Lookup` returns `Full` for misses. Because the HighVolume routes are all literal paths (no `{param}` segments), the existing raw-path span name matches the registry exactly; no path normalizer is needed. Param-bearing routes (`/api/commands/{id}`, `/api/enrollments/{host_id}/revoke`) are operator/low-volume and correctly fall to Full.

**Alternative considered**: add a path normalizer (collapse UUID/numeric segments) so param-bearing routes can be tiered too. Rejected for now: the volume drivers don't need it, and a normalizer is fragile to maintain. Documented as a known limitation.

### Sampler wiring: `ParentBased(RouteTierSampler)`

`RouteTierSampler` implements `sdktrace.Sampler`. Its state (a `TraceIDRatioBased` per ratio-bearing tier, an `AlwaysSample` for Full, and the `force_full` flag) lives in an `atomic.Pointer` so the poller swaps it under a hot reader without locking. `Apply(highVolume, standard, forceFull)` clamps each ratio to `[0,1]` as a defensive backstop. It is wrapped in `ParentBased` at the provider so a sampled parent forces its children sampled and only root spans take a tier decision. `observability.Init` accepts the sampler via `Options` and adds `sdktrace.WithSampler(...)`.

### Persistence: dedicated `trace_sampler_settings` singleton table

Typed columns (`high_volume_ratio` DOUBLE, `standard_ratio` DOUBLE, `force_full` BOOL, `updated_at`) with `CHECK (... BETWEEN 0 AND 1)` constraints, single row seeded by the migration with the sampler's compile-time defaults.

**Alternative considered**: extend identity's `appconfig` JSON blob. Rejected in favor of a dedicated table: explicit schema, DB-enforced bounds, and a clean read accessor, matching the Fleet design and "industry best practice" for a typed runtime-config knob.

**Ownership**: the table, migration, store, and handler live in a new **`observability`** bounded context (a sixth context, amending ADR-0004). It owns a schema and serves an authz-gated, audited HTTP route, which is the bounded-context shape here; a context-free platform package can't host it because arch-go forbids platform packages from importing any context (so they can't reach `identity/api` for authz + audit). The context consumes `identity/api` for the chokepoint + audit recorder, exactly as `endpoint`/`response` do, and exposes its store as the poller's `tracing.SettingsReader`. The sampler mechanism + `Settings` type stay in the agent-safe `internal/observability/tracing` infra package, which this context imports.

### Per-replica polling, 60s

`StartSettingsPoller` does one immediate read at startup, then ticks every 60s, applies only on change, and keeps the compile-time defaults if the first read fails (warn-logged, retried next tick). The applied state is a per-replica cache that is safe to lose, which satisfies ADR-0010.

### Admin API: `GET` / `PATCH /api/settings/tracing`

Super_admin only (session cookie + CSRF, matching the other `/api/settings/*` endpoints). `PATCH` validates each ratio in `[0,1]` before persisting and returns the updated settings. Not reachable with an agent host token.

### Default ratios (industry best practice)

Seed `high_volume_ratio = 0.01`, `standard_ratio = 0.1`, `force_full = false`. These keep the load-bearing rare paths at full fidelity (Full = 100%) while cutting the agent firehose by ~99%. Both are tunable live, so the exact seed is low-stakes; they match the sampler's compile-time constants so a fresh replica and a polled one agree.

## Risks / Trade-offs

- **Param-bearing high-volume route appears later** → it would default to Full (100%) and not be downsampled until a normalizer is added. Mitigation: documented limitation; today's volume drivers are all literal-path.
- **p99/error-rate dashboards currently read from spans** → under sampling they become biased. Mitigation: a spec requirement plus operator doc mandating that aggregate latency/alerting read from metrics (`http.server.request.duration`, counters), which are never sampled.
- **Misconfiguration sets a ratio to 0 and hides a real incident's traces** → Mitigation: `force_full` toggle restores 100% live within one poll interval; CHECK constraints and handler validation bound the inputs.
- **Poller adds a 60s query per replica** → negligible; single-row read, instrumented with its own internal span.

## Migration Plan

1. Additive migration creates `trace_sampler_settings` and seeds one row with the defaults. No change to the agent protocol, events schema, or host token, so no agent-side rollback is needed.
2. Deploy server + ingest with the sampler wired; trace volume drops immediately to the seeded ratios.
3. Move any span-derived p99/error dashboards to metrics before relying on them.
4. **Rollback**: drop the table (sampler falls back to compile-time defaults) or revert the binary (TracerProvider returns to the always-on default).
