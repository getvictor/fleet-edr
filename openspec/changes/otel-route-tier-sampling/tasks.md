## 1. Shared sampler package (`internal/observability/tracing`)

- [x] 1.1 Add `Tier` (Full=zero-value catch-all, Standard, HighVolume, Drop) and `Registry` (map of `"METHOD /path"` to tier; `Lookup` returns Full on miss) with `Register`/`Lookup`.
- [x] 1.2 Add `RouteTierSampler` implementing `sdktrace.Sampler`: `atomic.Pointer` state, `TraceIDRatioBased` per ratio tier + `AlwaysSample` for Full + `NeverSample` for Drop, `Apply(highVolume, standard, forceFull)` with `[0,1]` clamp, `Description()`. Drop is checked before the force-full branch so probes stay dropped under force-full.
- [x] 1.3 Add compile-time default consts (`DefaultHighVolumeRatio = 0.01`, `DefaultStandardRatio = 0.1`) and construct the sampler seeded with them.
- [x] 1.4 Add `Settings` struct and `StartSettingsPoller` (immediate first read, 60s tick, apply-on-change, keep defaults on read failure, internal poll span).
- [x] 1.5 Add `doc.go` describing the mechanism/policy split.

## 2. Tracer provider wiring

- [x] 2.1 Extend `observability.Options` with a `Sampler sdktrace.Sampler` field and add `sdktrace.WithSampler(...)` in `Init` (`internal/observability/observability.go`); default to the SDK behavior when nil.
- [x] 2.2 Construct `ParentBased(RouteTierSampler)` and pass it through `Options` from the server and ingest bootstrap.

## 3. Persistence (new `observability` bounded context)

- [x] 3.1 Add a migration creating the `trace_sampler_settings` singleton table (`high_volume_ratio`, `standard_ratio` DOUBLE with `CHECK (... BETWEEN 0 AND 1)`, `force_full` BOOL, `updated_at`), seeding one row with the default ratios. No cross-context FK to `users` (the audit log is the authoritative record).
- [x] 3.2 Add a store with get/update methods (update bounded by the DB `CHECK`); expose it as the poller's `tracing.SettingsReader`.
- [x] 3.3 Scaffold the context: `bootstrap` (New/ApplySchema/RegisterAuthedRoutes/TraceSamplerSettingsReader) + `testkit` + `migrations`; add arch-go rules and amend ADR-0004 for the sixth context.

## 4. Admin API

- [x] 4.1 Add `GET`/`PATCH /api/settings/tracing` (admin + super_admin via the `tracing.manage` action, session cookie + CSRF), mounted alongside the other `/api/settings/*` routes.
- [x] 4.2 `PATCH` validates ratios in `[0,1]`, persists via the store, and returns the updated settings; reject operators without the `tracing.manage` grant.

## 5. Route-tier policy registration

- [x] 5.1 In `server/cmd/fleet-edr-server/main.go` and `server/cmd/fleet-edr-ingest/main.go`: build the registry, register agent data-plane routes as HighVolume, operator/UI `GET` reads as Standard, and liveness/health/version probes as Drop, then start the poller with the observability context's settings reader.
- [x] 5.2 Audit shared paths (e.g. agent `GET /api/commands` vs operator `GET /api/commands/{id}`) so agent traffic lands in HighVolume and operator reads in Standard.

## 6. Tests

- [x] 6.1 `RouteTierSampler`: tier selection per route, force-full override, drop-tier precedence over force-full, ratio clamp; table-driven, plus PBT for the clamp/ratio invariant.
- [x] 6.2 `Registry`: lookup hits and Full-on-miss default.
- [x] 6.3 `StartSettingsPoller`: apply-on-change, no-op when unchanged, defaults-on-first-read-failure (fake `settingsReader`).
- [x] 6.4 Store: get/update round-trip and out-of-range rejection (real MySQL via `testdb/full.Open`).
- [x] 6.5 Admin handler: authorized success, denied (no grant), invalid-JSON, missing-actor, and out-of-range validation.
- [x] 6.6 `observability.Init`: provider builds with the sampler wired and stays no-op when the endpoint is empty.

## 7. Docs and spec finalization

- [x] 7.1 Operator doc for `GET`/`PATCH /api/settings/tracing`, the tier policy, defaults, and the "p99/alerting reads from metrics, not sampled spans" note.
- [x] 7.2 Add a spectrace marker from at least one test to the new SHALL scenarios; run `openspec validate --all --strict`.
