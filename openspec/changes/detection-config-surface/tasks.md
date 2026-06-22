# Tasks

## Data model (rules context)

- [x] `server/rules/migrations`: add `detection_rule_settings` (`rule_id`, `host_group_id` NOT NULL DEFAULT 0 where 0=global, `mode` ENUM('alert','monitor','disabled') DEFAULT 'alert', `severity_override` NULL, `settings` JSON, audit columns; unique on `(rule_id, host_group_id)`) and `detection_exclusions` (`id`, `rule_id` (''=shared), `match_type` ENUM, `value`, `host_group_id` NOT NULL DEFAULT 0, `reason`, `created_by`, `created_at`, `expires_at` NULL, `enabled`) plus `detection_config_meta` version counter. `host_group_id` is validated app-side; the FK + cascade to `host_groups` lands with editable host groups (Phase B).
- [x] A monotonic config `version` (per the App Control pattern) bumped on every mutation, for replica cache invalidation + hot reload (`detection_config_meta`; `bumpVersion` fails closed if the row is missing).

## Rule-facing contract (`server/rules/api`)

- [ ] Generalise `ConfigKnob` into a typed per-rule config schema: declared setting keys (type, default, bounds) + the `match_type`s the rule honours. Drives validation + the generic UI.
- [x] Define `ExclusionResolver` (narrow read surface, like `GraphReader`): `Excluded(ruleID, matchType, value, hostID) bool` resolving global + the host's groups, honouring `expires_at`. Index entries by `(rule_id, match_type)` so per-event cost is bounded to that key. Glob matching is now `api.GlobMatch` (canonical home; suspicious_exec's private copy is removed in the catalog-rewire task).
- [x] Define the per-host settings resolution: `mode` (alert/monitor/disabled) + severity override, most-specific-wins (`detectionconfig.Snapshot`).

## Engine + catalog

- [x] `catalog.New` is built from the DB snapshot (the `detectionconfig.Service` resolver) instead of `RegistryOptions` env allowlists. Rules consult the injected `ExclusionResolver` per finding/host instead of a baked `map[string]struct{}`.
- [x] Rules with allowlists (`suspicious_exec`, `persistence_launchagent`, `privilege_launchd_plist_write`, `sudoers_tamper`) call the resolver; their `Allowed*` map fields are removed (replaced by `Exclusions api.ExclusionResolver`).
- [ ] Canonicalize paths consistently between the rule and the resolver for `path_glob` / `parent_path_glob` matches, so an exclusion written against one macOS path form (`/etc/...`) still applies when ESF reports the aliased form (`/private/etc/...`); reuse the existing canonicalization (PR #50 / #290). Still deferred (Qodo #4 on PR #475); does not block the cutover.
- [x] Engine routes each finding by the `(rule, host)` resolved mode: `disabled` drops it, `monitor` drops the alert but emits an observability signal (a structured log line recording the match), `alert` persists. Applies `severity_override`. A globally-disabled rule stays in the catalog surface. A dedicated monitor counter is a follow-up.
- [x] Config is resolved against an atomically-swapped in-memory snapshot (the `detectionconfig.Service` holds `atomic.Pointer[Snapshot]`); boot loads it in `ApplySchema`. Per-mutation reload + the periodic multi-replica refresh land with the REST surface. No `Engine.LoadActive` churn is needed since disabled rules stay registered.

## REST + governance

- [ ] `server/rules/internal/detectionconfig` (store + service) + `server/rules/internal/operator` routes: list/create/update/delete exclusions; get/update per-rule settings; scoped to host groups. Mirror the App Control handler shape.
- [ ] Every mutation goes through the existing RBAC chokepoint and writes an audit row (actor + reason).
- [ ] Register the new `/api/v1/detection-config/*` routes in the session-protected route allowlist.

## Delete the env surface (hard switch)

- [x] Remove `EDR_LAUNCHAGENT_ALLOWLIST`, `EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST`, `EDR_SUDOERS_WRITER_ALLOWLIST`, `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST`, `EDR_DISABLED_RULES` and their `config.Config` fields + `loadAllowlists` + the `RegistryOptions` type (and `UnknownDisabledIDs`). No seeding, no fallback. The four rules' `Doc()` env-var ConfigKnobs are dropped and `docs/detection-rules.md` regenerated.

## UI

- [ ] `ui/src`: detection-config admin views (per-rule mode (alert/monitor/disabled) + severity + settings from the declared schema; exclusion list CRUD with match-type, value, reason, expiry, scope). Generic, schema-driven. Co-located `*.test.tsx`.

## Tests + docs

- [x] Store integration tests (real MySQL): CRUD, version bump, resolve-via-snapshot, invalid-input rejection (`store_test.go`). Pure snapshot tests: expiry, group scope, shared-rule, most-specific-wins mode/severity (`snapshot_test.go`).
- [ ] Catalog tests: each migrated rule suppressed by a DB exclusion at global scope; disabled rule emits nothing but stays listed.
- [ ] `docs/detection-rules.md`, `docs/operations.md`, `docs/install-server.md`: repoint from env vars to the new surface; regenerate `detection-rules.md` via `tools/gen-rule-docs`.
- [ ] Spectrace markers for the new SHALL/MUST scenarios.

## Gates

- [ ] `go test`, `task lint:go`, `task lint:dashes`, `tools/spectrace check --strict`, `openspec validate detection-config-surface --strict`, `cd ui && npm test`.

## Manual QA

- [ ] dev:server + edr-dev + SigNoz: add an exclusion via API, confirm a previously-firing chain is suppressed without restart; disable a rule, confirm it stops emitting and stays listed in `GET /api/rules`.

## Archive

- [ ] Archive at release (`openspec archive detection-config-surface`), not per-merge.
