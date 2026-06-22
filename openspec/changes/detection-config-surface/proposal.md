# DB-backed detection configuration surface

## Why

Detection-rule configuration (the four false-positive allowlists plus the disabled-rule list) is configured today as boot-time environment-variable CSVs: `EDR_LAUNCHAGENT_ALLOWLIST`, `EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST`, `EDR_SUDOERS_WRITER_ALLOWLIST`, `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST`, `EDR_DISABLED_RULES` (issue #459). That is the wrong layer for a stateless multi-replica server (ADR-0010): changing it requires editing env and restarting every replica, there is no audit trail of who changed what, it cannot be scoped to a host group, and it puts durable cross-request operator state in per-replica boot env instead of MySQL.

False-positive suppression is the number-one pilot pain for an EDR, and the detection catalog is growing: many future rules will need their own tunables (thresholds, windows, severity). We want one common, durable, governed config surface rather than a new env var per knob. The market has converged on this shape: CrowdStrike Falcon (prevention policies + host-group-scoped IOA/ML exclusions), Microsoft Defender (device-group-scoped indicators + custom detections), SentinelOne (policy inheritance + signer/path/hash exclusions), and Elastic Security (per-rule settings + first-class shared exception lists) all store detection config centrally, edit it through an API/console, scope it to groups, and audit every change. None use host-local or boot config.

## What changes

Introduce a DB-backed detection-configuration surface in the rules context (alongside the catalog rules, Application Control, and `host_groups` it already owns), edited through the admin REST API + UI, governed by the existing RBAC chokepoint and audit log, and consumed by the detection engine server-side with no agent fan-out.

Two layers, mirroring industry practice:

- **Per-rule settings.** One record per `(rule_id, scope)` carrying a `mode` (`alert` / `monitor` / `disabled`), an optional `severity_override`, and a JSON `settings` document validated against the rule's self-declared config schema (the existing `ConfigKnob` generalised). The three-value `mode` matches the universal EDR shape (Defender ASR audit mode, Falcon detect-vs-prevent, SentinelOne rule states): `alert` produces alerts as today, `disabled` evaluates nothing for that scope, and `monitor` evaluates the rule but emits an observability signal instead of an alert so an operator can gauge a rule's noise before promoting it to `alert`. Modelling state as an enum (not a boolean) means the audit/monitor third state the whole market has is available now without another migration. New detections get config by declaring their schema, with no new table and no new env var.
- **Typed exclusions** (the allowlist layer). One record per entry: a `match_type` (`path_glob`, `parent_path_glob`, `team_id`, `signing_id`, `cdhash`, `sha256`, `command_substring`, `domain`), a `value`, an owning `rule_id` (or shared), a `reason`, `created_by`, and an optional `expires_at` (auto-expiry, as Elastic and SentinelOne do). The four current allowlists become exclusion records: launchagent -> `path_glob`, launchdaemon -> `team_id`, sudoers -> `path_glob`, suspicious_exec -> `parent_path_glob`.

Both layers carry a `host_group_id` where `0` (the `GlobalScope` sentinel) means global and a real id scopes the record to a host group, from day one so the schema never has to be re-migrated when editable host groups arrive. Host-group editing is still Phase A immutable (only the seeded `all-hosts` group exists), so the operative scope today is global; the resolver and schema are group-ready for Phase B. The column is not FK-constrained to `host_groups` yet: group existence is validated at the app layer, and the FK plus cascade cleanup land with the editable-host-groups (Phase B) change (a sentinel-with-app-validation shape avoids InnoDB's restriction against an `ON DELETE` referential action on a column that also backs a uniqueness key, while keeping the global row unique per rule).

Resolution is **per host at evaluation time** (how Falcon, SentinelOne, and Elastic evaluate exclusions, and the only correct way to honour host-group scope): the engine hands each rule an `ExclusionResolver`. Before a rule emits a finding for host H it asks the resolver whether an exclusion of the relevant `match_type` applies at global scope or for any host group H belongs to; a match suppresses the finding. The resolver indexes entries by `(rule_id, match_type)` and compiles match values once, so per-event cost is bounded to the handful of entries for that key rather than a scan of the whole allowlist (the industry pattern; addresses the hot-path concern). Per-rule `mode` and `severity_override` resolve most-specific-wins per host. A globally-disabled rule stays visible in the catalog (`GET /api/rules`) with its mode indicator and simply emits nothing, rather than disappearing.

Config mutations bump a version and take effect without a restart: the rules context rebuilds the snapshot and the detection engine reloads it via the existing `Engine.LoadActive`. Each replica reads the snapshot from MySQL and may cache it keyed by version (a per-replica perf cache, safe to lose), so the stateless-multi-replica invariant holds.

## Hard switch (no migration, no deprecation)

Per the issue owner: this is a hard cutover. The five environment variables and their config plumbing (`config.Config` fields, `loadAllowlists`, the `RegistryOptions` allowlist fields populated from env) are **deleted**, not deprecated. There is no env-to-DB seeding and no fallback release. The DB surface starts empty (no entries, every rule enabled), and operators re-add any needed suppression through the UI/API after the switch.

## Scope notes

- Host-group-scoped *entries* are accepted by the schema/API now, but with only the immutable `all-hosts` group present the effective scope is global until editable host groups (Phase B) land. No re-migration is needed when they do.
- This is the generic framework; the five existing knobs are its first tenant. It is explicitly designed so detection rule number eleven gets config (settings + exclusions + a generic UI row) without new DDL or new env vars.

## Impact

- Affected specs: `server-detection-rules-engine` (config is DB-backed + host-scoped + hot-reloaded; the boot-time toggling requirement is modified; the env knobs are removed), `web-ui` (admin surface to view/edit detection config).
- Affected code: `server/rules/internal/<new detectionconfig package>` (store + service + REST handler), `server/rules/migrations` (new tables), `server/rules/internal/operator` (route registration), `server/rules/api` (generalised config schema + `ExclusionResolver` contract), `server/rules/internal/catalog` (rules consume the resolver instead of baked allowlist maps; `catalog.New` built from the DB snapshot), `server/detection` (engine threads the resolver + reload trigger), `server/config/config.go` (delete the five env knobs + `loadAllowlists`), `ui/src` (detection-config admin views), `docs/{detection-rules,operations,install-server}.md` (repoint at the new surface), and the session-protected route allowlist (new `/api/v1/detection-config/*` routes).
- No agent, extension, wire-format, or schema/events change. Server + UI only.
- Behavior change: a disabled rule remains listed in `GET /api/rules` (with its mode) instead of being removed from the catalog as `EDR_DISABLED_RULES` did. A new `monitor` mode evaluates a rule without raising alerts, emitting an observability signal instead.
