# 0009. Database migrations via goose: per-context, forward-only, tiered

- Status: Accepted
- Date: 2026-05-31
- Deciders: getvictor

## Context

Until now each bounded context (ADR-0004) owned a `bootstrap/schema.go` holding a `schemaStatements` slice of
`CREATE TABLE IF NOT EXISTS ...` strings, applied at boot by an in-process loop. That pattern is idempotent for table
creation but has no way to express a rename, a drop, a type change, or a data backfill, and no record of which DDL has run
against a given database. `docs/best-practices.md` §10 flagged the ceiling; ADR-0005 noted the in-process idempotent-ALTER
pattern would eventually be replaced by versioned migrations. Issue #115 tracks the replacement.

The forcing function is the v0.1.0 availability commitment (see `ai/migrations/recommendation.md` and
`ai/migrations/ha-architecture.md`): the application tier ships multi-replica behind a load balancer, and rolling upgrade is
the only supported upgrade procedure. During a rolling cutover two binary versions read and write the same MySQL, so the
schema corpus and the way it is applied must be safe under that condition from the first migration that ships.

## Decision

Adopt [pressly/goose](https://github.com/pressly/goose) (`github.com/pressly/goose/v3`), embedded into the server binary via
`embed.FS`, applied at boot. Specifically:

- **Per-context migration directories** at `server/<context>/migrations/`, each with a `//go:embed *.sql` `embed.go` and
  numbered `NNNNN_name.sql` files. A shared helper, `server/migrations/runner.Up`, wraps goose; each context's
  `bootstrap.ApplySchema` calls it.
- **Per-context tracking tables** named `<context>_goose_db_version` (set via `goose.WithTableName`). Each context records
  its own applied versions, so the corpora stay independent and cross-context coordination remains the boot order in
  `cmd/fleet-edr-server/main.go`, not a shared migration table.
- **Migration v1 is today's schema, frozen.** Each context's current `schemaStatements` becomes `00001_initial.sql` verbatim,
  keeping `CREATE TABLE IF NOT EXISTS`. That makes the baseline safe to apply against a database that already carries the
  tables from the legacy in-process loop: the CREATEs no-op and goose records version 1. No retroactive rewrite.
- **Forward-only.** No `-- +goose Down` migrations. The rollback path is restore-from-backup. Down migrations are routinely
  buggy in ways a backup restore is not.
- **Tiered policy.** Tier 1 (online-DDL-safe ALTERs: add nullable column, add index `ALGORITHM=INPLACE, LOCK=NONE`) ships
  single-step. Tier 2 (drops, renames, type rewrites, NOT NULL backfills) MUST use expand-contract because a rolling upgrade
  runs binary N and binary N+1 against the same MySQL. The full policy and the expand-contract recipe live in
  `ai/migrations/recommendation.md` §6-§7; `docs/best-practices.md` §10 links here.

## Consequences

- **Easier**: renames, drops, type changes, and data backfills become expressible and tracked; a database's applied-version
  state is queryable; the boot path is idempotent by version, not by `IF NOT EXISTS` luck.
- **Easier**: Go migrations are available (goose supports them) for the first data backfill that cannot be expressed in SQL,
  without a one-off `cmd/data-backfill-N` binary.
- **Harder**: Tier-2 changes now cost up to four releases (expand, backfill, cutover, contract) instead of one. Tier-2 changes
  are uncommon, so this is a few releases per year, not per change; small data can collapse the phases (recommendation §7).
- **Harder**: each context now carries a `migrations/` directory and a `*_goose_db_version` tracking table, a small structural
  addition reviewers must keep in mind.
- **Constraint**: the tracking-table name is load-bearing. Renaming `<context>_goose_db_version` strands the applied-version
  history and goose would re-run every migration. Pick once, never rename.
- **Concurrency**: `runner.Up` takes no distributed lock. Single-replica boot is safe as-is. The multi-replica rolling-upgrade
  path wraps the whole boot migration sequence in one MySQL advisory lock at the cmd layer (HA arc), after which goose's
  tracking table makes every other replica's apply a no-op.

## Alternatives considered

**golang-migrate/migrate.** Mature, many drivers, single tracking table. Rejected primarily because it is SQL-only: the first
data backfill that needs application logic would be forced into a separate one-off binary. Native `embed.FS` support is also
thinner than goose's. If goose's maintenance ever flatlines, the fallback is a mechanical rewrite of file headers
(`-- +goose Up` to `.up.sql`/`.down.sql`) and an embed-driver swap, so the optionality is cheap.

**ariga/atlas (declarative).** Strong linting and a declarative diff model. Rejected because Atlas wants one canonical schema
definition, which fights the per-context `bootstrap/schema.go` ownership that ADR-0004 establishes; it would force a synthetic
top-level schema that drifts from the per-context source of truth, and it adds a CLI step to the operator runbook.

**Keep the in-process idempotent-ALTER loop.** Rejected: it cannot express renames/drops/backfills and has no version
tracking, which is exactly the ceiling §10 of best-practices flagged and which rolling upgrade makes untenable.

## References

- [Issue #115](https://github.com/getvictor/fleet-edr/issues/115): use a best-practice DB migration approach
- ADR-0004 (`docs/adr/0004-modular-monolith-bounded-contexts.md`): the per-context ownership this preserves
- ADR-0005 (`docs/adr/0005-mysql-only-data-plane.md`): MySQL-only data plane; its "Bad" list pointed at this work
- `ai/migrations/recommendation.md`: the research, tiered policy (§6), and expand-contract recipe (§7)
- `ai/migrations/ha-architecture.md` and `ai/migrations/v0.1.0-execution-plan.md`: the HA arc this interlocks with
- `docs/best-practices.md` §10: the "Versioned migrations" item this cashes in
- [pressly/goose](https://github.com/pressly/goose)
