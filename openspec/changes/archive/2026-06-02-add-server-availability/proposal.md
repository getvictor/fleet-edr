# Server availability: versioned migrations + HA topology for v0.1.0

## Why

The v0.1.0 availability commitment is a 99.9% control-plane SLA with no customer-visible downtime on routine upgrade. The
current single-binary / single-MySQL-primary topology cannot deliver that: the binary restart itself is the gap. Closing it
needs two interlocking arcs that ship together (see `ai/migrations/recommendation.md`, `ai/migrations/ha-architecture.md`, and
the PR slicing in `ai/migrations/v0.1.0-execution-plan.md`):

1. **Versioned migrations** so schema changes are expressible (rename / drop / backfill), tracked, and safe under rolling
   upgrade, where two binary versions read and write the same MySQL during a cutover.
2. **HA topology** (stateless multi-replica app tier behind a load balancer, leader-gated periodic tasks, drain-on-SIGTERM,
   concurrent-boot safety, replica identity) so a rolling upgrade keeps the control plane up.

The migration discipline is load-bearing for the HA arc: rolling upgrade is the upgrade procedure, and expand-contract is what
makes Tier-2 migrations safe under it. Neither arc is useful without the other for v0.1.0.

This change carves a new `server-availability` spec slug and is landed incrementally across the six PRs in the execution plan.
This proposal's spec delta currently carries the migration requirement (PR 1); the HA requirements are added to the same slug by
their implementing PRs (drain + stateless + concurrent-boot in PR 3, leader coordination in PR 4, cross-replica + SKIP LOCKED +
rolling-upgrade-safe migration in PR 5). The change is archived after PR 6.

## What Changes

- Add the `server-availability` spec slug.
- **PR 1 (this delta)**: adopt goose, embedded per-context migration corpora with per-context tracking tables, forward-only +
  tiered policy (ADR-0009). Convert the response + endpoint contexts; add the shared `server/migrations/runner` helper. The
  emitted schema is byte-identical to the pre-goose `schemaStatements`.
- **PR 2**: convert the identity, detection, rules contexts; add a standalone `cmd/fleet-edr-migrate` CLI.
- **PR 3**: stateless-server invariant (ADR-0010), drain-then-shutdown on SIGTERM, race-safe first-boot admin seed,
  `service.instance.id` on the OTel resource.
- **PR 4**: leader coordinator (MySQL advisory locking) gating retention + process-TTL; processor stays parallel via SKIP LOCKED.
- **PR 5**: multi-replica install package + the multi-replica integration test, including the rolling-upgrade-safe migration lock.
- **PR 6**: rolling-upgrade runbook, availability + SLA docs, HA architecture ADR (ADR-0011).

## Impact

- Affected specs: `server-availability` (new).
- Affected code (PR 1): `server/migrations/runner` (new), `server/{response,endpoint}/migrations` (new),
  `server/{response,endpoint}/bootstrap` (ApplySchema now delegates to goose; `schema.go` deleted), `go.mod`.
- Affected docs (PR 1): ADR-0009 (new), ADR-0005 (Bad-list updated), `docs/best-practices.md` §10 (item checked).
- No wire-format, API, or emitted-schema change in PR 1; the persistence MECHANISM changes (goose tracking tables appear).
