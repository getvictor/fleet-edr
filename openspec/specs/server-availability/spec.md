# Server Availability Specification

## Purpose

Server availability is the set of invariants that let the Fleet EDR control plane stay up across routine operations - schema
upgrades, replica restarts, and rolling binary cutovers - rather than requiring a maintenance window that takes the EDR offline.
It is the server-side half of the v0.1.0 availability commitment: the application tier is stateless and horizontally scalable, a
load balancer can drain a replica cleanly, periodic work runs on exactly one replica, first boot is safe under concurrent replica
start, and the schema is managed by versioned migrations that a rolling upgrade tolerates.

This spec defines the behavior the deployment topology and the operator runbook depend on. The migration discipline below is
load-bearing for the rest: rolling upgrade means two binary versions read and write the same MySQL during a cutover, so the
schema corpus and the way it is applied must admit both. See `ai/migrations/recommendation.md` and `ai/migrations/ha-architecture.md`
for the design rationale, and `docs/adr/0009-migrations-via-goose.md` for the migration decision.

## Requirements

### Requirement: Schema is managed by versioned forward-only per-context migrations

The system SHALL apply database schema through versioned, forward-only migration files applied at boot rather than by re-running
idempotent DDL in process. A bounded context whose schema is managed this way owns an ordered migration corpus and a dedicated
tracking table recording applied versions, so already-applied migrations are never re-run. Applying such a corpus SHALL be
idempotent: a boot whose corpus carries no new migration relative to the tracking table MUST make no schema change and MUST
succeed. Migrations SHALL be forward-only; the system MUST NOT depend on down-migrations for recovery (the documented rollback
path is restore-from-backup).

The conversion to this mechanism is staged across the v0.1.0 migration arc: the response and endpoint contexts are managed this
way today; identity, detection, and rules follow in the #115 rollout.

#### Scenario: Applying a baseline on a fresh database creates its tables

- **GIVEN** a fresh database with no migration tracking table
- **WHEN** the system applies a context's migration corpus
- **THEN** the tables defined by the corpus exist
- **AND** the context's tracking table records the applied version

#### Scenario: Re-applying an already-applied corpus makes no changes

- **GIVEN** a database whose tracking table already records every migration in a context's corpus
- **WHEN** the system applies that corpus again
- **THEN** the apply succeeds without error
- **AND** no migration is re-run and the schema is unchanged
