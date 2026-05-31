# Server Availability Specification

## ADDED Requirements

### Requirement: Schema is managed by versioned forward-only per-context migrations

The system SHALL apply database schema through versioned, forward-only migration files applied at boot rather than by re-running
idempotent DDL in process. A bounded context whose schema is managed this way owns an ordered migration corpus and a dedicated
tracking table recording applied versions, so already-applied migrations are never re-run. Applying such a corpus SHALL be
idempotent: a boot whose corpus carries no new migration relative to the tracking table MUST make no schema change and MUST
succeed. Migrations SHALL be forward-only; the system MUST NOT depend on down-migrations for recovery (the documented rollback
path is restore-from-backup).

The conversion to this mechanism is staged across the v0.1.0 migration arc: the response and endpoint contexts land in this
change's first PR; identity, detection, and rules follow in the #115 rollout.

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
