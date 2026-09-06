# Server availability: context registration delta

## MODIFIED Requirements

### Requirement: Schema is managed by versioned forward-only per-context migrations

The system SHALL apply database schema through versioned, forward-only migration files applied at boot rather than by re-running idempotent DDL in process. A bounded context whose schema is managed this way owns an ordered migration corpus and a dedicated tracking table recording applied versions, so already-applied migrations are never re-run. Applying such a corpus SHALL be idempotent: a boot whose corpus carries no new migration relative to the tracking table MUST make no schema change and MUST succeed. Migrations SHALL be forward-only; the system MUST NOT depend on down-migrations for recovery (the documented rollback path is restore-from-backup).

Every bounded context that owns database tables is managed this way. That is stated as a property rather than as a list of contexts, because a hand-maintained list drifts silently: the previous enumeration named five contexts and had fallen three behind the tree.

The standalone migration tool SHALL apply the corpus of every such context. A context it omits is not merely unmigrated: the tool reports success having skipped it, so a deployment that migrates as a privileged step and then runs without schema-change permission fails at boot on that context alone, and a multi-replica boot races to apply it, which is the race a separate tool exists to remove.

Whether a context is registered with that tool SHALL be checkable from the source tree rather than asserted against a maintained list, because a list of expectations drifts in step with the list it checks.

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

#### Scenario: A context shipping migrations is registered

- **GIVEN** a bounded context in the source tree that ships migration files
- **WHEN** the registered contexts are compared against the tree
- **THEN** that context is registered with the standalone migration tool

#### Scenario: A registered context ships migrations

- **GIVEN** a context registered with the standalone migration tool
- **WHEN** the registered contexts are compared against the tree
- **THEN** it ships migration files, so its registration is not a step that silently does nothing
