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

Every bounded context that owns database tables (identity, endpoint, rules, response, detection) is managed this way.

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

### Requirement: The server holds no in-process state that survives a request lifetime

The server SHALL NOT retain in-process state that outlives a single request and that a peer replica would need to serve a
subsequent request correctly. Durable state SHALL live in the shared MySQL store; per-request state MAY ride in signed cookies;
short-lived per-replica performance caches are permitted only when losing them on a restart is harmless. This invariant is what
lets any replica behind the load balancer serve any request and lets a replica restart without customer-visible state loss. It is
enforced at review time against `docs/adr/0010-stateless-server.md`; there is no runtime test.

### Requirement: SIGTERM produces a load-balancer-drainable graceful shutdown

On SIGTERM the server SHALL begin draining before it closes its listener: it SHALL report not-ready on its readiness probe so a
load balancer removes the replica from rotation, SHALL keep serving in-flight and newly-accepted requests for a bounded drain
window, and SHALL then stop accepting new connections and wait for in-flight requests to finish up to a bounded shutdown deadline.
The process SHALL exit within the drain window plus the shutdown deadline. The drain window is operator-configurable and MAY be
zero to disable the wait.

#### Scenario: Readiness reports not-ready once draining begins

- **GIVEN** a running server whose readiness probe reports ready
- **WHEN** the server begins draining on SIGTERM
- **THEN** the readiness probe reports not-ready with HTTP 503
- **AND** it does so regardless of whether the database check would otherwise pass

#### Scenario: In-flight requests complete before the listener closes

- **GIVEN** a server draining on SIGTERM with a request in flight
- **WHEN** the drain window elapses and graceful shutdown runs
- **THEN** the in-flight request completes successfully before the process exits

#### Scenario: The process exits within the drain plus shutdown deadline

- **GIVEN** a server draining on SIGTERM
- **WHEN** the drain window and the shutdown grace deadline elapse
- **THEN** the process has exited

### Requirement: First-boot admin seed is safe under concurrent replica boot

When multiple replicas boot concurrently against a fresh database, the first-boot break-glass admin seed SHALL produce exactly one
admin row and every replica's seed SHALL succeed. The replica that loses the create race SHALL adopt the existing row rather than
failing its boot. The break-glass redemption banner SHALL be emitted by at most one replica per concurrent boot, so an operator
sees a single redemption URL rather than one per replica.

#### Scenario: Two replicas seeding concurrently produce exactly one admin row

- **GIVEN** a fresh database and two replicas running the admin seed concurrently
- **WHEN** both seed attempts run
- **THEN** both succeed
- **AND** exactly one break-glass admin row exists

#### Scenario: Only one replica emits the bootstrap-token banner under concurrent boot

- **GIVEN** multiple replicas booting concurrently with the admin not yet redeemed
- **WHEN** they race to emit the break-glass redemption banner under the leader gate
- **THEN** exactly one replica emits the token and prints the banner
- **AND** the other replicas do not

### Requirement: Replica identity is observable via service.instance.id

Every replica SHALL attach a `service.instance.id` resource attribute to the telemetry it emits so an operator can tell replicas
apart in the observability backend. The identifier SHALL be stable for the lifetime of the process.

#### Scenario: Every emitted span carries the service instance id

- **GIVEN** a configured telemetry resource for a replica with a service instance id set
- **WHEN** the resource is built
- **THEN** it carries a non-empty `service.instance.id` attribute

#### Scenario: The service instance id is stable for the process lifetime

- **GIVEN** a running replica
- **WHEN** its service instance id is read more than once
- **THEN** the same value is returned each time

### Requirement: Periodic tasks run on exactly one replica via MySQL advisory locking

The system SHALL run its single-instance periodic maintenance tasks (event retention and the stale-process TTL reconciler) on
exactly one replica at a time, coordinated through MySQL named advisory locks, even though every replica runs the same binary. A
replica that does not hold a task's lock SHALL NOT run that task, and SHALL take over when the current holder releases the lock or
its connection drops. The event processor is explicitly NOT coordinated this way: it scales across replicas via row-level
SKIP LOCKED claiming, so each replica processes disjoint batches.

#### Scenario: Single replica acquires the lease uncontended

- **GIVEN** a single replica and no other holder of a task's lock
- **WHEN** the replica runs the task under the coordinator
- **THEN** it acquires the lock and runs the task

#### Scenario: Concurrent replicas elect exactly one leader per task

- **GIVEN** two replicas contending for the same task lock
- **WHEN** both run the task under the coordinator
- **THEN** exactly one replica acquires the lock and runs the task
- **AND** the other does not run the task while the holder keeps the lock

#### Scenario: Lease releases on context cancel

- **GIVEN** a replica holding a task lock
- **WHEN** its context is cancelled for a graceful shutdown
- **THEN** it releases the lock
- **AND** a waiting replica acquires it

#### Scenario: Lease releases on replica crash via connection close

- **GIVEN** a replica holding a task lock
- **WHEN** its database connection drops because the process crashed
- **THEN** MySQL releases the lock
- **AND** another replica can acquire it

### Requirement: The processor scales across replicas via SKIP LOCKED

The system SHALL claim event batches for processing with row-level `SELECT ... FOR UPDATE SKIP LOCKED` so the event processor runs
on every replica concurrently, each claiming a disjoint set of unprocessed events, and no event row is claimed by more than one
replica at a time. This is the deliberate counterpart to the leader-gated periodic tasks: throughput-bound event processing scales
horizontally across the replica fleet rather than running on a single elected replica.

#### Scenario: Two replicas claim disjoint event batches

- **GIVEN** unprocessed events in the shared store and two replicas claiming batches concurrently
- **WHEN** both run the SKIP LOCKED claim
- **THEN** each replica receives a batch of events
- **AND** no event appears in both replicas' batches

### Requirement: Sessions and CSRF tokens validate across any replica

A user session and its CSRF token SHALL validate on any replica, not only the one that minted them, because session state lives in
the shared MySQL store rather than in replica memory. A request bearing a valid session cookie SHALL be authenticated on a replica
that did not mint the session, and an unsafe request bearing the session's CSRF token SHALL pass CSRF validation on that replica.
This is what lets the load balancer route a user's requests to any replica without sticky sessions.

#### Scenario: Session minted on replica A validates on replica B

- **GIVEN** a session minted against the shared store
- **WHEN** a request bearing its cookie reaches a replica that did not mint it
- **THEN** that replica authenticates the request from the shared store
- **AND** an equivalent request carrying no session cookie is rejected

#### Scenario: CSRF token from replica A passes on replica B

- **GIVEN** a session and its CSRF token minted against the shared store
- **WHEN** an unsafe request bearing that CSRF token reaches a replica that did not mint it
- **THEN** that replica accepts the CSRF token
- **AND** an equivalent unsafe request carrying no CSRF token is rejected

### Requirement: Schema migrations are safe under rolling upgrade

When several replicas boot concurrently against one database during a rolling upgrade, the system SHALL apply schema migrations
under a database advisory lock so no two replicas run the migration tool against the same database at once. Every replica SHALL
still complete its boot-time apply: the per-context tracking table makes an already-applied corpus a no-op, so a replica that
acquires the lock after another has already applied performs no schema change and boots successfully.

#### Scenario: Goose tracking table lock prevents concurrent apply

- **GIVEN** several replicas booting concurrently and racing to apply the same migration corpus
- **WHEN** they apply under the boot-time migration advisory lock
- **THEN** the applies are serialized so no two run at once
- **AND** every replica completes its apply and boots successfully
