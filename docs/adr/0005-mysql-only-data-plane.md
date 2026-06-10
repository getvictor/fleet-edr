# 0005. MySQL is the only supported RDBMS for the data plane

- Status: Accepted
- Date: 2026-05-15
- Deciders: getvictor

## Context

The EDR server is a write-heavy + scan-heavy data plane. It persists raw event envelopes from agents (`events`), a derived per-host process graph (`processes`), alerts produced by detection rules (`alerts`), command records issued from the UI (`commands`), session/auth state for the admin UI (`sessions`, `users`, `identities`, `roles`), and an append-only audit log (`audit_events`). The biggest table by row count is `events`; the biggest by row width is `processes` (every exec snapshot plus its parent chain). Hot reads are the unprocessed-event poll (`SELECT ... WHERE NOT processed`) and the UI's per-host process tree. The retention runner deletes old rows on a schedule.

The store layer has settled on a handful of MySQL-specific patterns the hot paths rely on:

- `FOR UPDATE SKIP LOCKED` in `server/detection/internal/mysql/store.go` lets multiple processor workers claim disjoint event batches without blocking each other. The query is idiomatic in MySQL 8 and matches the equivalent PostgreSQL feature in both semantics and syntax; the remaining MySQL coupling lives in the driver flags and error codes below.
- Idempotent `CREATE TABLE IF NOT EXISTS` across `server/<context>/bootstrap/schema.go` makes `ApplySchema` safe to re-run on every process start. There is no migration layer today: the five contexts each own their tables and recreate-if-missing is the whole bootstrap. If/when migrations land, the affordance for duplicate-column / duplicate-index recovery on re-run is MySQL's error-code shape (1060 / 1061 / 1091); the equivalent Postgres path would mean branching on SQLSTATE codes instead. The current code has no such branch yet, so this is a forward-looking cost, not a sunk one.
- `parseTime=true` in the DSN, enforced by `bootstrap.ensureParseTime` for callers that forget it. The driver-flag concept is MySQL-specific; the pgx driver scans timestamps natively.
- Composite indexes tuned for MySQL's query planner shape (`(processed, host_id, timestamp_ns)` and similar), with explicit thinking about index selectivity for MySQL's index-merge optimiser.

The team is small (one full-time maintainer plus AI assistants). Every hour spent supporting a second RDBMS is an hour not spent on detection content, agent reliability, or QA against real customer-shape data. Pilots are macOS-only and Apple-Silicon-only per ADR-0002, so the data plane runs in a controlled set of operator deployments.

Three demands push back on MySQL-only:

1. Some prospective customers run only PostgreSQL in production and treat "another database" as a meaningful operational cost.
2. SIEM / data-lake teams want a Postgres-friendly export pipeline.
3. The "EDR is self-hostable" story (per ADR-0003) wants to accommodate a customer's existing database fleet.

## Decision

The data plane runs on MySQL 8.4 only. There is no abstraction layer over the SQL dialect: stores use raw MySQL features (`FOR UPDATE SKIP LOCKED`, duplicate-error swallowing, `parseTime=true`, the docker-compose `mysql_test` service on port 33307 for integration tests). The reference deployment is the `mysql:8.4` image from the official Docker library, run either as a sidecar container or as a managed service (RDS, CloudSQL, Aurora MySQL-compatible) keyed off `EDR_DSN`.

Customers who require PostgreSQL receive their EDR data via a CDC bridge (Debezium MySQL connector to Kafka, then sink into Postgres / Snowflake / S3 / whatever). The CDC contract becomes the public integration seam; the EDR's primary store stays MySQL.

## Consequences

**Good:**

- One store implementation per bounded context. Adding a new table is one schema file, one set of indexes, one test pass.
- Hot-path tuning happens against one query planner. The `(processed, host_id, timestamp_ns)` composite index, the `FOR UPDATE SKIP LOCKED` claim pattern, and the `parseTime=true` invariant are all MySQL-specific and only have to be right in one place.
- Test infrastructure is single-shape: `testdb/full.Open` against a real MySQL on `127.0.0.1:33307` is the integration-test seam, with parallel schema isolation. No matrix builds across RDBMSes.
- Operators get a predictable upgrade path within MySQL 8.x; the team audits one stream of CVEs and one set of breaking-change notes.
- The `mysql:8.4` image is widely supported on every cloud and on-prem installer the team has tested against, so the deployment surface stays shallow.

**Bad:**

- A customer whose standardised stack is "Postgres only, no exceptions" cannot run the EDR's primary store on their existing infrastructure. The CDC bridge gives them downstream Postgres data but not a Postgres primary; for a subset of buyers this is a deal-killer rather than an acceptable trade-off.
- Postgres-specific operational tooling (pgBouncer, logical replication with native publications, `pg_dump`'s shape) isn't reusable. Operators who have built their on-call rotation around Postgres semantics have to learn the MySQL equivalents (ProxySQL, GTID replication, `mysqldump` + `mysqlbinlog`).
- The in-process idempotent-`ALTER` pattern didn't generalise off MySQL. ADR-0009 has since replaced it with versioned migrations via goose (`goose.DialectMySQL`), MySQL-specific by the same single-store reasoning recorded here; a port off MySQL would also re-target the goose dialect.

## Alternatives considered

**PostgreSQL as the only supported RDBMS.** Plausible from a pure greenfield standpoint: Postgres' `SELECT ... FOR UPDATE SKIP LOCKED` syntax is equivalent, its index features are richer, and its extensibility (JSONB, FTS, custom types) maps onto event-payload work nicely. Rejected because MySQL is already the existing store and the team's operational experience, the docker-compose dev loop, the test seam, and several bounded-context schemas are all already MySQL-shaped. A migration to Postgres would pay a one-time porting cost without delivering a feature customers asked for. Re-evaluate if a future customer mix shifts decisively Postgres-ward and the team's bandwidth for the port appears.

**Dual support (MySQL + PostgreSQL).** Each store-layer file becomes a small dialect branch; the test matrix doubles; every schema change has to be authored, indexed, and tuned against two planners; CI runs two integration suites; the integration-test seam (`testdb/full.Open`) doubles to handle both. Carries a recurring tax for the small team proportional to the size of the store surface, not the number of customers asking for Postgres. The CDC alternative below delivers the read-side Postgres story without paying that tax on every write.

**Embedded SQLite for single-node self-hosted installs.** Attractive for "appliance" deployments and for developer ergonomics (no docker-compose to bring up). Rejected for the data plane because SQLite's writer concurrency model (a single writer at a time, even with WAL) limits the ingest rate well below what a busy host fleet generates, and because the `FOR UPDATE SKIP LOCKED` claim pattern has no SQLite analogue. SQLite is already the agent-side queue (`agent/queue/`), where its single-writer shape is a feature; on the server it's not the right fit.

**Embedded KV store (Badger / Pebble) wrapped by an ORM-style layer.** Attractive in theory for write throughput. Rejected as a category mismatch: the UI queries against the process graph and alerts are relational (join across hosts, filter by severity, aggregate by timestamp), and reimplementing those access patterns on top of an embedded KV would just rebuild a smaller, less-tested RDBMS.

**Debezium-CDC from MySQL as a Postgres replica, then deprecate the MySQL primary.** Order-reversed alternative: ship the Postgres primary, deprecate MySQL. Same porting cost as "PostgreSQL as the only supported RDBMS" plus the operational risk of the inversion. Not worth doing unless the customer mix forces it.

## References

- [`best-practices.md`](../best-practices.md) §10 (the original `[-] will not do` entry that this ADR consolidates).
- `server/bootstrap/db.go` (DSN handling, `parseTime=true` enforcement).
- `server/detection/internal/mysql/store.go` (the `FOR UPDATE SKIP LOCKED` claim pattern).
- `server/<context>/bootstrap/schema.go` files (the `CREATE TABLE IF NOT EXISTS` + duplicate-error-swallowing pattern, per bounded context).
- `docker-compose.yml` (`mysql:8.4` dev + `mysql_test` test service).
- [Issue #145](https://github.com/getvictor/fleet-edr/issues/145) (ADR audit gap that flagged this decision as worth recording).
- [Issue #115](https://github.com/getvictor/fleet-edr/issues/115) (future versioned-migrations work that will land on top of this ADR).
- [Debezium MySQL connector](https://debezium.io/documentation/reference/stable/connectors/mysql.html) (the recommended CDC bridge for downstream Postgres / data-lake consumers).
