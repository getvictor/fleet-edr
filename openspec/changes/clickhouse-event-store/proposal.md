## Why

The `events` table is the largest table in the data plane and the one that does not scale: on the Render pilot it grows on the order of GB/day, append-mostly, and MySQL's B-tree write amplification plus secondary-index overhead (#408 measured index bytes exceeding data bytes) work against it. The v0.5.0 hunting epic (#415) is query-heavy over exactly this data, so the store decision must come first or the analytics get built twice. ClickHouse is the industry-standard columnar store for high-volume security telemetry. See ADR-0015 (`docs/adr/0015-clickhouse-visibility-store.md`) for the full decision and alternatives.

This is the phase-1 decision-gate proposal. It records the target behavior; the implementation lands in later PRs that reference these scenarios.

## What Changes

- **Raw events are durably persisted to a ClickHouse event archive instead of the MySQL `events` table.** The archive is append-mostly, columnar, time-partitioned, and aged out by native time-based expiry (TTL) rather than an explicit per-row `DELETE` sweep.
- **Ingest and processing are decoupled by a separate work queue (the `EventLog`).** Ingestion writes each batch to the archive and enqueues it on an ephemeral MySQL `event_queue`; the processor claims work from the queue (the existing multi-replica lock-free claim, ADR-0011, preserved), not from the archive. Queue entries are removed after processing, so the queue holds only the in-flight working set.
- **Alert evidence becomes self-contained.** When an alert is created, the triggering events' payloads are copied into durable alert-scoped storage in MySQL, so an alert's evidence survives independently of the archive's retention window and never depends on a cross-store foreign key.
- **BREAKING (operational, one-time): hard switch with no data migration.** On upgrade, pre-upgrade event history is discarded; the MySQL `events` table is dropped. Alerts and their now self-contained evidence survive in MySQL. There is no dual-write cutover or backfill.
- **Unchanged:** the `POST /api/events` wire contract, the event envelope schema (`schema/events.json`), the agent protocol, and the persisted host token. The process graph stays in MySQL. Process-detail network/DNS correlation and rule cross-stream correlation read the same data from the archive; their observable results are unchanged.

This work also extracts a new `visibility` bounded context that owns ingestion and the event store (ADR-0015, amending ADR-0004). That is a code-organization change with no spec-level behavior of its own, so it carries no capability delta here; the behavioral deltas below are store-and-context-neutral.

## Capabilities

### New Capabilities

<!-- None. The `visibility` bounded context reorganizes ownership of existing behavior; it introduces no new capability spec. -->

### Modified Capabilities

- `server-event-ingestion`: persistence target, the decoupled work queue, multi-replica durability, idempotency under at-least-once delivery, and event retention all change; the MySQL-`events` index-diet requirement is removed because that table is dropped; a durable-archive-with-TTL requirement is added.
- `server-detection-rules-engine`: a new requirement that an alert's evidence is self-contained and survives the event archive's retention window.

## Impact

- **Affected specs:** `server-event-ingestion` (4 modified, 1 removed, 1 added requirement), `server-detection-rules-engine` (1 added requirement).
- **Affected code:** new `server/visibility/` context (ingestion + `internal/clickhouse` event archive + `internal/eventlog` MySQL queue + `api/` with the `EventLog`/`EventArchive` published interfaces); `server/detection` becomes a consumer of `visibility/api` (its pipeline claims from the queue; the `GetNetworkEventsForProcess` read moves to `visibility/api`); new MySQL migrations (`event_queue`, `alert_event_payloads`, drop `events`); new embedded ClickHouse migrations; `server/migrations/runner` gains the goose ClickHouse dialect; `docker-compose.yml` gains a ClickHouse service; `go.mod` promotes `clickhouse-go/v2` to a direct dependency.
- **Dependencies / ops:** a ClickHouse instance is added to the single-VM and multi-replica deployment topologies (a new operational competency; ADR-0015 consequence). New config `EDR_CLICKHOUSE_DSN` (+ test DSN).
- **Preserved invariants:** ADR-0010 (stateless server), ADR-0011 (multi-replica lock-free claim, now on `event_queue`), the `POST /api/events` contract, and `schema/events.json`.
- **Rollback:** the agent protocol, events schema, and host token are untouched, so agents need no rollback. Reverting the server is a redeploy of the prior binary plus restoring the MySQL `events` schema; because the switch discards pre-switch event history and writes the archive only to ClickHouse, event history accumulated on ClickHouse is not visible to a rolled-back MySQL-only server (alerts and evidence remain intact). The acceptance gate (#203 500-agent run) must pass before the switch ships.
