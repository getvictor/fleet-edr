# Events index and primary-key diet

## Why

On the `events` table, index storage exceeds row data (issue #408 diagnostics: 0.79 GB index vs 0.52 GB data). Two structural causes:

- **The primary key is a 36-character UUID string** (`event_id VARCHAR(255)`, agent-emitted `UUID().uuidString`). InnoDB copies the primary key into every secondary index leaf, so each of the table's secondary indexes carries ~36 bytes of UUID per row on top of its own key columns.
- **Two secondary indexes are redundant.** `idx_events_host_id (host_id)` is a strict left-prefix of `idx_events_host_type_ingested (host_id, event_type, ingested_at_ns)`, and `idx_events_type (event_type)` is matched by no query in the codebase (every event-type predicate is anchored by `host_id` and served by a composite). Both consume write + storage cost for no read benefit.

## What changes

- **Drop the two redundant secondary indexes** (`idx_events_host_id`, `idx_events_type`). Verified against the codebase: no query filters on `host_id` alone that the composite cannot serve via its left prefix, and no query filters on `event_type` without a leading `host_id`.
- **Replace the UUID primary key with a compact surrogate.** `events` gains a `BIGINT AUTO_INCREMENT` surrogate primary key (`id`); `event_id` is retained as a `UNIQUE KEY`. `event_id` stays the logical unique identity on the wire and in every query, so the change is invisible to callers:
  - `INSERT IGNORE` still dedups on the `event_id` unique constraint (the idempotent-submission contract is unchanged).
  - The `alert_events.event_id` foreign key still references `events(event_id)` (a FK may target a unique key, not only the primary key).
  - Every query that selects, joins, or filters on `event_id` as a string is unchanged.
  - Each secondary index leaf now carries the 8-byte surrogate instead of the 36-byte UUID.

## Migration cost

Swapping the primary key rebuilds the table (InnoDB cannot change the clustered key in place). On a large existing `events` table this is a one-time, write-blocking rebuild that operators SHOULD run in a maintenance window; on a fresh install it is free. The two index drops are online (`ALGORITHM=INPLACE`). Migrations are forward-only (ADR-0009); the down steps are no-ops. The diet is most effective measured against the reduced row set produced by the heartbeat-drop and network/DNS-coalescing changes, so it lands alongside them.

### Not in this change

- Narrowing `host_id` (a real query dimension carried by the composites; out of scope).
- Heartbeat drop and network/DNS coalescing (separate changes).
- The ClickHouse evaluation (deferred; to be decided against post-change numbers).
