# Events index diet

## Why

On the `events` table, index storage exceeds row data (issue #408 diagnostics: 0.79 GB index vs 0.52 GB data). Two secondary indexes are pure waste:

- `idx_events_host_id (host_id)` is a strict left-prefix of `idx_events_host_type_ingested (host_id, event_type, ingested_at_ns)`, so any `host_id`-only lookup is already served by the composite.
- `idx_events_type (event_type)` is matched by no query in the codebase: every event-type predicate is anchored by a leading `host_id` and served by a composite, so a standalone `event_type` index is never chosen.

## What changes

- **Drop the two redundant secondary indexes** (`idx_events_host_id`, `idx_events_type`). Verified against the codebase: no query filters on `host_id` alone that the composite cannot serve via its left prefix, and no query filters on `event_type` without a leading `host_id`. The drops are online (`ALGORITHM=INPLACE`) and do not rebuild the table.

## Primary-key swap: evaluated and dropped

Issue #408 also proposed narrowing the `event_id` primary key (a 36-char UUID, copied into every secondary index leaf) to a compact `BIGINT AUTO_INCREMENT` surrogate. This was implemented and then reverted: with a surrogate primary key, the multi-replica processor's claim query (`FetchUnprocessed`: `WHERE processed=0 ORDER BY host_id, timestamp_ns LIMIT N FOR UPDATE SKIP LOCKED`) regressed into **deterministic deadlocks** under concurrent claimers (measured 20/20 deadlocks vs 0/20 with the `event_id` primary key). The optimizer also began mis-costing a full-scan + filesort over the order-providing `idx_events_processed` once the clustered row shrank. The `SKIP LOCKED` disjoint-claim property (ADR-0011, server-availability) is load-bearing, so `event_id` stays the primary key. The per-row index-leaf saving was not worth destabilizing the hottest claim path; the bigger disk levers are the row-count reductions from the heartbeat-drop and network/DNS-coalescing changes.

### Not in this change

- Any primary-key change (evaluated and dropped, above).
- Heartbeat drop and network/DNS coalescing (separate changes).
- The ClickHouse evaluation (deferred; to be decided against post-change numbers).
