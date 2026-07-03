## Context

The ClickHouse `events` archive (visibility context) stores each event's fields inside a JSON `payload`; only `pid` is materialized today. `NetworkEventsForProcess` reads it FINAL, host+pid+event_type+time-bounded. The `EventArchive` interface has three methods (Insert, NetworkEventsForProcess, EventsByIDs) with a compile-time assertion, so a new query lands on the interface, the ClickHouse store, and the in-memory fake together. PR 1 established the search contract (opaque keyset cursor, `total_matched`, newest-first) and the operator reader-seam pattern.

## Goals / Non-goals

**Goals:**

- Same search contract as PR 1 so the UI (PR 3) treats process/connection/DNS results uniformly.
- Fleet-wide by-IP and by-domain that prune rather than full-scan the archive.
- One archive method covering both classes, parameterized by event type.

**Non-goals:**

- No `has_network` process filter here (deferred from PR 1; a follow-up now that the archive is queryable cross-host).
- No free-text or partial-match on IP/domain in v1 (exact match; the UI pivots pass a concrete value).

## Decisions

- **One `SearchEvents(filter, cursor, limit)` on `EventArchive`, event-type-parameterized.** The connection and DNS queries differ only in which materialized column they match (`remote_address` vs `query_name`); the store maps the event type to the column. Two handler routes (`/connections`, `/dns`) each set the event type, so the URL stays self-describing while the store stays single.
- **Keyset over `(timestamp_ns, event_id)` DESC.** `timestamp_ns` is not unique; `event_id` (a string) breaks ties and is the archive's own tiebreak in its sort key. The cursor is opaque base64url of `timestamp_ns:event_id`, its own codec in the clickhouse package (PR 1's cursor was int64:int64; this one is int64:string).
- **Materialized columns + bloom skip indexes.** `remote_address` and `query_name` are added as `MATERIALIZED JSONExtractString(payload, ...)` with `bloom_filter` skip indexes, exactly the idiom migration 00002 used for `event_id`; `MATERIALIZE COLUMN`/`MATERIALIZE INDEX` backfill existing parts. The search queries the materialized columns (not `JSONExtract` inline) so the skip index can prune. This is the "index as needed" the epic calls for, in ClickHouse's shape.
- **Window over `ingested_at_ns`**, matching `NetworkEventsForProcess`: server-stamped ingest time is clock-drift tolerant and is what the archive's other reads bound on.
- **Reader seam satisfied by the detection MySQL store**, which delegates to `s.archive.SearchEvents`, exactly as it already delegates `GetNetworkEventsForProcess`. This keeps the operator handler's seams uniform (all satisfied by `mysql.Store`) and bootstrap wiring unchanged in shape.

## Risks / Trade-offs

- [`MATERIALIZE COLUMN` on a large archive is a background mutation] -> additive and online; new writes get the value immediately, the backfill catches historical rows. On the pilot's 30-day-TTL archive this is bounded.
- [`total_matched` COUNT over the archive] -> same trade as PR 1; bounded by the exact-match predicate + the time window the UI always sends, and the bloom index prunes it.
- [FINAL on the search read] -> required to collapse ReplacingMergeTree re-deliveries, as every archive read does; the pruned granule set keeps it cheap.
