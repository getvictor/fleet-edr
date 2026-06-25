## Context

The full decision record, with alternatives, is ADR-0015 (`docs/adr/0015-clickhouse-visibility-store.md`). This document is the implementation-facing summary; the phased PR breakdown lives in the Migration Plan below.

Today the MySQL `events` table does two incompatible jobs: a durable work queue (a `processed` state machine claimed by every replica via `FOR UPDATE SKIP LOCKED`, ADR-0011) and an append-mostly telemetry archive (read for correlation and, soon, hunting, swept by a retention `DELETE`). A columnar store handles the archive well and cannot do the lock-claimed queue at all. The change splits those two roles.

Constraints: the server is stateless (ADR-0010) and multi-replica (ADR-0011); the product is self-hosted, single-VM, 10-500 endpoints (ADR-0002/0003), so the design adopts the streaming-pipeline shape with components that collapse to a single binary at small scale.

Target architecture (this increment delivers the v0.4.0 row; later rows are the same seams with heavier implementations):

```text
Agent (mTLS, batched, gzip)
   |
   v
Ingest API  (stateless, multi-replica; ADR-0010/0011)
   |   validate -> fan out; ack 200 only after BOTH writes below succeed
   +--> EventArchive interface -> ClickHouse event lake   (v0.4.0: async_insert at ingest)
   +--> EventLog interface  { Append, Claim, Ack; per-host order; idempotent by event_id }
   |       v0.4.0  : MySQL event_queue  (FOR UPDATE SKIP LOCKED, ADR-0011 verbatim)
   |       at scale: Redpanda topic, partitioned by host_id   (swap a driver, not the callers)
   v
Detection consumers  (claim from EventLog; idempotent, per-host ordered)
   |   - maintain process graph     -> MySQL processes  (OLTP: mutation, recursion, FK)
   |   - real-time rules -> alerts    -> MySQL  (+ copy triggering-event payloads as evidence)
   v
ClickHouse event lake   (MergeTree; native JSON + typed hot columns; native TTL; hot disk -> S3 cold tier)
   v
Hunting / retro-detection / investigation = queries   (v0.5.0+)

At scale the archive write migrates from the ingest fan-out to a log consumer
(ClickHouse Kafka engine / batch writer); the EventArchive interface is unchanged.

Control plane (identity, endpoint, rules, response, detection) = MySQL, unchanged
```

## Goals / Non-Goals

**Goals:**

- Move the high-volume event archive off MySQL onto a columnar store that scales with the firehose and serves v0.5.0 hunting as queries.
- Preserve the `POST /api/events` wire contract, the event envelope schema, the agent protocol, and the host token unchanged.
- Preserve the multi-replica, lock-free, per-host-ordered, at-least-once, idempotent processing claim (ADR-0011).
- Draw the `visibility` context boundary at the moment its published interfaces (`EventLog`, `EventArchive`) are created.

**Non-Goals:**

- No data migration or dual-write cutover. Pre-upgrade event history is discarded (hard switch).
- No message bus (Redpanda/Kafka) or stream-processing runtime in this increment; the `EventLog` interface keeps that additive later.
- No move of the process graph, the detection pipeline, the visibility reads, or `alerts` out of `detection` yet (staged to the v0.5.0 hunting epic).
- No change to detection rule semantics or alert dedup.

## Decisions

- **ClickHouse is the event archive.** `MergeTree`, time-partitioned, native `JSON` payload plus typed columns for the hot fields (host, pid, ppid, event_type). The sorting key leads with `(host_id, event_type, timestamp_ns)` to serve per-process correlation and ends with `event_id` so each event is a distinct key. Dedup uses `ReplacingMergeTree(ingested_at_ns)`: rows that share the full sorting key (the same immutable event re-delivered) collapse on merge to the latest-ingested version, so at-least-once delivery never surfaces a duplicate, while two genuinely different events never collide. Reads that must not double-count pre-merge use `FINAL` or dedup-aware aggregation. Native TTL replaces the retention `DELETE`; a hot-disk to S3 cold-tier storage policy is designed in, disabled at pilot. Rationale and alternatives (Elasticsearch, Druid/Pinot, lakehouse): ADR-0015. Schema sketch:

  ```sql
  CREATE TABLE events (
    event_id        String,
    host_id         LowCardinality(String),
    timestamp_ns    Int64,
    ingested_at_ns  Int64,
    event_type      LowCardinality(String),
    pid             Int64,                         -- typed hot columns extracted at ingest
    ppid            Int64,
    payload         JSON,                          -- native JSON for the long tail
    ingested_date   Date MATERIALIZED toDate(ingested_at_ns / 1000000000),  -- ns -> s -> Date
    INDEX idx_event_id event_id TYPE bloom_filter GRANULARITY 4
  )
  ENGINE = ReplacingMergeTree(ingested_at_ns)      -- ingested_at_ns = version; latest re-delivery wins on merge
  PARTITION BY toYYYYMM(ingested_date)
  ORDER BY (host_id, event_type, timestamp_ns, event_id)  -- event_id makes the key unique per event
  TTL ingested_date + INTERVAL 30 DAY;             -- + storage policy: hot disk -> S3 cold (disabled at pilot)
  ```

  The correlation read filters a host's events by `event_type` and a time window; whether it keys on `timestamp_ns` or the server-stamped `ingested_at_ns` (today's `GetNetworkEventsForProcess` uses the latter for clock-drift tolerance) is settled at implementation and validated under the #203 load.

- **`EventLog` interface decouples ingest from processing.** `Append` (ingest), `Claim`/`Ack` (processor), per-host ordering, idempotent by `event_id`. v0.4.0 implementation is an ephemeral MySQL `event_queue` carrying the same `FOR UPDATE SKIP LOCKED` claim; the future Redpanda implementation (Kafka API, single binary, no ZooKeeper/JVM, partitioned by `host_id`) is additive and changes no caller. Triggers to introduce Redpanda later: ingest backing up detection, rule replay/backfill needed, or a single ClickHouse node insufficient. Queue rows are deleted after `Ack` plus a short safety expiry, so the queue holds only the in-flight working set.
- **`EventArchive` interface is the lake writer/reader.** Writes are batched, never synchronous-per-request: `async_insert` with `wait_for_async_insert=1` at pilot scale (the 200 OK still waits for the flush ack), a log-consumer batch writer at scale. Reads serve correlation and hunting.
- **Self-contained alert evidence.** At alert creation the triggering events' payloads are copied into a MySQL `alert_event_payloads` table keyed by `(alert_id, event_id)`. This removes the cross-store dependency that the old `alert_events -> events` foreign key provided, so archive TTL never orphans alert evidence. Alerts are rare; the payloads are the evidence.
- **Goose carries ClickHouse migrations.** goose v3 already supports the ClickHouse dialect; `server/migrations/runner` gains that path and a `migrations-clickhouse/` embedded dir, applied at bootstrap alongside the MySQL migrations.
- **Staged context extraction.** v0.4.0 moves only ingestion and the event store into `visibility`; `detection` consumes `visibility/api`. The process graph and visibility reads move later (ADR-0015 #6).

## Risks / Trade-offs

- **Two datastores to operate** → documented as an ADR-0015 consequence; ClickHouse ships in the single-VM compose and deployment docs; healthchecks and backups extended.
- **Synchronous archive insert durability** → `wait_for_async_insert=1` waits for the flush ack before acknowledging the batch; validated against the #203 chaos (no-event-loss) tests. At scale the durability concern moves to the log.
- **UI-synchronous reads now hit ClickHouse** (process-detail network/DNS) → validate p99 under the #203 500-agent load; the ordering key keeps these reads index-served. Cold-partition spikes are the watch item.
- **At-least-once duplicates before merge** → `ReplacingMergeTree` collapses re-deliveries that share the sorting key (which includes `event_id`) to the latest-ingested version; reads that must not double-count use `FINAL` or dedup-aware aggregation.
- **Hard switch discards pilot history** → acceptable because alerts and self-contained evidence survive; communicated as a release note.

## Migration Plan

Phased PRs:

1. ADR-0015 + this proposal (decision gate, no code).
2. Interfaces + infra: `EventLog`/`EventArchive` in `visibility/api`, docker-compose ClickHouse, goose ClickHouse dialect, bootstrap wiring (connection opened, unused). No behavior change.
3. Functional hard switch: ClickHouse archive, `event_queue`, intake fans out to both, processor reads the queue, MySQL `events` dropped.
4. Reads + retention: correlation + process-detail reads to the archive, retention to TTL, `alert_event_payloads`.
5. Acceptance: re-run the #203 500-agent baseline against ClickHouse; record disk/compression and ingest/UI p99; close #427.

**Rollback:** agents, the events schema, and the host token are untouched, so no agent rollback. Reverting the server before the switch ships is a redeploy of the prior binary; after the switch, rolling back to a MySQL-only server loses the ClickHouse-resident event history (alerts and evidence persist in MySQL). The #203 acceptance gate must pass before phase 3 merges.

## Open Questions

- Single-node ClickHouse footprint and resource sizing for the single-VM deployment (settled by the #203 run).
- Exact retention window default and whether the S3 cold tier ships enabled for any topology in this increment (default: disabled).
