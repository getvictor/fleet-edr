# 0015. ClickHouse event store in a new `visibility` bounded context

- Status: Proposed
- Date: 2026-06-25
- Deciders: getvictor

This proposes to narrow [0005](0005-mysql-only-data-plane.md) (the raw `events` archive leaves MySQL) and to amend [0004](0004-modular-monolith-bounded-contexts.md) (a seventh context, `visibility`, carved out of `detection`; `observability` was the sixth).

## Context

This narrows [0005](0005-mysql-only-data-plane.md). MySQL remains the sole RDBMS for the control plane and the derived process graph; only the raw event archive moves.

The `events` table is the largest table in the data plane and the one that does not scale. On the Render pilot it grows on the order of GB/day and is append-mostly: B-tree write amplification, secondary-index overhead (#408 measured index bytes exceeding data bytes), and row-store scan cost all work against it. The v0.5.0 hunting epic (#415: process search with cursor pagination and sort, events-over-time histograms, server-side sibling aggregation, tree virtualization) is query-heavy over exactly this data. Building those analytics on MySQL and re-building them on a columnar store later is wasted work; the store decision has to come first (#427).

The `events` table also conflates two incompatible roles:

1. **A durable work queue.** A `processed` state machine (0 unclaimed, 2 claimed, 1 done) claimed by every replica via `SELECT ... FOR UPDATE SKIP LOCKED` ([0011](0011-ha-architecture.md)), ordered per host for causal correctness. Low-latency, mutable, transactional, multi-replica-coordinated.
2. **An event archive.** The append-mostly JSON firehose, read for UI process-detail correlation and (soon) hunting, swept by a retention `DELETE`.

A columnar store is excellent at role 2 and cannot do role 1: ClickHouse has no row-level locks, no efficient point `UPDATE`, no `SKIP LOCKED` claim. Any move of the archive must split these two roles apart.

The forces:

- **Every top-tier EDR/XDR backend is a streaming pipeline, not a polled database.** Agent → durable log (Kafka/Kinesis/PubSub) → stream detection → columnar lake. CrowdStrike's Threat Graph, Microsoft Defender's Advanced Hunting (backed by Kusto/Azure Data Explorer, a columnar MPP store architecturally close to ClickHouse, queried by scheduled KQL), SentinelOne's Singularity Data Lake (columnar), and Elastic Security (hot→frozen tiers on object storage) all share this shape. The defining element is the **durable log between ingest and detection**: it gives replay (backfill a new rule), backpressure isolation (ingest spikes do not stall detection), and lock-free consumer-group scaling.
- **Those architectures assume a cloud the vendor operates.** This product is self-hosted, single-VM, 10-500 endpoints, Jamf-Pro-style ([0002](0002-macos-apple-silicon-mvp-only.md), [0003](0003-standalone-product-not-fleet-integrated.md)). A pilot customer will not operate a Kafka cluster, a stream-processing job, and a ClickHouse cluster on a VM. Copying the hyperscale stack wholesale is the wrong instinct here.
- **The app tier is stateless ([0010](0010-stateless-server.md)) and multi-replica ([0011](0011-ha-architecture.md)).** Whatever replaces the events table as the work queue must preserve lock-free, idempotent, per-host-ordered work distribution across replicas.
- The team is small. Operating two datastores is a real, recurring cost.
- **The `detection` context (ADR-0004) is overloaded.** It carries three subdomains: visibility (ingestion, the event store, the process graph, the host/tree/process-detail reads), detection proper (the engine + pipeline that applies `rules` and produces `alerts`), and the operator surface for both. Two seams already exist in the code without a context to name them: separate `fleet-edr-ingest` and `fleet-edr-server` binaries mount the same `IngestHandler` under different middleware, and the `rules` context already consumes `detection/api` (`GraphReader`) as a published read surface. Endpoint visibility is a coherent subdomain distinct from detection (the industry "visibility/Insight" vs "Detections" split); the v0.5.0 hunting epic is a visibility consumer, not a detection feature.

## Decision

Adopt the streaming-pipeline **shape**, choose components that collapse to a single binary at small scale, and keep the seams as interfaces so growth is additive rather than a rewrite. Concretely:

1. **ClickHouse is the event lake.** The raw event archive (today's `events` payloads) lives only in ClickHouse: `ReplacingMergeTree(ingested_at_ns)` for dedup, time-partitioned, sorting key `(host_id, event_type, timestamp_ns, event_id)` (the leading `(host_id, event_type, time)` prefix serves per-process correlation; the trailing `event_id` makes the key unique so an at-least-once re-delivery of the same immutable event collapses on merge to the latest-ingested version), native TTL for retention, the native `JSON` payload type plus typed columns for the hot fields detections filter on (host, pid, ppid, event_type, signing identity, hashes, remote address). A tiered storage policy (hot local disk to an S3 cold volume) is designed in from the start, disabled by default at pilot scale.

2. **Ingest and detection are decoupled by an `EventLog` interface** (`Append`, `Claim`, `Ack`, per-host ordering, idempotent by `event_id`). The first implementation is a small, ephemeral MySQL `event_queue` table that preserves the exact `FOR UPDATE SKIP LOCKED` claim of [0011](0011-ha-architecture.md). When scale demands it (ingest backing up detection, rule replay/backfill, a single ClickHouse node insufficient), the implementation is swapped for **Redpanda** (Kafka API, single binary, no ZooKeeper/JVM) partitioned by `host_id`. Detection code does not change across that swap.

3. **Writes to ClickHouse are batched, never synchronous per request.** At pilot scale this is ClickHouse `async_insert` (server-side batching). At scale it becomes a log-consumer batch writer (or ClickHouse's Kafka engine / ClickPipes). Same `EventArchive` interface either way.

4. **MySQL retains the process graph and the entire control plane.** `processes` is derived, mutable state (exec/exit updates, re-exec chains walked by recursive CTE, TTL reconciliation, FK target for alerts) and stays OLTP. `alerts`, `alert_events`, `hosts`, and the identity/endpoint/rules/response contexts are unchanged. Alert evidence is made self-contained by copying the linked event payloads into MySQL at alert-creation time, so retention of the lake never depends on a cross-store foreign key.

5. **Detection is two tiers.** Real-time stream rules over the `EventLog` (today's pipeline) and, in v0.5.0, scheduled/retro hunting expressed as queries over the ClickHouse lake (the Advanced-Hunting model). The rules engine is designed so the second tier is a query executor, not a second detection runtime.

6. **A new `visibility` bounded context owns ingestion and the event store**, carved out of `detection`. The `EventLog` and `EventArchive` interfaces are its `visibility/api` published language (the same artifacts the ClickHouse work introduces, so the boundary costs almost nothing to draw now). `detection` becomes a consumer: its pipeline `Claim`s from `visibility`'s `EventLog` and reads the archive for correlation, exactly as `rules` already consumes `detection/api`. The extraction is **staged** to avoid a big-bang refactor on top of the store swap: in v0.4.0 only ingestion (`intake/`, and the `fleet-edr-ingest` binary's wiring) and the event store move to `visibility`; the process graph, the detection pipeline, the operator reads (host list, process tree, process detail), and `alerts` stay in `detection`. The process graph and the operator + hunting reads move to `visibility` later, with the v0.5.0 hunting epic, when the pipeline is split into a visibility materialization stage and a detection evaluation stage.

The first increment (v0.4.0, #427) is a hard switch with **no data migration**: new and re-provisioned deployments start on ClickHouse; existing pilot event history is discarded (alerts and their linked evidence survive in MySQL). We do not build a dual-write cutover or a backfill.

## Consequences

**Good:**

- The firehose lands in a store built for it: columnar compression and time-partitioned scans replace B-tree write amplification and index bloat (#408). Retention becomes native TTL instead of a batched `DELETE` job.
- The v0.5.0 hunting epic is built once, on the right engine, and as queries rather than bespoke endpoints.
- The ingest/detection decoupling is correct from day one. The single highest-leverage, lowest-cost decision, putting the queue behind an `EventLog` interface, makes the eventual move to a real log additive. The path from pilot-on-a-VM to scale is incremental at every step.
- The `FOR UPDATE SKIP LOCKED` claim ([0011](0011-ha-architecture.md)) and the existing `event_id` idempotency (`INSERT IGNORE`) carry forward unchanged; the current design is already log-architecture-ready in its dedup primitive.
- Detection latency-sensitive work (graph build, real-time rules) stays in MySQL where it is proven; only the high-volume archive and the analytic reads move.
- The `visibility` context gives ingestion and the event store a named owner with its own datastore and lifecycle, draws the boundary at the moment its published language is being created anyway, and gives the v0.5.0 hunting epic a home. The existing `fleet-edr-ingest` binary becomes the visibility context's wiring, making a split that already exists coherent.

**Bad:**

- Two datastores to operate: backups, upgrades, health checks, and the single-VM footprint all grow. ClickHouse is a new operational competency for the team and for self-hosting customers. This is the direct cost of the decision and it is borne even at pilot scale, where the disk-growth problem it solves is not yet acute.
- A second consistency boundary. Events are in ClickHouse, the graph and alerts are in MySQL; a read that needs both (process detail with its network connections) now spans stores. Mitigated by keeping correlation reads background and self-containing alert evidence, but it is new surface for bugs.
- UI-synchronous reads (process-detail network/DNS table) now hit ClickHouse; cold-partition reads can spike. Must be validated under the #203 500-agent load before #427 closes.
- The hard switch discards pilot event history. Acceptable because alerts and their evidence survive, but it is a real loss and must be communicated to any pilot operator.
- This narrows [0005](0005-mysql-only-data-plane.md) within a year of its acceptance. The "one store" simplicity that ADR bought is partially spent.
- A seventh bounded context is added (amending [0004](0004-modular-monolith-bounded-contexts.md); `observability` was the sixth): more `api/` packages, a new arch-go block, and a `rules` dependency on `visibility.api`. Staging the extraction leaves a transitional state where the process graph and the event store sit in different contexts, so `detection`'s `GraphReader` splits (process reads stay, the network/DNS event read moves to `visibility.api`) and the eventual `alerts.process_id -> processes.id` cross-context reference must move to app-level enforcement (precedent: `alerts.updated_by -> users` already has no FK, enforced by a `UserExists` closure).

## Alternatives considered

**Keep MySQL-only and tune harder ([0005](0005-mysql-only-data-plane.md)).** Attractive for operational simplicity: one store, one query planner, one test seam. #408 already harvested the cheap wins (drop heartbeat rows, coalesce network/DNS, index diet). Rejected because the remaining growth is structural to a row store on an append-mostly firehose, and because building v0.5.0 hunting analytics on MySQL would be thrown away. The disk-growth and query-shape forces are real and not tunable away.

**Introduce Kafka/Redpanda and stream processing now.** This is the genuinely best-practice hyperscale shape. Rejected as premature for a 10-500 endpoint, single-VM product: it saddles a pilot operator with a message bus and stream-processing runtime for a load a MySQL queue handles comfortably. We adopt the shape (the `EventLog` interface) without the component, and name the explicit triggers for introducing Redpanda later. Re-evaluate when ingest backs up detection, rule replay is needed, or one ClickHouse node is insufficient.

**Elasticsearch / OpenSearch.** Elastic Security's choice; excellent full-text and a mature security ecosystem. Rejected for the primary event store on cost-per-GB and operational weight (JVM, shard management) versus ClickHouse for an append-mostly, time-series-shaped workload where full-text search is not the primary access pattern.

**Apache Druid / Apache Pinot.** Real-time OLAP with sub-second queries and native streaming ingestion, used by some security/observability vendors. Rejected as more operationally complex to self-host than ClickHouse for no benefit at this scale; ClickHouse single-node → cluster is a gentler growth curve.

**Lakehouse: OCSF-normalized Parquet + Iceberg on object storage, queried by DuckDB/Trino.** The emerging "security data lake" / BYO-lake pattern (Amazon Security Lake). Strong for interop and decoupled storage/compute at very large scale. Rejected for now as too much moving infrastructure for a self-hosted VM, but kept as the likely long-term direction for the _export/interop_ seam; aligning the wire schema toward OCSF over time keeps that door open.

**Keep the work queue in ClickHouse too (single store for events).** The tidiest on paper: one events store. Impossible in practice: ClickHouse cannot do the `FOR UPDATE SKIP LOCKED` per-row claim ([0011](0011-ha-architecture.md)) the multi-replica processor depends on. This is the constraint that forces the two-role split and the `EventLog` seam.

**Keep everything in the `detection` context (ClickHouse as an internal infrastructure detail).** Lowest churn: `internal/clickhouse` and `internal/eventlog` packages, no new `api/` surface, no arch-go change. Rejected because it perpetuates the overloaded `detection` context and leaves the v0.5.0 hunting epic without a home, forcing more analytic surface onto a context that is already three subdomains in one. The `EventLog`/`EventArchive` interfaces are being created either way; placing them on a context boundary now is nearly free, whereas extracting the boundary after code accretes inside `detection/internal` is expensive.

**Extract the full visibility subdomain now (process graph + operator reads + hunting, not just ingestion + store).** The cleanest long-term alignment: `detection` would shrink to the engine + alerts. Rejected for v0.4.0 because it forces a pipeline re-architecture (splitting the single claim/build/evaluate loop into a visibility materialization stage and a detection evaluation stage) and the `alerts -> processes` FK rework on top of the store swap. Staged instead: draw the boundary at ingestion + store now, move the graph and operator reads with the v0.5.0 hunting epic that touches them anyway.

**Model the process graph in ClickHouse via `ReplacingMergeTree` (last-state-wins).** Would let the graph share the columnar store. Rejected because the graph's recursive re-exec chain walk and its transactional exit/reexec updates and FK-to-alerts are OLTP-shaped; collapsing mutable state on background merges fights the access pattern. The graph is small relative to the raw firehose, so the cost of leaving it in MySQL is low.

## References

- [Issue #427](https://github.com/getvictor/fleet-edr/issues/427) (migrate the event store to ClickHouse).
- [Issue #408](https://github.com/getvictor/fleet-edr/issues/408) (disk-growth reduction + ClickHouse evaluation; the cheap wins landed, the evaluation concluded here).
- [Issue #415](https://github.com/getvictor/fleet-edr/issues/415) (v0.5.0 hunting epic that this store decision sequences before).
- [Issue #203](https://github.com/getvictor/fleet-edr/issues/203) (500-agent scale harness; the acceptance gate for #427).
- [0004](0004-modular-monolith-bounded-contexts.md) (bounded contexts this amends with `visibility`), [0005](0005-mysql-only-data-plane.md) (the MySQL-only decision this narrows), [0010](0010-stateless-server.md) (stateless server), [0011](0011-ha-architecture.md) (multi-replica `SKIP LOCKED` claim preserved by the MySQL `event_queue`), [0009](0009-migrations-via-goose.md) (goose, whose v3 ClickHouse dialect carries the lake migrations).
- The OpenSpec change `clickhouse-event-store` (`openspec/changes/clickhouse-event-store/`): the proposal, design (with the phased PR breakdown), and spec deltas.
- ClickHouse native `JSON` type, `MergeTree` TTL, tiered storage policies (hot/cold S3 volumes), `async_insert`, Kafka table engine / ClickPipes.
