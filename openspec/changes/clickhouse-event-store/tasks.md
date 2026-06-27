## 1. Decision gate (this PR, no implementation code)

- [x] 1.1 ADR-0015 accepted (`docs/adr/0015-clickhouse-visibility-store.md`); amends ADR-0004, narrows ADR-0005
- [x] 1.2 This proposal, design, and spec deltas pass `openspec validate clickhouse-event-store --strict`
- [ ] 1.3 Run the #203 500-agent MySQL baseline (`task uat:scale -- --hosts=500`) and record the numbers ADR-0015 cites

## 2. Interfaces and infrastructure (no behavior change)

- [x] 2.1 Define `EventLog` (`Append`/`Claim`/`Ack`, per-host order, idempotent by `event_id`) and `EventArchive` (`Insert`, correlation/hunting reads) in a new `server/visibility/api`
- [x] 2.2 Add `clickhouse` + `clickhouse_test` services to `docker-compose.yml` (digest-pinned, healthcheck, volume); `task db:up` brings them up
- [x] 2.3 Promote `github.com/ClickHouse/clickhouse-go/v2` to a direct dependency in `go.mod`
- [x] 2.4 Add the goose ClickHouse dialect path to `server/migrations/runner` and an embedded `migrations-clickhouse/` dir
- [x] 2.5 Add `EDR_CLICKHOUSE_DSN` (+ test DSN) config; bootstrap opens the ClickHouse connection (unused this phase)

## 3. Functional hard switch (events move to ClickHouse)

- [~] 3.1 Create the `visibility` context: the context, its bootstrap, and both stores exist and are wired into `fleet-edr-server` + `fleet-edr-ingest`; intake fans out to them. The `intake/` package physically stays under `detection/internal/intake` (fed the visibility stores via bootstrap deps) rather than being relocated, to keep the cutover diff bounded; a later refactor can move it.
- [x] 3.2 ClickHouse `events` archive: `ReplacingMergeTree(ingested_at_ns)`, ordering key `(host_id, event_type, timestamp_ns, event_id)` (event_id makes the key unique so re-deliveries dedup to the latest version), `ingested_date` via `toDate(ingested_at_ns / 1000000000)`, native `JSON` payload + typed `pid`/`ppid`, TTL; storage policy hot-disk to S3 cold tier (disabled by default)
- [x] 3.3 MySQL migration: `event_queue` (`event_id` PK, claim index `(processed, host_id, timestamp_ns)`); drop the `events` table
- [~] 3.4 Ingest fans out to `EventArchive.Insert` + `EventLog.Append`, archive first, 200 only after both succeed. The archive insert uses a synchronous native batch (one prepared INSERT, one committed block); the `async_insert` / `wait_for_async_insert=1` throughput optimization is deferred to the #203 acceptance pass, where it is tuned against real ingest p99.
- [x] 3.5 Processor claims from `EventLog` (`event_queue`); the ADR-0011 `FOR UPDATE SKIP LOCKED` claim is unchanged; entries removed after processing
- [x] 3.6 arch-go: add the `**.visibility.internal.**` block; `rules.internal` and `detection.internal` gain a `visibility.api` allowance

## 4. Reads, retention, and self-contained alert evidence

- [x] 4.1 `GetNetworkEventsForProcess` correlation read moves to `visibility/api` (ClickHouse archive); process reads stay in `detection`
- [x] 4.2 Process-detail network/DNS UI read serves from the archive
- [x] 4.3 Event retention switches to ClickHouse native TTL; remove the events `DELETE` sweep (process-record pruning unchanged)
- [x] 4.4a MySQL `alert_event_payloads` migration; alert creation copies the triggering-event envelopes; alert detail resolves evidence from it (`GetAlertEvidence`). Done in the alert-evidence PR (pre-cutover; reads the source events from MySQL `events`, which the cutover repoints to the archive).
- [x] 4.4b Drop the `alert_events -> events` FK (part of the cutover, when the `events` table is dropped).

## 5. Tests and spec traceability

- [~] 5.1 PBT: deferred. The Event envelope is unchanged by the cutover (no new wire-format struct/field, so the project's PBT-round-trip rule is not triggered), and the claim invariants (disjoint batches, per-host order, idempotent re-append, stale-claim re-offer) are pinned by example-based integration tests in `server/visibility/internal/tests/eventlog_integration_test.go`. A property-based pass can be added later without blocking the cutover.
- [x] 5.2 Integration (new `clickhouse_test` container): intake -> archive + `event_queue` -> processor -> alert + evidence, end to end
- [x] 5.3 Add spectrace markers tying tests to the new/modified scenarios in `server-event-ingestion` and `server-detection-rules-engine`. (Done for `server-detection-rules-engine/alert-evidence-is-self-contained` in the alert-evidence PR; `server-event-ingestion` markers land with the cutover.)
- [x] 5.4 Observability parity with MySQL: open the ClickHouse `database/sql` connection through the same `otelsql` wrapper as `server/bootstrap/db.go` (`db.system=clickhouse`, `otelsql.RegisterDBStatsMetrics`) so every archive query/insert gets a span plus the connection-pool / `db.sql.*` RED metrics with no bespoke code; add archive-specific signals (`async_insert` flush-ack latency, batch row counts); SigNoz dashboard panel (OTel only, ADR-0006)

## 6. Acceptance gate

- [ ] 6.1 Re-run the #203 500-agent baseline against ClickHouse; capture ingest p99, UI-read p99, and archive disk/compression vs the MySQL baseline
- [ ] 6.2 Update deployment docs (single-VM + multi-replica), the single-VM compose, and release/quickstart artifact lists for the ClickHouse instance
- [ ] 6.3 Close #427 once the acceptance numbers meet the gate
