# Drop snapshot_heartbeat persistence

## Why

`snapshot_heartbeat` is the single largest contributor to `events`-table row count: ~22% of rows on the Render pilot (issue #408), one row per still-alive snapshot PID every `EDR_PROCESS_RECONCILE_INTERVAL` (default 60s, ~900 PIDs on a normal macOS host). Its only server-side effect is bumping `processes.last_seen_ns` so the freshness-TTL reconciler (#6, `EDR_STALE_PROCESS_TTL`, default-on at 6h) exempts genuinely long-lived snapshot rows from being force-exited. The detection engine already drops heartbeats before rule evaluation (`filterSnapshotEvents`). Yet every heartbeat is INSERTed into the heaviest table, fully indexed (6 secondary indexes), and retained for the whole `EDR_RETENTION_DAYS` window for zero forensic value.

## What changes

- **The ingest path processes heartbeats for their freshness side effect, then drops them instead of writing a retained `events` row.** `POST /api/events` partitions a batch into `snapshot_heartbeat` events and the rest. The rest are persisted exactly as today. For each heartbeat the ingest path applies the `processes.last_seen_ns` bump directly (the same scoped UPDATE the graph builder used: live, snapshot-originated row for `(host_id, pid)` only), in one batched statement per request, and the heartbeat is not stored.
- **Host liveness is preserved.** Heartbeats still feed `UpsertHosts`, so `hosts.last_seen_ns` and `event_count` advance for a near-idle host whose only traffic is heartbeats, exactly as before.
- **The freshness contract is unchanged.** `last_seen_ns` is still bumped for every live snapshot PID; the TTL reconciler's `COALESCE(last_seen_ns, fork_time_ns)` exemption behaves identically. The only difference is the bump is applied synchronously at ingest rather than asynchronously in the graph builder.
- **The graph builder and engine filter keep their heartbeat handling as a defensive path** for heartbeat rows that predate this change and are still `processed=0` at upgrade time. New heartbeats never reach them.
- **Observability.** A dedicated counter `edr.ingest.heartbeats_dropped` reports how many heartbeats were processed-and-dropped per request, so operators can see the row-count savings on the dashboard.
- **Operator lever documented.** `EDR_PROCESS_RECONCILE_INTERVAL` is documented as the immediate knob: raising 60s to 5m cuts heartbeat volume ~5x, and stays well under the 6h server TTL.

## Race note

A heartbeat ingested before the processor has materialized its snapshot row no-ops (the scoped UPDATE matches no row), exactly as the graph-builder path did. Heartbeats repeat every reconcile interval and snapshot rows are created at agent startup, so the next heartbeat re-applies the bump within one interval, far under the 6h TTL. No freshness is lost.

### Not in this change

- Network/DNS coalescing (separate change `coalesce-network-dns-telemetry`).
- The events index/PK diet (separate change `events-index-pk-diet`).
- Changing `EDR_PROCESS_RECONCILE_INTERVAL` or `EDR_RETENTION_DAYS` defaults; only documenting the reconcile-interval lever.
