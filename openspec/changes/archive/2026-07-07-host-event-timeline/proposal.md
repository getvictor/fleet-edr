## Why

The host page shows a process graph (lineage: "how") but no flat, time-ordered event stream (hunting: "when" + filter + pivot). Every leading EDR pairs the graph with a filterable timeline over the same data because graphs stop being readable past a few hundred nodes. This is the server half of #583 (epic #577): a host-scoped, time-ordered, merged event query the Timeline tab (PR 2) will render. It reuses the keyset-cursor contract #582 established for fleet-wide search.

## What Changes

- A new endpoint `GET /api/hosts/{host_id}/timeline` returns exec, network_connect, and DNS query events for one host, interleaved in event-time order (newest first), over an event-time window, filterable by event type and a case-insensitive text match, keyset-paginated with a `total_matched` count. Gated on process read, scoped to the host.
- The visibility `EventArchive` gains a `HostTimeline` query. All three event classes already live in the ClickHouse archive, so one `event_type IN (...)` query merges them in native time order; no API-layer merge of MySQL processes and ClickHouse events is needed. The window bounds event `timestamp_ns` (what the graph's window means), not ingest time.
- The detection operator delegates the query to the archive through the same reader seam pattern as the fleet-wide search (`mysql.Store` forwards to the injected archive), so an unset archive routes 503 and the endpoint is off outside ModeFull.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `server-rest-api`: ADDED requirement "Host event timeline endpoint".

## Impact

- `server/visibility/api/eventarchive.go` (`HostTimeline` + `HostTimelineFilter`; reuses `EventSearchResult`/`EventCursor`), `server/visibility/internal/clickhouse/store.go`, `server/visibility/testkit/mem_archive.go`.
- `server/detection/internal/mysql/processes.go` (delegate), `server/detection/internal/operator/host_timeline_handler.go` (new reader seam + route + gate), `server/detection/bootstrap/bootstrap.go` (wire in ModeFull).
- No agent, wire-format, or schema change: the events are already archived; this is a new read path.
- The Timeline tab UI and the graph/timeline cross-links follow as PR 2 of #583.
