## Why

The two scoping questions that matter most in an intrusion are cross-host and about network artifacts: "who else connected to this IP" and "who else resolved this domain". PR 1 of #582 shipped fleet-wide process search over MySQL; connections and DNS live in the ClickHouse event archive, a different context, so they are their own PR. This is PR 2 of 3 for #582 (epic #577); the `/search` UI and host-page bridge pivots are PR 3.

## What Changes

- Two endpoints, `GET /api/search/connections` and `GET /api/search/dns`, gated on process read: fleet-wide search of the event archive for network connections by remote address and DNS queries by query name.
- Each accepts the artifact value (required), an optional `host_id`, and a `from`/`to` window over ingest time; results are newest-first with the same keyset-cursor + `total_matched` contract as the process search, keyed on `(timestamp_ns, event_id)`.
- The `EventArchive` interface gains a `SearchEvents` method, implemented by the ClickHouse store and the in-memory test fake; the detection store delegates to it exactly as it already delegates per-process correlation.
- The ClickHouse `events` table gains materialized `remote_address` and `query_name` columns (extracted from the JSON payload) with bloom-filter skip indexes, so a fleet-wide by-IP/by-domain lookup prunes granules instead of scanning; `MATERIALIZE` backfills existing rows.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `server-rest-api`: ADDED requirement "Fleet-wide connection and DNS search endpoints".

## Impact

- `server/visibility/api` (EventSearchFilter/Result + the interface method), `server/visibility/internal/clickhouse` (the query + a materialized-column migration), `server/visibility/testkit` (the fake's implementation), `server/detection/internal/mysql` (a thin delegate), `server/detection/internal/operator` (an `EventSearchReader` seam + two handlers), bootstrap wiring.
- No agent or MySQL-schema changes. The process search's `has_network` filter, deferred from PR 1, is a natural follow-up now that the archive can answer "does this process have connections", but stays out of this PR to keep it focused.
