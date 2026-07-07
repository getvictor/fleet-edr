## Why

The process tree answers "what happened on this host in this window"; it cannot answer the cross-host scoping questions that dominate triage: "where else did this hash run", "what did uid 0 exec in this window across the fleet", "show every unsigned binary anywhere". Every leading EDR pairs the per-host view with a global hunting console (Defender Advanced Hunting, Falcon Event Search, SentinelOne Deep Visibility). This is the producer half of story #582 (epic #577): the fleet-wide process search endpoint. The connection/DNS artifact classes (ClickHouse) and the `/search` UI follow as the next two PRs.

## What Changes

- New endpoint `GET /api/search/processes`: a fleet-wide, filterable, cursor-paginated query over the process table, gated on process read.
- Filters compose (AND) in SQL: `host_id` (optional; absent means fleet-wide), `path` (contains), `hash` (exact SHA-256), `uid`, `from`/`to` (fork-time range), `exit_reason`, and `signing` (a derived verdict class: unsigned, ad-hoc, platform, developer-id, signed).
- Keyset (not offset) pagination over the compound key `(fork_time_ns, id)` descending, with an opaque cursor and a `total_matched` count of the full filtered set.
- A new index supporting the fleet-wide time-ordered scan and a hash-lookup index.
- The route lives under `/api/search/`, not `/api/hosts/`, so it cannot collide with the `GET /api/hosts/{host_id}` wildcard.

Deferred to the next PRs of #582, called out so the scope is honest: the `has_network` filter (it requires the ClickHouse network correlation the connection-search PR builds; it cannot be applied in SQL across two databases), the connection-by-IP and DNS-by-domain artifact classes (ClickHouse), and the `/search` UI plus host-page bridge pivots.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `server-rest-api`: ADDED requirement "Fleet-wide process search endpoint".

## Impact

- `server/detection/api` (search request/result types), `server/detection/internal/mysql` (the search store query + a new migration for the scan and hash indexes), `server/detection/internal/operator` (a `ProcessSearchReader` seam + handler on the established reader-seam pattern), bootstrap wiring.
- No agent, wire-schema, or ClickHouse changes in this PR.
