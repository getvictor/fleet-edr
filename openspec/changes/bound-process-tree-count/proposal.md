# Bound the process-tree count so the endpoint always answers

## Why

`GET /api/hosts/{host_id}/tree` returns 500 on a real host, and the UI shows an empty graph and then `Error: API error: 502`.

Found on the dogfood deployment against `v0.5.0-rc.4`, opening an alert on a host carrying 5.4 million process rows and 8.2GB of history. Measured on that host, with the alert's own 24-hour window:

| query | time |
| --- | --- |
| the row read, `ORDER BY fork_time_ns DESC LIMIT 2000` | 0.089s |
| the unbounded `COUNT(*)` that runs beside it | over 120s |
| a capped count on the same access path, bound 10,001 | 0.148s |

The row read was never slow. `BuildTree` runs `CountProcessTree` whenever the limit binds, purely to fill `total_matched`, and that count has no bound: it evaluates every match, 542,268 rows here. At 24 hours the optimizer also abandons `idx_processes_exit_time` (range, 642k rows) for `uk_processes_source_event` (ref, 2.9M rows, a 1022-byte key), which makes it worse again. The server's 30-second write timeout cuts the request, returns 500, and the proxy relays 502.

Neither obvious repair works. Forcing both indexes still takes 74 seconds, and splitting the `OR` into its two branches does not help either: `exit_time_ns IS NULL` is 3,552 rows and fast, while `exit_time_ns >= from` is the half-million-row branch. Counting that many rows is simply expensive, so the fix is not to count faster but to stop counting past the point the answer stops mattering.

This predicate was tuned once before, in #423, which measured a 631k-row database. This host is an order of magnitude past that, which is why the tuning held until now.

## What changes

- `CountProcessTree` counts through the row query's `ORDER BY fork_time_ns DESC` access path with a bound, so its cost is set by the bound rather than by how much the window matched.
- `total_matched` is exact below the bound and a floor at or above it. A new `total_matched_capped` says which, so a client never has to guess whether a round number is real.
- The bound is 10,000, five times the 2,000 row limit. It answers "is there a lot more" in 0.148s on the host that failed.

## What does not change

The row read, its predicate, its ordering, and the shape of the tree. `returned` and `truncated` keep their meanings, and a window inside the bound reports exactly what it reports today.

## Impact

- Affected specs: `server-rest-api`
- Affected code: `server/detection/internal/mysql/processes.go`, `server/detection/internal/graph/query.go`, `server/detection/api`, `ui/src/api.ts`
