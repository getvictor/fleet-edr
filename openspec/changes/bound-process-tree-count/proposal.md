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
- `total_matched` is exact when the count finished and a floor when it did not. A new `total_matched_capped` says which, so a client never has to guess whether a round number is real.
- The bound is 10,000, five times the 2,000 row default limit. It answers "is there a lot more" in 0.148s on the host that failed. The count reads one row past it, so "capped" means strictly more matched and the page can say "more than 10,000" rather than "at least".
- The count also carries a 5-second time budget. The bound caps rows EMITTED, not rows examined, so a sparse window still walks its whole range to prove it matched few rows: about 1.7s for a full scan of this host's 5.2M rows, and more on a larger one. On expiry the count reports what the read already holds instead of failing the request.
- `truncated` is proven by reading one row past the requested limit rather than derived from `total_matched`. The count can be capped or give up, and a truncation flag derived from it read a partial forest as complete on exactly the hosts where the count cannot finish. This also stops paying for a count on a window holding exactly the limit, which is not truncated at all.

## What does not change

The row read's predicate, its ordering, and the shape of the tree. `returned` and `truncated` mean what they meant, and a window inside the bound reports exactly what it reports today. The read now asks for one row more than the limit and drops it, which is invisible to a client.

## Impact

- Affected specs: `server-rest-api`
- Affected code: `server/detection/internal/mysql/processes.go`, `server/detection/internal/graph/query.go`, `server/detection/api`, `ui/src/api.ts`
