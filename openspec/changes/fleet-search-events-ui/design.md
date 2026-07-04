## Context

PR 3 shipped `/search` as a single-purpose process console: `SearchPage` reads a `ProcessSearchFilter` from `useSearchParams`, drives a `useCursorList` over `GET /api/search/processes`, and renders a process table with removable `FilterChips`. PR 2 shipped two sibling endpoints, `GET /api/search/connections?remote_address=` and `GET /api/search/dns?query_name=`, each returning `{events, next_cursor, total_matched}` where an event is the visibility `Event` (event_id, host_id, timestamp_ns, event_type, payload). The event payload shapes (`NetworkConnectPayload`, `DNSQueryPayload`) already exist in the UI types (the process detail panel renders them via `NetworkConnections`). The event endpoints require a non-empty artifact value and 400 on an empty one, unlike process search whose filters are all optional.

## Goals / Non-goals

**Goals:**

- One search page that hosts three modes (processes, connections, DNS) with the mode in the URL, reusing the list hook, chips, and result frame across all three.
- Network investigation reachable in one click from a process's connections/DNS rows.
- No duplication of the loading/empty/error/count/load-more shell between process and event results.

**Non-goals:**

- No new endpoint or wire change (both event endpoints are merged).
- No free-text query language and no saved searches (typed artifact value + optional host, same as process mode).
- No client-side coalescing of event rows (the archive already coalesces at ingest; the search returns representative events).

## Decisions

- **Mode is a URL param, modes are separate components.** `SearchPage` reads `?mode=` (default `process`), renders a mode selector (links that set `?mode=` and clear the other mode's params), and delegates to `ProcessSearch` or `EventSearch`. Splitting by component rather than branching one giant component keeps each result type's filter set, fetch, and columns cohesive and independently testable; the process body is extracted verbatim from PR 3's `SearchPage` so its behavior (and its four spec scenarios) is unchanged.
- **One `searchEvents(mode, filter, cursor)` in the API layer.** The two endpoints differ only in path segment and the query-parameter name carrying the artifact (`remote_address` vs `query_name`); a single client function maps the mode to both, mirroring the server's shared `serveEventSearch`. Returns `EventSearchResult { events, next_cursor?, total_matched }`.
- **Event modes require the artifact before searching.** The endpoint 400s on an empty value, so `EventSearch` shows a prompt ("Enter a remote address to search") until the operator supplies the address/domain, rather than firing a request that can only fail. Processes mode keeps its all-optional filters.
- **Shared `SearchResultsFrame`.** The error banner, "searching", empty state, "showing N of M" count, and the "Load more" button are identical across modes; they move into one presentational component driven by the `useCursorList` state, and each mode supplies only its table. This removes the duplication the split would otherwise create and is what keeps the new-code cognitive-complexity and lexical-duplication gates green.
- **Pivots reuse the PR 3 pattern.** `NetworkConnections` gains a sibling "search fleet" `Link` on each remote address row (`/search?mode=connections&remote_address=<addr>`) and each DNS query name (`/search?mode=dns&query_name=<name>`), the network analogue of the process detail panel's path/hash/uid/signing pivots.

## Risks / Trade-offs

- [Refactoring the just-merged process page] -> the process body moves into `ProcessSearch` unchanged and its spec scenarios move with its tests, so the observable process-search behavior is identical; the shell only adds the mode selector above it.
- [An event artifact value with no matches] -> unlike a bad process filter this is a valid search that simply returns zero events; the page shows the empty state, not an error, and the operator can switch modes or edit the value. A malformed cursor or window is still a 400 surfaced in the banner.
- [Coalesced events under-count occurrences] -> a connections/DNS row is a representative event after agent-side coalescing, so one row can stand for many identical flows; this matches how the host detail panel already presents them, and the total is a count of representative events, not raw flows. Noted so the count is not read as a raw-flow total.
