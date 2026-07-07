## Context

Post-ADR-0015, every accepted event (exec, fork, exit, network_connect, dns_query) is written to the ClickHouse archive with a materialized `pid` column and `remote_address`/`query_name` columns plus bloom skip indexes. The archive already serves `NetworkEventsForProcess` (per-process correlation, bounded by event `timestamp_ns`) and `SearchEvents` (fleet-wide artifact search, bounded by `ingested_at_ns`, keyset over `(timestamp_ns, event_id)` DESC). The detection operator exposes host-scoped read endpoints (`/tree`, `/processes/{pid}`, `/health`, `/activity-histogram`, `/{host_id}`) each through a reader seam satisfied by `mysql.Store`, gated with `identityapi.HTTPGate(ActionProcessRead, Resource{Type:"process", ID: hostID})`.

## Goals / Non-goals

**Goals:**

- One host-scoped, time-ordered stream of the three investigation event classes over the graph's active window, filterable by type and text, server-paginated with the #582 keyset contract.
- Reuse the archive's existing cursor codec and result shape so the UI's `useCursorList` drives the timeline unchanged.

**Non-goals:**

- No API-layer merge of heterogeneous sources: the events are co-located in ClickHouse, so the merge is a `WHERE event_type IN (...)`.
- No server-side event-to-process-node resolution: rows carry `pid` in the payload; the Timeline tab (PR 2) correlates to the already-loaded tree client-side. Adding a per-row `process_id` would be N cross-context lookups per page for a link the UI can resolve from data it already holds.
- No fork/exit rows: exec is the meaningful process-start row; fork/exit lineage is the graph's job. The allowlist is exactly {exec, network_connect, dns_query}.
- No brush-to-zoom (deferred per the issue; a UI concern regardless).

## Decisions

- **Merged in ClickHouse, one query.** `HostTimeline` selects `host_id = ? AND event_type IN (?) AND timestamp_ns BETWEEN ? AND ?`, ordered `timestamp_ns DESC, event_id DESC`, keyset-paged over `(timestamp_ns, event_id)` exactly like `SearchEvents`. This gives native interleave + stable pagination for free and keeps the query in the context that owns the data.
- **Window bounds event time, not ingest time.** The graph's window is event time (fork/exec timestamps); the timeline shares it, so the filter bounds `timestamp_ns`. This differs from `SearchEvents` (ingest time), which is why it is a distinct filter type (`HostTimelineFilter`) rather than an overload of `EventSearchFilter`.
- **Type allowlist, default all.** No `type` param means all three classes. A `type` param is a comma list validated against the allowlist; an unknown type is a 400 (mirrors #582 rejecting a missing artifact), not a silent empty result.
- **Text is a case-insensitive payload substring.** `positionCaseInsensitiveUTF8(payload, ?) > 0` matches a path, remote address, hostname, or query name without per-type field logic. It scans the payload string, but the host + window + type predicate has already pruned to a small granule set, so the scan is bounded. Empty text is omitted.
- **Reuse `EventSearchResult` + `EventCursor` + `ErrInvalidEventCursor`.** The page shape (events, next_cursor, total_matched) and the keyset position are identical to the fleet-wide search; reusing them keeps one cursor codec and lets the UI share `useCursorList`.
- **Same reader-seam shape.** `HostTimelineReader` interface + `SetHostTimeline` + `registerHostTimelineRoutes` co-located in `host_timeline_handler.go`, satisfied by `mysql.Store` delegating to the archive, wired in ModeFull, 503 when unset.

## Risks / Trade-offs

- [Payload text scan has no index] -> acceptable: it only runs after the host + event-time-window + type predicate prunes to a bounded set, and the window is operator-chosen (not the whole archive). If a pathological all-time window over a noisy host becomes slow, a tokenized text index is a follow-up, not a contract change.
- [A very wide window returns a huge stream] -> the endpoint caps the page (shared `searchMaxLimit`) and returns `total_matched`, so the UI shows "N of M" and the operator narrows with the time control or type/text filters, the same affordance the fleet search uses.
- [Events for a pid the tree didn't load can't cross-link] -> a network/DNS event whose process is outside the rendered tree (capped or aged) has a pid the UI can still show, just without a node link; the row is not dropped. PR 2 renders the link when the node is present and omits it otherwise.
