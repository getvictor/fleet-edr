## Context

`ProcessTreeView` (in `ProcessTree.tsx`) is the host page: it owns the single `timeWindow` state (and derived `bounds`), renders `HostHeader`, the compact `TimeRangeControl`, the `ActivityHistogram`, the d3 process graph, and the `ProcessDetail` aside, and reads `?at=`/`?process=`/`?alert=` from the URL. PR 1 shipped `GET /api/hosts/{host_id}/timeline` returning `{events, next_cursor, total_matched}` (the visibility `Event` shape the UI already types as `EventRecord`, with `NetworkConnectPayload`/`DNSQueryPayload`), keyset-paged like the fleet search, filterable by `type` and `text`, bounded by event time. The fleet-search UI (#582) left reusable `useCursorList`, `SearchResultsFrame`, and `format` (hostPort/basename/formatNs) plus the `NetworkConnections` "search fleet" pivots.

## Goals / Non-goals

**Goals:**

- One host page, two views over one time window: switching Graph<->Timeline never changes the window or the alert anchor.
- The timeline reuses the fleet-search list machinery (hook + frame + formatters) rather than re-implementing paging.
- Move between the views by pid: a row opens its node; a node shows its rows.

**Non-goals:**

- No brush-to-zoom on the timeline (deferred per the issue; the shared time control already narrows the window).
- No pid filter on the endpoint: PR 1 deliberately omitted it, so node->timeline emphasizes the process's rows client-side (each row carries pid) rather than server-filtering.
- No new graph-selection URL contract beyond adding `?pid=&at=` resolution; `?process=<dbId>` stays the primary node deep-link.

## Decisions

- **View is a URL param; the host page swaps only the main content.** `ProcessTreeView` reads `?view=` (default `graph`). The `HostHeader`, time control, and histogram render in both views (they describe the window, shared by both). The graph-only effects (the `getProcessTree` fetch and the d3 render) early-return when `view !== "graph"`, so the timeline view does no graph work and the unmounted `<svg>` is never touched. Below the shared header, the page renders the graph canvas + detail aside, or `<HostTimeline hostId bounds .../>`. Keeping one component owning the window avoids lifting intricate d3 state into a new parent.
- **`getHostTimeline(hostId, {from,to,types,text}, cursor)` returns the shared `EventSearchResult`.** The response shape is identical to the fleet event search, so the UI reuses `EventSearchResult` and drives the table with the same `useCursorList` + `SearchResultsFrame`. Type filters are chip toggles that compose a `type=` comma list; the text box drives `text=`. Both live in the URL so a timeline view is shareable.
- **Row -> node by pid + time, resolved in the graph.** A timeline row links to `?view=graph&pid=<pid>&at=<eventMs>` (dropping `?process=`). After the tree loads, `ProcessTreeView` resolves `?pid=&at=` to the node with that pid whose lifetime brackets the anchor and selects it, the pid-based analogue of the existing `?process=<dbId>` selection. The timeline holds no tree, so it cannot resolve a DB id itself; resolving in the graph (which has the tree) is where the mapping is cheap and correct.
- **Node -> timeline emphasizes by pid.** `ProcessDetail` adds a "Show in timeline" link to `?view=timeline&pid=<pid>`. `HostTimeline` reads `?pid=` and visually emphasizes rows whose payload pid matches, without a server filter (PR 1 has none). This honors "a graph node links to its rows in the timeline" while staying within the merged contract; the analyst still sees the whole host stream with the process's rows highlighted, which is more useful than a hard filter that would hide the surrounding context.
- **Artifact pivots reuse the fleet-search links.** A connection row's remote address and a DNS row's query name render the same "search fleet" pivot the `NetworkConnections` panel uses, so a timeline finding jumps to the fleet-wide view in one click.

## Risks / Trade-offs

- [Guarding the graph effects with `view !== "graph"`] -> the guards are early-returns at the top of the existing effects, so the graph's behavior in graph view is unchanged; a switch to timeline simply skips the fetch/draw. The graph re-fetches on switch back, which is the same cost as landing on the page.
- [An event whose pid is not in the loaded tree] -> the row's node link resolves to nothing (the process was capped out of the tree or aged past it); the link is still rendered but selecting finds no node, matching how an out-of-window `?process=` deep link already degrades. The row itself is never dropped.
- [pid reuse within a wide window] -> `?pid=&at=` picks the node whose lifetime brackets the anchor time, so a reused pid resolves to the generation live at the event, not the most recent one; this is the same (host, pid, at) correlation the process-detail network join already relies on.
