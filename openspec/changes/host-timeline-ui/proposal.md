## Why

The host page shows the process graph (lineage) but not the flat, filterable event stream analysts use for hunting ("when + filter + pivot"). PR 1 of #583 shipped the `GET /api/hosts/{host_id}/timeline` endpoint; this PR (the UI half, completing #583 and epic #577's timeline track) puts a Timeline tab beside the graph over the same time window, with the cross-links that let an analyst move between the two views.

## What Changes

- The host page gains a **Graph / Timeline** view selector (the active view lives in the URL as `?view=`, so it is bookmarkable and the shared time window and alert anchor survive a switch). Graph is the default, so every existing host-page link still lands on the graph.
- A new Timeline view renders the host's exec, network, and DNS events for the active window as a flat, newest-first table (time, type, process, and per-type detail), filterable by event-type chips and a text box, with keyset "Load more" paging and a `total_matched` count. It reuses the fleet-search list hook and result frame and the same compact time control and activity histogram as the graph, so both views always reflect one window.
- **Cross-links both ways.** A timeline row links to its process node in the graph (switches to the graph view anchored at the event and selects the owning process by pid + time); a graph node's detail panel gains a "Show in timeline" link that switches to the Timeline view and emphasizes that process's rows. Timeline row artifacts (remote address, domain) reuse the fleet-search "search fleet" pivots.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `web-ui`: ADDED requirements "Host event timeline view" and "Graph and timeline cross-navigation".

## Impact

- `ui/src/api.ts` + `ui/src/types.ts` (`getHostTimeline`), new `ui/src/components/HostTimeline.tsx` (+ scss, test), `ui/src/components/ProcessTree.tsx` (`ProcessTreeView` gains the view tabs, guards the graph-only effects when the timeline is active, and resolves the `?pid=&at=` selection), `ui/src/components/ProcessDetail.tsx` ("Show in timeline" link), reusing `components/Search/{useCursorList,SearchResultsFrame,format}`.
- No server, agent, or wire change: the endpoint is merged; this is a new consumer.
