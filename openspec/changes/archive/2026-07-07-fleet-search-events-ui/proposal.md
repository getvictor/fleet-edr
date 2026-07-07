## Why

The fleet-wide connection and DNS search endpoints (`GET /api/search/connections`, `GET /api/search/dns`, PR 2 of #582) have no operator surface: an analyst can search processes fleet-wide from the `/search` page (PR 3) but cannot pivot on a remote address or a domain, the two artifacts a network-based investigation starts from. This PR is the final piece of #582 (epic #577): it adds connection and DNS modes to the existing search page and the network pivots from a host's process detail that make "who else talked to this IP / resolved this domain" one click.

## What Changes

- The `/search` page gains a mode selector (Processes / Connections / DNS). The mode lives in the URL (`?mode=`), so it stays bookmarkable and a pivot is a link. Processes mode is unchanged.
- Connections mode queries `GET /api/search/connections` for a remote address; DNS mode queries `GET /api/search/dns` for a domain. Both are cursor-paginated with a `total_matched` count and "Load more", reusing the same list hook and result frame as process search. Because the endpoint requires an artifact value (it 400s on an empty one), the event modes prompt for the address/domain rather than firing an empty search.
- Event results render per event: time, host (hostname resolved from the host list, else the id), the process (path and pid), and the mode-specific columns: direction, protocol, and remote address:port for connections; query type and resolved addresses for DNS. An optional host chip narrows either mode to one host.
- The process detail panel's network section (`NetworkConnections`) gains a "search fleet" pivot on each remote address and each DNS query name, landing on `/search` pre-filtered to that artifact in the matching mode.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `web-ui`: ADDED requirements "Fleet-wide connection and DNS search" and "Network artifact search pivots".

## Impact

- `ui/src/api.ts` + `ui/src/types.ts` (`searchEvents` + `EventSearchResult`), the `ui/src/components/Search/` page (mode shell, extracted process search, new event search, shared result frame), and `ui/src/components/NetworkConnections.tsx` (pivots), plus co-located tests.
- No server, agent, or wire changes: both endpoints and their contract are merged.
