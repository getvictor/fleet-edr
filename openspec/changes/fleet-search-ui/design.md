## Context

`GET /api/search/processes` returns `{rows, next_cursor, total_matched}` with keyset pagination. The UI has no cursor-pagination and no filter-chip prior art; filtering elsewhere is `<Select>` dropdowns, and `Table` is a bare wrapper. Search rows carry only `host_id` (no hostname); `listHosts()` returns `HostSummary[]` with hostnames. Cross-page links are template strings with `encodeURIComponent`; the search page reads its filters from `useSearchParams`, matching the tree's `?alert=&at=` reading. The `/search` endpoints are gated on `process.read`, which is absent from the UI `PermissionAction` enum.

## Goals / Non-goals

**Goals:**

- The page's filter state lives in the URL, so a pivot is just a link to `/search?...` and the page is bookmarkable/shareable.
- One reusable search-page shell (chips + load-more + result table) that PR 3b extends with connection/DNS modes.
- Every process artifact the endpoint can filter is one click from the detail panel.

**Non-goals:**

- No connection/DNS modes or network pivots (PR 3b).
- No signing-id/team-id pivot (no server filter; stays copy-only).
- No saved searches, no free-text query language (typed filters via chips).

## Decisions

- **URL is the filter state.** The page derives its `ProcessSearchFilter` from `useSearchParams` and re-fetches when the params change; adding/removing a chip pushes a new query string. This makes a pivot a plain `<Link to="/search?hash=...">`, keeps back/forward working, and needs no cross-component state. The cursor is page-local state (not in the URL): it resets whenever the filter params change.
- **"Load more", not numbered pages.** Keyset pagination has no page numbers; the table appends the next page's rows and shows the running count against `total_matched` ("showing N of M"). One `useCursorList` hook owns the accumulate-and-advance loop so PR 3b reuses it for events.
- **Hostname decoration via one `listHosts` call.** Fetched once alongside the results into a `host_id → hostname` map; a row shows the hostname over the id, falling back to the id (the same treatment HostList and the host header already give the small host set). Avoids a per-row lookup and needs no new endpoint.
- **Chips are removable filter tokens** rendered from the active URL params; each chip's remove control drops its param. A small chip-input row adds a filter (a field select + value input) rather than a full query builder, matching the typed-param endpoint.
- **Pivots reuse the copy-affordance sites.** The detail panel already renders path/sha256/uid/signing next to a CopyButton; the pivot is a sibling link (`Link to="/search?<param>=<value>"`), so the evidence row gains "copy" + "search fleet" side by side.

## Risks / Trade-offs

- [A huge result set with "load more"] -> the server caps the page at 200 and returns `total_matched`; the UI shows the running/total count so the analyst knows the set is large and can narrow with chips rather than paging forever.
- [Filter state only in the URL] -> the page reads only the whitelisted filter keys, so an unknown hand-added param is ignored rather than misinterpreted; a recognized key with a bad value (non-numeric uid, unknown signing verdict, malformed window) is rejected 400 by the endpoint and surfaced in the error banner, not silently dropped.
- [Signing-id/team-id look pivotable but aren't] -> they stay copy-only with no search affordance, so there's no dead link; a filter for them is a possible endpoint follow-up.
