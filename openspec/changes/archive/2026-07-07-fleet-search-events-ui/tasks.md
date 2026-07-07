## 1. API + types

- [x] 1.1 `ui/src/types.ts`: `EventSearchResult` ({events: EventRecord[], next_cursor?, total_matched})
- [x] 1.2 `ui/src/api.ts`: `EventSearchMode` + `searchEvents(mode, {value, host_id?, from?, to?}, cursor?)` mapping mode -> path + artifact param; unit test (URL composition) and the deferred `searchProcesses` URL test

## 2. Search page modes

- [x] 2.1 `ui/src/components/Search/SearchResultsFrame.tsx` (+ test): presentational error / searching / empty / "N of M" / load-more shell driven by useCursorList state
- [x] 2.2 `ui/src/components/Search/ProcessSearch.tsx`: extract the process body from `SearchPage` verbatim (chips, useCursorList over searchProcesses, process table) onto the shared frame; move its spec markers with its test
- [x] 2.3 `ui/src/components/Search/EventSearch.tsx` (+ scss): connection/DNS mode; requires an artifact value before searching, host chip optional, mode-specific event table on the shared frame
- [x] 2.4 `ui/src/components/Search/SearchPage.tsx`: mode shell reading `?mode=` (default process), a Processes/Connections/DNS selector that sets the mode and clears the other mode's params, delegating to ProcessSearch or EventSearch

## 3. Network pivots

- [x] 3.1 `ui/src/components/NetworkConnections.tsx`: "search fleet" Link on each remote address (`/search?mode=connections&remote_address=`) and each DNS query name (`/search?mode=dns&query_name=`)

## 4. Tests

- [x] 4.1 `EventSearch` tests: connection rows, DNS rows, prompt-before-search, load-more appends, error (spec markers `fleet-wide-connection-and-dns-search/*`)
- [x] 4.2 `SearchPage` tests: mode selector switches modes and clears params; `NetworkConnections` tests: pivot targets (spec markers `network-artifact-search-pivots/*`)

## 5. Verification

- [x] 5.1 `cd ui && npm test`, `npm run lint`, tsc, `tools/spectrace check --strict`, `openspec validate --all --strict`
- [x] 5.2 Manual QA on the dev server: `/search?mode=connections`, `/search?mode=dns`, pivot from a process's network row, load more against the seeded events

## 6. Docs

- [x] 6.1 CHANGELOG entry under 0.4.0
