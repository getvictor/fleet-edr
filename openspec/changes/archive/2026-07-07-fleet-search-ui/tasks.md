## 1. Permission + API + types

- [x] 1.1 `ui/src/permissions-core.ts`: add `ProcessRead: "process.read"`
- [x] 1.2 `ui/src/types.ts`: `ProcessSearchResult` ({rows: Process[], next_cursor?, total_matched}); `ui/src/api.ts`: `searchProcesses(filter, cursor)` building the query with URLSearchParams

## 2. Search shell

- [x] 2.1 `ui/src/components/Search/useCursorList.ts`: a hook that fetches the first page, exposes rows + total + a loadMore that follows next_cursor and appends, and resets when its input key changes; unit test
- [x] 2.2 `ui/src/components/Search/FilterChips.tsx` (+ test): render active filters as removable chips + an add-filter control (field select + value input) driving URL params

## 3. Search page

- [x] 3.1 `ui/src/components/Search/SearchPage.tsx` (+ scss): read filters from `useSearchParams`, fetch via useCursorList, decorate rows with a host_id->hostname map from `listHosts`, render the result table (time, host, process, parent, cmdline, user, signing, exit_reason), Load more, "N of M" count; rows Link to the host tree anchored at the process
- [x] 3.2 Route in `App.tsx` (`/search`, wrapped in RequirePermission ProcessRead) + nav entry in `nav-links.ts`
- [x] 3.3 Component tests: renders matches + total + hostnames, remove-chip drops the param, load-more appends, row link target (spec markers `fleet-wide-search-page/*`)

## 4. Detail-panel pivots

- [x] 4.1 `ProcessDetail.tsx`: "search all hosts" Link next to path, sha256, uid, and the signing verdict, each targeting `/search?<param>=<value>`; signing id / team id stay copy-only
- [x] 4.2 Tests: pivot link targets present for path/hash/uid/signing, absent for signing id/team id (spec markers `host-page-search-pivots/*`)

## 5. Verification

- [x] 5.1 `cd ui && npm test`, `npm run lint`, tsc, `tools/spectrace check --strict`, `openspec validate --all --strict`
- [x] 5.2 Manual QA on the dev server: open `/search`, add/remove chips, load more against the live 400k-process set, pivot from a process's detail panel

## 6. Docs

- [x] 6.1 CHANGELOG entry under 0.4.0
