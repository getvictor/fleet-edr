## 1. API

- [x] 1.1 `ui/src/api.ts`: `getHostTimeline(hostId, {from?, to?, types?: string[], text?}, cursor?)` -> `EventSearchResult`, composing `?type=`/`?text=`/`from`/`to`/`cursor` (reuse the `EventSearchResult` type from #582); unit test for URL composition.

## 2. Timeline component

- [x] 2.1 `ui/src/components/HostTimeline.tsx` (+ scss): props `{hostId, bounds, emphasizePid?}`. Event-type chip toggles + text box driving URL params; `useCursorList` over `getHostTimeline`; table (time, type, process `name (pid)`, detail) on `SearchResultsFrame`; row -> `?view=graph&pid=&at=` link; connection/DNS "search fleet" pivots; rows whose pid == emphasizePid get an emphasis class.
- [x] 2.2 Component test: renders interleaved rows, type chip filters the query, text filters the query, row link target carries pid+at, emphasized pid row, load-more.

## 3. Host page view tabs + cross-links

- [x] 3.1 `ProcessTree.tsx` `ProcessTreeView`: read `?view=` (default graph); Graph/Timeline tab links preserving window/at/process; early-return the getProcessTree fetch effect and the d3 render effect when `view !== "graph"`; render `<HostTimeline hostId bounds emphasizePid>` vs the graph canvas + detail; resolve `?pid=&at=` to a node after the tree loads (`findNodeByPidAtTime`) and select it.
- [x] 3.2 `ProcessDetail.tsx`: "Show in timeline" link to `?view=timeline&pid=<pid>` next to the identity row.
- [x] 3.3 Tests: view switch preserves the window; `?pid=&at=` selects the right node; "show in timeline" link target.

## 4. Verification

- [x] 4.1 `cd ui && npm test`, `npm run lint`, tsc, `vite build`, `tools/spectrace check --strict`, `openspec validate --all --strict`.
- [x] 4.2 Manual QA on the dev server: open a host, switch to Timeline, filter by type and text, load more, pivot a row to the graph, and "show in timeline" from a node; confirm the window is shared.

## 5. Docs

- [x] 5.1 CHANGELOG entry under 0.4.0.
