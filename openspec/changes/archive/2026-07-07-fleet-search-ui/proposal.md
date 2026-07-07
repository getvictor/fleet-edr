## Why

The fleet-wide process search endpoint (PR 1 of #582) has no operator surface yet: an analyst can only reach it by hand-crafting a URL. This PR gives it a page, the global hunting console every leading EDR has, plus the "bridge" pattern that makes it reachable in one click from a process's detail panel. This is PR 3a of #582 (epic #577); the connection/DNS search modes and their network pivots follow as PR 3b on the same page shell.

## What Changes

- A new `/search` page (nav entry "Search", gated on process read) with a filterable, cursor-paginated table over `GET /api/search/processes`: filter chips for host, path, hash, uid, and signing verdict; columns time, host (hostname resolved from the host list), process, parent, command line, user, signing, exit reason; a "Load more" control that follows `next_cursor`; and a `total_matched` result count.
- Removable filter chips as a reusable component, and a cursor "load more" list hook, both net-new to the UI.
- Result rows link to the host's process tree anchored at the matching process (`/hosts/:id?...&at=`), the standard pivot into the tree.
- "Search all hosts" pivots on the process detail panel's path, SHA-256, uid, and signing-verdict rows, each landing on `/search` pre-filtered. (Signing id and team id stay copy-only: the endpoint has no filter for them.)
- The UI `PermissionAction` enum gains `ProcessRead` (`process.read`), which the server already enforces on the search endpoints but the UI could not reference.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `web-ui`: ADDED requirements "Fleet-wide search page" and "Host page search pivots".

## Impact

- `ui/src/permissions-core.ts` (ProcessRead), `ui/src/components/ui/nav-links.ts` + `ui/src/App.tsx` (nav + route), `ui/src/api.ts` + `ui/src/types.ts` (searchProcesses + result type), new `ui/src/components/Search/` (page, filter-chips, load-more hook) and `ui/src/components/ProcessDetail.tsx` (pivots), co-located tests.
- No server, agent, or wire changes: the endpoint and its contract are merged.
