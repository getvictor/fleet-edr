## Why

The only investigation surface today renders every process node in D3 and is silently capped at 2,000 rows. On a real host a single 15-minute window matched 2,588 processes, and the dominant volume is repetition, not system-path noise: `grep ×1000`, `docker ×270`, `jspawnhelper ×240`, `ssh ×170` in one window. None of it is touched by the existing client-side `showSystem` toggle, which filters Apple platform paths post-cap. A raw 2,588-node graph is not a graph problem, it is a search-and-aggregate problem, and the single biggest "make this manageable" win is collapsing repeated identical child executions under one parent into a single node carrying a count. Doing it server-side shrinks the response payload itself rather than only the render (issue #416, part of the hunting epic #415).

## What changes

- The per-host process forest query (`server/detection/internal/graph`) gains a read-time transform: after the forest is built, repeated identical-path leaf siblings under the same parent are grouped by binary identity (path + sha256 + cdhash) and collapsed into a single aggregated node carrying the group's count, its exited/running split, and its first/last fork-time span. Only childless (leaf) siblings are folded, so a child that has its own subtree is never silently dropped; the full per-member fetch is the lazy-expand story (#421), and until it lands each aggregated node carries a small capped sample of its members so the UI can expand it in place.
- The `GET /api/hosts/{host_id}/tree` response nests these aggregated nodes in the forest exactly where the collapsed siblings sat. Aggregation is on by default and opt-outable with a `?flatten=1` query parameter that returns the raw forest for an analyst who wants every node.
- The web UI renders an aggregated node as a `×N` badge (green when any member is still running, grey otherwise), expands it to its sample on click, and adds a persisted "Flatten" toggle beside "Show system" that refetches the un-aggregated forest.

Out of scope, tracked as follow-ups in the epic: honest truncation metadata (`total_matched` / `truncated`, story #423); the interesting-branches-only default (#417); the server-side search endpoint and table that actually relieve the 2,000-row cap (#418/#419); and lazy per-member expansion that replaces the capped sample with an on-demand fetch (#421). This change deliberately aggregates in memory over the already-fetched forest, so it shrinks the payload but does not by itself lift the fetch cap.

## Capabilities

### Modified capabilities

- `server-process-graph-builder`: the forest read path collapses repeated identical-path leaf siblings into aggregated nodes as a pure, order-preserving transform that never drops or duplicates a process and never folds a node that has its own subtree.
- `server-rest-api`: the process-forest endpoint returns aggregated nodes by default and accepts a `flatten` opt-out; the aggregated node wire shape carries the count, exited/running split, fork-time span, and a capped sample.
- `web-ui`: the process tree renders aggregated groups as `×N` badges, expands them to their sample on click, and exposes a Flatten toggle for the raw forest.

## Impact

- Code (server): a new `aggregateSiblings` transform plus helpers in `server/detection/internal/graph/query.go`; a `flatten` parameter threaded through `api.Service.BuildTree`, `service.Service.BuildTree`, and the operator handler (`server/detection/internal/operator/handler.go`), which reads it via a new `httpserver.ParseBoolParam`; a new `AggregatedSiblings` type and an `Aggregated` field on `api.ProcessNode` in `server/detection/api/types.go`.
- Code (UI): `ui/src/types.ts` (add `AggregatedSiblings`, extend `ProcessNode`), `ui/src/api.ts` (`getProcessTree` gains a `flatten` argument), and `ui/src/components/ProcessTree.tsx` (badge rendering, expand-to-sample state, Flatten toggle), each with a `*.test.tsx` sibling.
- Data: none. No migration, no schema change; aggregation is a read-time transform over rows already materialized in `processes`.
- APIs: the `/api/hosts/{host_id}/tree` response gains optional `aggregated` nodes and accepts a new `flatten` query parameter. The default response shape changes (repeated siblings now collapse); `flatten=1` reproduces the prior shape exactly.
- Security: no new authz. The endpoint stays behind the existing `ActionProcessRead` gate; the transform reads no new data and exposes no field a process node did not already carry.
- Rollback is a code revert; a client that does not understand `aggregated` still renders the representative node (path, pid) and simply ignores the badge.
