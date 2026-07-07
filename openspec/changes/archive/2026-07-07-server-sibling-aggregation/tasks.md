## 1. Wire shape

- [x] 1.1 Add `AggregatedSiblings` (`count`, `exited_count`, `running_count`, `first_fork_ns`, `last_fork_ns`, `sample`) and an `Aggregated *AggregatedSiblings` field on `api.ProcessNode` in `server/detection/api/types.go`, `omitempty` so a non-aggregated node's wire shape is unchanged
- [x] 1.2 Mirror the type in `ui/src/types.ts`: `AggregatedSiblings` + optional `aggregated` on `ProcessNode`

## 2. Server aggregation transform

- [x] 2.1 `aggregateSiblings` in `server/detection/internal/graph/query.go`: recursive, pure (never mutates the input), collapses only leaf siblings grouped by binary identity (`path` + `sha256` + `cdhash`), folds groups of >= `aggregateMinGroup`, and orders output siblings by first fork time then row id for determinism
- [x] 2.2 Per-group summary: full-group `count`, exited/running split, min/max fork time, and a fork-ordered `sample` capped at `aggregateSampleCap`; the earliest member is the representative whose `Process` fields the node carries with `Children` nil
- [x] 2.3 Thread `flatten bool` through `Query.BuildTree`; aggregate by default, return the raw forest when `flatten` is set
- [x] 2.4 PBT (`pgregory.net/rapid`): for a random leaf-sibling batch, `Σ count over aggregated nodes + one per individual == input size`, output ordered by first fork, per-identity multiset preserved (no child lost, none duplicated, none regrouped), and each aggregated node internally consistent (exited+running==count, first<=last, sample capped and drawn from the group)
- [x] 2.5 Table-driven unit cases: N identical leaves collapse with the correct split and span; a singleton stays individual; distinct sha256 under one path stays separate; a node with a subtree stays individual and its own children aggregate one level down; large group caps the sample

## 3. Service and API surface

- [x] 3.1 Add `flatten bool` to `api.Service.BuildTree` and delegate through `service.Service.BuildTree`; update the operator `fakeService` and the detection integration-test callers
- [x] 3.2 `httpserver.ParseBoolParam` (accepts the `strconv.ParseBool` set); the operator tree handler reads `?flatten=` (default false = aggregate on) and passes it to `BuildTree`
- [x] 3.3 Handler tests: `flatten` threads through (absent/`1`/`true`/`0`); the aggregated node wire shape is pinned end to end

## 4. UI

- [x] 4.1 `ui/src/api.ts`: `getProcessTree` gains a `flatten` argument appended as `&flatten=1`
- [x] 4.2 `ui/src/components/ProcessTree.tsx`: render an aggregated node as a `×N` badge (green when any member runs, grey otherwise), a persisted "Flatten" toggle beside "Show system" that refetches the raw forest, and an expand-in-place that materializes the aggregated node's sample as children on click/chevron
- [x] 4.3 vitest siblings: the `×N` badge renders, clicking expands to the sample, and the Flatten toggle refetches with `flatten=true`

## 5. Spec and QA

- [x] 5.1 spectrace markers from the new tests to the scenario IDs in the three delta specs
- [x] 5.2 `openspec validate server-sibling-aggregation --strict`; prose + dash + markdown lints
- [x] 5.3 Live QA on dev:server + real browser: a seeded host's tree collapses `grep ×10` (green: 2 running) and `docker ×2` (grey: all exited), keeps `vim` individual and `make -> cc` intact, expands `grep ×10` to its 8-member sample in place, and the Flatten toggle refetches every node (`?flatten=1`)

## 6. Follow-ups (not in this change)

- [ ] 6.1 Lazy per-member expansion (#421) replacing the capped sample with an on-demand fetch
- [ ] 6.2 Non-leaf aggregation (collapsing repeated `sh -c` style parents that each spawn a child), once lazy expansion can re-fetch the folded subtrees
- [ ] 6.3 Honest truncation metadata (#423) and the search endpoint (#418) that lift the 2,000-row fetch cap the in-memory transform cannot
