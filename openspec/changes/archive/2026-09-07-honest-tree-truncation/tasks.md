# Tell the analyst when the process tree is not showing everything: tasks

## 1. The shared window predicate

- [x] `server/detection/internal/mysql/processes.go`: lift the five-clause overlap predicate out of `GetProcessTree` into one `const` plus an argument-builder, and have both the row query and the new count build from it. The count is only meaningful if it counts exactly the rows the SELECT would have returned without its limit, and two hand-maintained copies of that predicate drift into a banner that states a wrong number confidently.
- [x] `CountProcessTree` runs `COUNT(*)` over the same predicate, and BuildTree calls it only when the row read came back at the limit. Fewer rows than the limit proves the limit did not bind, so the total is already known; counting anyway would turn a limit-bounded read into a full window scan on every load. No not-counted sentinel: when it runs, it is exact.

## 2. The result type

- [x] `server/detection/api/types.go`: `ProcessTreeResult` carries `Roots`, `Returned`, `TotalMatched`, `Truncated`. `Returned` is carried rather than left for the client to derive because the handler clamps the requested limit and aggregation makes rendered nodes an unreliable proxy for rows; a client deriving it reintroduces the exact lie the change removes.
- [x] `server/detection/api/service.go`: `BuildTree` returns the struct. A struct rather than a second return value so the handler marshals the response shape directly and a later field (the depth-truncation flag #421 will need) does not churn the signature again.

## 3. Wiring

- [x] `server/detection/internal/graph/query.go`: `BuildTree` issues the count alongside the rows and reports `Truncated` as `Returned < TotalMatched`. `Returned` is captured before aggregation, which folds rows into `×N` headers and would otherwise undercount.
- [x] `server/detection/internal/service/service.go` + `server/detection/internal/operator/handler.go`: delegate and marshal. The handler drops its ad-hoc `map[string]any{"roots": ...}` in favour of the typed result.

## 4. UI

- [x] `ui/src/types.ts`: `TreeResponse` gains the three fields.
- [x] `ui/src/components/ProcessTree.tsx`: keep the metadata in state next to the roots, and render the notice through the existing `process-tree__status--info` affordance rather than adding a new banner primitive.

## 5. Tests

- [x] Handler tests (default tag) for truncated true and false, and that `total_matched` is independent of the requested limit.
- [x] Store test (integration tag) that the count matches the row query's own predicate at the window edges, so a future edit to one cannot silently diverge from the other.
- [x] UI test that the notice renders only when `truncated`, and names both counts.
- [x] `spec:` markers for the five new scenarios.

## 6. Verification

- [x] All three visibility levels, because `BuildTree` is an exported-signature change with implementors at each: `go build ./...` (non-test), `go vet ./...` (the `handler_test.go` fake), `go vet -tags integration ./...` (the integration callers).
- [x] `tmp/golangci-lint-custom run --build-tags=integration ./server/detection/...`, since `task lint:go` does not pass the tag.
