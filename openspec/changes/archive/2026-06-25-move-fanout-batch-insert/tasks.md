# Tasks

## 1. Response context: batched insert

- [x] 1.1 Add `Store.InsertBatch(ctx, hostIDs, commandType, payload) (int, error)` to `server/response/internal/mysql/store.go`, chunked multi-row `INSERT` (chunk size 256), mirroring `bulkInsertAlertEvents`. Returns the count of rows that landed; on a chunk error returns the count so far plus the error.
- [x] 1.2 Add `Service.InsertBatch` validation wrapper to `server/response/internal/service/service.go` (empty `commandType` / `payload` / `hostIDs` wrap `ErrInvalidInsertRequest`).
- [x] 1.3 Add `InsertBatch` to the `response/api.Service` interface with doc.

## 2. Rules application-control fan-out

- [x] 2.1 Replace `appcontrol.CommandInserter` with `CommandBatchInserter` (batch signature) on the `Service`, `ServiceDeps`, and `NewService` nil-guard.
- [x] 2.2 Rewrite `Service.fanout` to collect the resolved unique host set and call the batch inserter once; `failed = attempted - inserted`.
- [x] 2.3 Thread the batch closure through `server/rules/bootstrap` (`Deps.CommandBatchInserter`) and `server/cmd/fleet-edr-server/main.go` (`responseCtx.Service().InsertBatch`).

## 3. Tests

- [x] 3.1 Store: `InsertBatch` lands N rows, crosses the chunk boundary (> 256), payloads byte-identical, status pending, correct count.
- [x] 3.2 Service: validation branches for empty `commandType` / `payload` / `hostIDs`.
- [x] 3.3 appcontrol: fan-out issues a single batch call with the full unique host set; `fanout_hosts` counts uniques; a failed batch records `fanout_failed` for every host in it (new scenario marker).

## 4. Gates

- [x] 4.1 `openspec validate move-fanout-batch-insert --strict`.
- [x] 4.2 `go build ./...`, integration tests, `task lint:go`, `task lint:dashes`.
- [x] 4.3 Manual: create a rule against dev:server with multiple enrolled hosts; confirm batched rows in `commands` and accurate audit counts.
