## 1. Spec delta and decision

- [x] 1.1 This proposal + spec deltas pass `openspec validate detection-processor-throughput --strict`
- [x] 1.2 Confirm with the differential property test that the batched fold equals the per-event fold (the equivalence gate the spec pins)

## 2. Set-based graph builder (lever 1: batch the round-trips)

- [x] 2.1 Add a bulk-load store method that returns every candidate process row for a set of `(host_id, pid)` pairs in one query (`mysql.LoadProcessesForKeys`)
- [x] 2.2 Add an in-memory batch session that reproduces the per-event read predicates (`GetProcessByPID`, `GetParentPath`) and write semantics (`InsertProcess`, `UpdateProcessExec`, `UpdateProcessExit`, `CloseStaleProcess`, `ReExec`, `UpdateLastSeenForSnapshot`), including same-batch-created rows (`graph.batchSession`)
- [x] 2.3 Parameterize the builder's fork/exec/exit/heartbeat handlers over the read/write surface (`processStore`) so the same handler code drives both the per-event store and the in-memory session
- [x] 2.4 Flush the session: a multi-row INSERT for new rows (resolving same-batch re-exec `previous_exec_id` linkage), batched `CASE`-keyed UPDATEs for modified loaded rows, in one transaction (`mysql.FlushProcessBatch`)
- [x] 2.5 Preserve poison isolation: drop malformed payloads during the fold; on a permanent data error at flush, degrade the failing batched write to per-row execution and drop the offending row(s); a transient error fails the whole batch
- [x] 2.6 `ProcessBatch` builds a session, folds, flushes; the cross-batch exit-before-snapshot buffer stays on the builder

## 3. Intra-replica concurrency (lever 2)

- [x] 3.1 Add a fixed `DefaultProcessConcurrency` constant in `server/config`; plumb `ProcessConcurrency` through `Deps` and `main.go`
- [x] 3.2 Run N processor workers sharing one builder + engine, each claiming disjoint batches via the existing SKIP LOCKED claim (with a full-batch drain loop)
- [x] 3.3 Bound the shared MySQL pool in `OpenDB` (`SetMaxOpenConns`/`SetMaxIdleConns`) sized to the worker count with request-path headroom

## 4. Tests

- [x] 4.1 Differential PBT: batched (one big batch) == per-event (size-1 batches) over crafted scenarios + a rapid generator (real MySQL)
- [x] 4.2 Extend builder/integration tests for set-based flush + poison fallback (incl. per-row fallback preserving a same-batch re-exec link)
- [x] 4.3 Concurrency-safety test: 8 workers over a shared queue produce a complete, duplicate-free forest and fully drain
- [x] 4.4 Run the efficacy corpus; confirm no detection-output regression (`task test:efficacy` green)

## 5. Re-baseline (lever 3)

- [ ] 5.1 Re-run the #203 single-replica 500-host lane with `--backlog-dsn` + `--pass-max-server-backlog`; record the new single-replica ceiling and the pprof CPU/round-trip delta. Requires the isolated scale stack (MySQL + ClickHouse + fake-agent fleet); run on the scale lane, not in unit CI.
