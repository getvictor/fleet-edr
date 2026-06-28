package mysql

import (
	"context"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/detection/api"
)

// processBatchSelectColumns is the full process-row projection, shared by the bulk preload here and the single-row reads in
// processes.go so the in-memory batch overlay sees byte-identical rows to the per-event path.
const processBatchSelectColumns = `id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
	fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
	exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
	is_snapshot, last_seen_ns`

// loadKeyChunk caps the (host_id, pid) pairs folded into one preload statement. The row-constructor IN list binds two
// placeholders per key, so 1000 keys stay well under MySQL's placeholder ceiling while collapsing the per-event SELECTs into a
// handful of statements.
const loadKeyChunk = 1000

// processUpdateChunk caps the rows folded into one set-based UPDATE. Each row binds 14 CASE values plus one IN-list id (15
// placeholders), so a few hundred per chunk keeps the statement well bounded.
const processUpdateChunk = 200

// HostPID identifies a process lineage key for the batch preload.
type HostPID struct {
	HostID string
	PID    int
}

// LoadProcessesForKeys returns every process row for the given (host_id, pid) pairs, ordered oldest-first by (fork_time_ns, id).
// The graph builder's batch path preloads the full candidate set in one round-trip and then resolves every per-event read
// (GetProcessByPID, GetParentPath) against the in-memory overlay instead of issuing a SELECT per event. All rows for each key are
// returned (no exit-time filter) so the overlay can reproduce GetParentPath, which orders by fork time regardless of exit. The
// per-(host_id, pid) row count is bounded by the retention prune, so this stays small in steady state.
func (s *Store) LoadProcessesForKeys(ctx context.Context, keys []HostPID) ([]api.Process, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	var out []api.Process
	for start := 0; start < len(keys); start += loadKeyChunk {
		end := min(start+loadKeyChunk, len(keys))
		chunk, err := s.loadProcessesChunk(ctx, keys[start:end])
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
	}
	return out, nil
}

func (s *Store) loadProcessesChunk(ctx context.Context, keys []HostPID) ([]api.Process, error) {
	var sb strings.Builder
	sb.WriteString("SELECT ")
	sb.WriteString(processBatchSelectColumns)
	sb.WriteString(" FROM processes WHERE (host_id, pid) IN (")
	args := make([]any, 0, len(keys)*2)
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("(?, ?)")
		args = append(args, k.HostID, k.PID)
	}
	sb.WriteString(") ORDER BY fork_time_ns, id")
	var procs []api.Process
	if err := s.db.SelectContext(ctx, &procs, sb.String(), args...); err != nil {
		return nil, fmt.Errorf("load processes for %d keys: %w", len(keys), err)
	}
	return procs, nil
}

// NewProcessRow is one row the batch fold wants inserted. Proc carries the final field values. PrevNewIndex links a re-exec child
// to a prior generation that was ALSO created in this batch (an index into the plan's NewRows slice); it is -1 when there is no
// same-batch predecessor, in which case Proc.PreviousExecID already holds the real id of a preloaded predecessor (or nil). The
// split exists because a same-batch predecessor has no id until it is inserted, so the flush resolves the link after assigning ids.
type NewProcessRow struct {
	Proc         api.Process
	PrevNewIndex int
}

// ProcessRowUpdate is the final state of a preloaded row the batch fold mutated (an exit, an exec patch, a PID-reuse close, a
// re-exec close, or a freshness bump). The flush writes the full mutable column set to the row's final value, so a column the fold
// left untouched is rewritten to its existing value (a no-op) rather than tracked per-column. Immutable columns (host_id, pid,
// ppid, fork_time_ns, fork_ingested_at_ns, previous_exec_id, is_snapshot) are never in this set.
type ProcessRowUpdate struct {
	ID               int64
	Path             string
	Args             api.NullRawJSON
	UID              *int
	GID              *int
	CodeSigning      api.NullRawJSON
	SHA256           *string
	CDHash           *string
	ExecTimeNs       *int64
	PIDVersion       *uint32
	ExitTimeNs       *int64
	ExitIngestedAtNs *int64
	ExitReason       *string
	ExitCode         *int
	LastSeenNs       *int64
}

// ProcessBatchPlan is the set of writes the graph builder's in-memory fold produced for one batch: new rows to insert (in creation
// order) and preloaded rows to update. The plan is pure data so the builder stays free of SQL and the fold is unit-testable.
type ProcessBatchPlan struct {
	NewRows []NewProcessRow
	Updates []ProcessRowUpdate
}

// Empty reports whether the plan would issue no writes.
func (p ProcessBatchPlan) Empty() bool { return len(p.NewRows) == 0 && len(p.Updates) == 0 }

// FlushProcessBatch persists a batch plan. The fast path runs in one transaction: a single multi-row INSERT for the new rows (when
// none links to a same-batch predecessor) plus chunked set-based UPDATEs for the modified rows, collapsing what used to be
// ~1000+ per-event round-trips into a small constant.
//
// Poison isolation (issue #379) is preserved: if any batched write fails with a permanent data error (a value the database can
// never store), the whole fast path rolls back and the plan is re-applied row by row, dropping just the offending row(s) and
// committing the rest, so one poison row cannot wedge the batch. A transient (retryable) fault is returned so the caller nacks and
// the processor retries the whole batch, exactly as the per-event path did.
func (s *Store) FlushProcessBatch(ctx context.Context, plan ProcessBatchPlan) error {
	if plan.Empty() {
		return nil
	}
	err := s.flushProcessBatchFast(ctx, plan)
	if err == nil {
		return nil
	}
	if !IsPermanentDataError(err) {
		return err // transient fault: caller nacks and the batch is retried
	}
	// A row carries a value the DB can never store. Re-apply per row so the poison row is dropped and the rest persists.
	return s.flushProcessBatchPerRow(ctx, plan)
}

// flushProcessBatchFast applies the plan with set-based statements inside one transaction. Any error rolls the transaction back via
// the deferred Rollback; the caller classifies it (permanent -> per-row fallback, transient -> retry).
func (s *Store) flushProcessBatchFast(ctx context.Context, plan ProcessBatchPlan) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin process-batch tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if err := s.insertNewRowsBatched(ctx, tx, plan.NewRows); err != nil {
		return err
	}
	if err := s.updateRowsBatched(ctx, tx, plan.Updates); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit process-batch tx: %w", err)
	}
	return nil
}

// insertNewRowsBatched inserts every new row in a single multi-row INSERT when none links to a same-batch predecessor (the common
// case). When a same-batch re-exec link exists (a process forked, exec'd, and re-exec'd within one batch), the predecessor's id is
// not known until it is inserted, so the rows are inserted individually in creation order to resolve the linkage live.
func (s *Store) insertNewRowsBatched(ctx context.Context, ext sqlx.ExtContext, rows []NewProcessRow) error {
	if len(rows) == 0 {
		return nil
	}
	if hasSameBatchLink(rows) {
		return insertNewRowsLinked(ctx, ext, rows, false)
	}
	var sb strings.Builder
	sb.WriteString(insertProcessColumns)
	sb.WriteString(" VALUES ")
	args := make([]any, 0, len(rows)*21)
	for i, r := range rows {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(insertProcessPlaceholders)
		args = appendInsertProcessArgs(args, r.Proc)
	}
	if _, err := ext.ExecContext(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("batch insert %d process rows: %w", len(rows), err)
	}
	return nil
}

// hasSameBatchLink reports whether any new row links to a predecessor created in the same batch (PrevNewIndex >= 0), which forces
// the per-row insert path so the link can be resolved to a real id.
func hasSameBatchLink(rows []NewProcessRow) bool {
	for _, r := range rows {
		if r.PrevNewIndex >= 0 {
			return true
		}
	}
	return false
}

// insertNewRowsLinked inserts the new rows one at a time in creation order, resolving each same-batch re-exec link to the real id
// the predecessor received. Creation order guarantees a predecessor is inserted before the child that links to it. When dropPoison
// is true a per-row permanent data error drops that row (and any later row whose predecessor was dropped loses its link) instead of
// failing; a transient error always aborts.
func insertNewRowsLinked(ctx context.Context, ext sqlx.ExtContext, rows []NewProcessRow, dropPoison bool) error {
	ids := make([]int64, len(rows)) // assigned id per row; 0 for a row that was dropped or has no predecessor
	for i, r := range rows {
		if r.PrevNewIndex >= 0 {
			// Link to a predecessor created earlier in this batch. A dropped predecessor (id 0) leaves the link nil.
			if prevID := ids[r.PrevNewIndex]; prevID != 0 {
				r.Proc.PreviousExecID = &prevID
			} else if dropPoison {
				r.Proc.PreviousExecID = nil
			}
		}
		id, err := insertOneProcessRow(ctx, ext, r.Proc)
		if err != nil {
			if dropPoison && IsPermanentDataError(err) {
				continue // drop the poison row; ids[i] stays 0
			}
			return err
		}
		ids[i] = id
	}
	return nil
}

// insertOneProcessRow inserts a single process row on the given executor and returns its auto-increment id. Shares the column list
// and arg order with the batched INSERT and the per-event InsertProcess.
func insertOneProcessRow(ctx context.Context, ext sqlx.ExtContext, p api.Process) (int64, error) {
	res, err := ext.ExecContext(ctx, insertProcessColumns+" VALUES "+insertProcessPlaceholders,
		appendInsertProcessArgs(nil, p)...)
	if err != nil {
		return 0, fmt.Errorf("insert process row (host=%s pid=%d): %w", p.HostID, p.PID, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("insert process row last id: %w", err)
	}
	return id, nil
}

// updateRowsBatched applies the modified-row updates with chunked, set-based CASE statements (one statement per chunk of rows
// rather than one per row). Each row's full mutable column set is rewritten to its final value.
func (s *Store) updateRowsBatched(ctx context.Context, ext sqlx.ExtContext, updates []ProcessRowUpdate) error {
	for start := 0; start < len(updates); start += processUpdateChunk {
		end := min(start+processUpdateChunk, len(updates))
		if err := updateRowsChunk(ctx, ext, updates[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// mutableUpdateColumns is the set CASE-keyed by id in the batched UPDATE, in a fixed order shared by the SQL builder and the arg
// appender. Immutable identity/fork columns are intentionally excluded.
var mutableUpdateColumns = []string{
	"path", "args", "uid", "gid", "code_signing", "sha256", "cdhash",
	"exec_time_ns", "pidversion", "exit_time_ns", "exit_ingested_at_ns", "exit_reason", "exit_code", "last_seen_ns",
}

func updateRowsChunk(ctx context.Context, ext sqlx.ExtContext, updates []ProcessRowUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString("UPDATE processes SET ")
	// Pre-size: each column contributes one CASE arm (id + value) per row; the trailing IN list one id per row.
	args := make([]any, 0, len(updates)*(len(mutableUpdateColumns)*2+1))
	for c, col := range mutableUpdateColumns {
		if c > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(col)
		sb.WriteString(" = CASE id")
		for _, u := range updates {
			sb.WriteString(" WHEN ? THEN ?")
			args = append(args, u.ID, updateColumnValue(col, u))
		}
		sb.WriteString(" END")
	}
	sb.WriteString(" WHERE id IN (")
	for i, u := range updates {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("?")
		args = append(args, u.ID)
	}
	sb.WriteString(")")
	if _, err := ext.ExecContext(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("batch update %d process rows: %w", len(updates), err)
	}
	return nil
}

// updateColumnValue returns the bound value for a column in the CASE-keyed UPDATE. Centralised so the column order in the SQL
// builder and the values stay in lockstep.
func updateColumnValue(col string, u ProcessRowUpdate) any {
	switch col {
	case "path":
		return u.Path
	case "args":
		return u.Args
	case "uid":
		return u.UID
	case "gid":
		return u.GID
	case "code_signing":
		return u.CodeSigning
	case "sha256":
		return u.SHA256
	case "cdhash":
		return u.CDHash
	case "exec_time_ns":
		return u.ExecTimeNs
	case "pidversion":
		return u.PIDVersion
	case "exit_time_ns":
		return u.ExitTimeNs
	case "exit_ingested_at_ns":
		return u.ExitIngestedAtNs
	case "exit_reason":
		return u.ExitReason
	case "exit_code":
		return u.ExitCode
	case "last_seen_ns":
		return u.LastSeenNs
	default:
		panic("mysql: unknown mutable update column " + col) // unreachable: driven by mutableUpdateColumns
	}
}

// flushProcessBatchPerRow re-applies the plan one statement at a time in a fresh transaction, dropping rows that hit a permanent
// data error and logging nothing here (the builder logs the drop with event context). Used only after the batched fast path failed
// with a permanent error, so this slow path runs at most once per poison batch.
func (s *Store) flushProcessBatchPerRow(ctx context.Context, plan ProcessBatchPlan) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin process-batch per-row tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if err := insertNewRowsLinked(ctx, tx, plan.NewRows, true); err != nil {
		return err
	}
	for _, u := range plan.Updates {
		if err := updateRowsChunk(ctx, tx, []ProcessRowUpdate{u}); err != nil {
			if IsPermanentDataError(err) {
				continue // drop the poison update; the rest still applies
			}
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit process-batch per-row tx: %w", err)
	}
	return nil
}
