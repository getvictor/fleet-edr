package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/fleetdm/edr/server/detection/api"
)

// InsertProcess inserts a new process record (typically from a fork event). The caller is expected to pass the ingest timestamp of
// the originating fork event in ForkIngestedAtNs so cross-source correlation queries can anchor against a server-controlled clock;
// nil is tolerated for back-compat with pre-migration callers.
func (s *Store) InsertProcess(ctx context.Context, p api.Process) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO processes
			(host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash,
			 fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
			 exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
			 is_snapshot, last_seen_ns)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.HostID, p.PID, p.PPID, p.Path, p.Args, p.UID, p.GID,
		p.CodeSigning, p.SHA256, p.CDHash, p.ForkTimeNs, p.ForkIngestedAtNs, p.ExecTimeNs, p.ExitTimeNs,
		p.ExitIngestedAtNs, p.ExitReason, p.ExitCode, p.PreviousExecID,
		p.IsSnapshot, p.LastSeenNs,
	)
	if err != nil {
		return 0, fmt.Errorf("insert process: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("insert process last id: %w", err)
	}
	return id, nil
}

// UpdateLastSeenForSnapshot bumps last_seen_ns on the live snapshot row matching (host_id, pid). Only affects rows where
// is_snapshot=TRUE AND exit_time_ns IS NULL - non-snapshot rows and already-exited rows are not touched, so a stray heartbeat for a
// recycled PID cannot resurrect an exited row. Returns nil on success (including the no-row-affected case, which is the common path
// when the heartbeat lands before the snapshot row arrives or after a re-exec flipped is_snapshot off).
func (s *Store) UpdateLastSeenForSnapshot(ctx context.Context, hostID string, pid int, lastSeenNs int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET last_seen_ns = ?
		WHERE host_id = ? AND pid = ? AND is_snapshot = TRUE AND exit_time_ns IS NULL
		ORDER BY fork_time_ns DESC LIMIT 1`,
		lastSeenNs, hostID, pid,
	)
	return err
}

// ProcessExecUpdate carries the exec-time metadata patched onto an existing process row. Grouped as a struct so callers don't pass a
// 10-parameter positional list.
type ProcessExecUpdate struct {
	HostID      string
	PID         int
	ExecTimeNs  int64
	Path        string
	Args        api.NullRawJSON
	UID         *int
	GID         *int
	CodeSigning api.NullRawJSON
	SHA256      *string
	CDHash      *string
}

// UpdateProcessExec updates an existing process record with exec-time
// metadata.
func (s *Store) UpdateProcessExec(ctx context.Context, u ProcessExecUpdate) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET path = ?, args = ?, uid = ?, gid = ?, code_signing = ?, sha256 = ?, cdhash = ?, exec_time_ns = ?
		WHERE host_id = ? AND pid = ? AND exit_time_ns IS NULL
		ORDER BY fork_time_ns DESC LIMIT 1`,
		u.Path, u.Args, u.UID, u.GID, u.CodeSigning, u.SHA256, u.CDHash, u.ExecTimeNs,
		u.HostID, u.PID,
	)
	return err
}

// UpdateProcessExit sets the exit timestamp, code, and reason for a running process. exitIngestedAtNs is the server-stamped ingest
// time of the originating exit event and anchors the upper bound of correlation queries against a server-controlled clock (issue #7).
// reason distinguishes kernel-observed exits (ExitReasonEvent: the default) from agent-side reconciled ones (ExitReasonHostReconciled:
// issue #6 client half) so the UI can render the latter with a "reconciled" badge instead of pretending it was a clean observed exit.
// An empty reason normalises to ExitReasonEvent.
func (s *Store) UpdateProcessExit(ctx context.Context, hostID string, pid int,
	exitTimeNs, exitIngestedAtNs int64, exitCode int, reason string,
) (int64, error) {
	if reason == "" {
		reason = api.ExitReasonEvent
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE processes SET exit_time_ns = ?, exit_ingested_at_ns = ?,
		                    exit_reason = ?, exit_code = ?
		WHERE host_id = ? AND pid = ? AND exit_time_ns IS NULL
		ORDER BY fork_time_ns DESC LIMIT 1`,
		exitTimeNs, exitIngestedAtNs, reason, exitCode, hostID, pid,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ReconcileStaleProcesses forces an exit_time_ns on processes that
// have been running (no observed exit event) for longer than maxAgeNs
// since their fork. Addresses issue #6: agent drops, kernel
// back-pressure, and SQLite-queue pruning all cause exit events to
// go missing, leaving rows green forever. The synthesized exit is
// marked ExitReasonTTLReconciliation so the UI can show a
// "forced gray" badge rather than pretending it was an observed
// clean exit.
//
// cutoffNs is the fork-time cutoff: rows with fork_time_ns < cutoffNs
// and still no exit_time_ns are reconciled. maxAgeNs is the TTL
// delta added to fork_time_ns to form the synthesized exit_time_ns
// (so the UI shows the node as having exited at roughly the TTL
// boundary). Returns rows affected.
func (s *Store) ReconcileStaleProcesses(ctx context.Context, cutoffNs, maxAgeNs int64) (int64, error) {
	// Predicate uses COALESCE(last_seen_ns, fork_time_ns) instead of plain fork_time_ns so
	// snapshot rows (issue #173) with a recent agent-emitted heartbeat are exempt from the
	// issue #6 force-exit. Non-snapshot rows have last_seen_ns IS NULL forever, so COALESCE
	// degenerates to fork_time_ns and the original #6 behaviour holds for them.
	//
	// Synthesised exit_time_ns also uses the same COALESCE so a snapshot row that DID age
	// out (no heartbeat in 6h) lands its exit at last_seen + maxAge rather than fork + maxAge.
	// That keeps the UI's "exited at" timestamp meaningful for snapshot rows whose
	// fork_time_ns is the extension-startup moment rather than a real exec time.
	res, err := s.db.ExecContext(ctx, `
		UPDATE processes
		SET exit_time_ns = COALESCE(last_seen_ns, fork_time_ns) + ?,
		    exit_ingested_at_ns = COALESCE(last_seen_ns, fork_ingested_at_ns, fork_time_ns) + ?,
		    exit_reason = ?
		WHERE exit_time_ns IS NULL
		  AND COALESCE(last_seen_ns, fork_time_ns) < ?`,
		maxAgeNs, maxAgeNs, api.ExitReasonTTLReconciliation, cutoffNs,
	)
	if err != nil {
		return 0, fmt.Errorf("reconcile stale processes: %w", err)
	}
	return res.RowsAffected()
}

// ReExec finalizes the prior generation of a same-PID re-exec chain
// AND inserts the new generation in a single transaction. Prior to
// this the close + insert were two separate statements; if the
// insert failed, the PID would appear exited with no current
// generation row, losing the process's running state.
//
// The prior-row UPDATE predicate accepts two prior-row states:
//
//	(a) exit_time_ns IS NULL: the normal case, prior row is live.
//	(b) exit_reason = ExitReasonTTLReconciliation: the TTL reconciler
//	    synthesized an exit that turned out to be wrong (the process
//	    was still alive and just re-exec'd). We overwrite the TTL
//	    guess with the real re-exec close so the chain semantics are
//	    correct.
//
// When RowsAffected is 0 (prior row was observed-exited or pid-reused
// real terminal states we must NOT overwrite), the new row is still
// inserted but with previous_exec_id = NULL so it anchors a fresh
// chain. Caller gets reLinked=false to log that edge.
//
// newRow.PreviousExecID is ignored and set by this method.
func (s *Store) ReExec(
	ctx context.Context, priorID int64,
	exitTimeNs, exitIngestedAtNs int64,
	newRow api.Process,
) (newID int64, reLinked bool, err error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("begin tx for re-exec: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx, `
		UPDATE processes
		SET exit_time_ns = ?, exit_ingested_at_ns = ?, exit_reason = ?
		WHERE id = ?
		  AND (exit_time_ns IS NULL OR exit_reason = ?)`,
		exitTimeNs, exitIngestedAtNs, api.ExitReasonReExec, priorID, api.ExitReasonTTLReconciliation,
	)
	if err != nil {
		return 0, false, fmt.Errorf("close prior re-exec row id=%d: %w", priorID, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("close prior re-exec rows affected id=%d: %w", priorID, err)
	}
	reLinked = rows > 0
	if reLinked {
		newRow.PreviousExecID = &priorID
	} else {
		newRow.PreviousExecID = nil
	}

	ins, err := tx.ExecContext(ctx, `
		INSERT INTO processes
			(host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash,
			 fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
			 exit_ingested_at_ns, exit_code, previous_exec_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newRow.HostID, newRow.PID, newRow.PPID, newRow.Path, newRow.Args, newRow.UID, newRow.GID,
		newRow.CodeSigning, newRow.SHA256, newRow.CDHash, newRow.ForkTimeNs, newRow.ForkIngestedAtNs,
		newRow.ExecTimeNs, newRow.ExitTimeNs, newRow.ExitIngestedAtNs, newRow.ExitCode,
		newRow.PreviousExecID,
	)
	if err != nil {
		return 0, false, fmt.Errorf("insert new re-exec generation: %w", err)
	}
	newID, err = ins.LastInsertId()
	if err != nil {
		return 0, false, fmt.Errorf("insert new re-exec LastInsertId: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("commit re-exec tx: %w", err)
	}
	return newID, reLinked, nil
}

// GetExecChain walks previous_exec_id backward from the given current
// row and returns the chain oldest-first (NOT including the current
// row). For a non-re-exec process the result is an empty slice.
// Bounded to maxChainLen rows to stop a cycle.
//
// Issue #94: prior shape was N sequential round-trips (one per chain
// link, capped at 64). The recursive CTE collapses that into one
// query. The depth column inside the CTE serves two purposes: a
// belt-and-suspenders cycle guard (in case of a corrupt FK), and the
// ordering key for the result. The anchor row sits at depth=0 and
// each recursion step adds one, so depth tracks structural distance
// back from `current.PreviousExecID`. ORDER BY depth DESC therefore
// yields oldest-first - independent of fork_time_ns, which can tie or
// drift across agents (per Gemini Code Assist + Copilot review on
// PR #110).
//
// The SELECT is scoped by host_id as well as id so a corrupted
// previous_exec_id value can never surface a row from a different
// host (defense-in-depth, preserved from the prior implementation).
func (s *Store) GetExecChain(ctx context.Context, current api.Process) ([]api.Process, error) {
	const maxChainLen = 64
	if current.PreviousExecID == nil {
		return nil, nil
	}
	var chain []api.Process
	err := s.db.SelectContext(ctx, &chain, `
		WITH RECURSIVE chain AS (
			SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash,
			       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
			       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
			       is_snapshot, last_seen_ns,
			       0 AS depth
			FROM processes
			WHERE id = ? AND host_id = ?
			UNION ALL
			SELECT p.id, p.host_id, p.pid, p.ppid, p.path, p.args, p.uid, p.gid,
			       p.code_signing, p.sha256, p.cdhash, p.fork_time_ns, p.fork_ingested_at_ns,
			       p.exec_time_ns, p.exit_time_ns, p.exit_ingested_at_ns,
			       p.exit_reason, p.exit_code, p.previous_exec_id,
			       p.is_snapshot, p.last_seen_ns,
			       c.depth + 1
			FROM processes p
			JOIN chain c ON p.id = c.previous_exec_id AND p.host_id = c.host_id
			WHERE c.depth < ?
		)
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash,
		       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
		       is_snapshot, last_seen_ns
		FROM chain
		ORDER BY depth DESC`,
		*current.PreviousExecID, current.HostID, maxChainLen-1,
	)
	if err != nil {
		return nil, fmt.Errorf("walk exec chain at id=%d: %w", *current.PreviousExecID, err)
	}
	return chain, nil
}

// CloseStaleProcess force-closes a process record that hasn't exited yet. Used to handle PID reuse: when a fork arrives for a PID
// that already has an active (non-exited) record, close the old one first. exit_reason is set to ExitReasonPIDReuse so analysts can
// distinguish this synthesis path.
func (s *Store) CloseStaleProcess(ctx context.Context, hostID string, pid int, closedAtNs int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET exit_time_ns = ?, exit_ingested_at_ns = ?, exit_reason = ?
		WHERE host_id = ? AND pid = ? AND exit_time_ns IS NULL`,
		closedAtNs, closedAtNs, api.ExitReasonPIDReuse, hostID, pid,
	)
	return err
}

// GetParentPath returns the path of the most recent process with the given PID that is still alive (or was alive most recently).
// Used for fork-without-exec to inherit the parent's path.
func (s *Store) GetParentPath(ctx context.Context, hostID string, pid int) (string, error) {
	var path string
	err := s.db.GetContext(ctx, &path, `
		SELECT path FROM processes
		WHERE host_id = ? AND pid = ?
		ORDER BY fork_time_ns DESC LIMIT 1`,
		hostID, pid,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return path, err
}

// GetProcessTree returns all processes for a host within a time range. Includes any process that was alive at any point during the
// window so long-running processes still appear in short-window views.
func (s *Store) GetProcessTree(ctx context.Context, hostID string, tr api.TimeRange, limit int) ([]api.Process, error) {
	var procs []api.Process
	err := s.db.SelectContext(ctx, &procs, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash,
		       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
		       is_snapshot, last_seen_ns
		FROM processes
		WHERE host_id = ?
		  AND (
		    (fork_time_ns >= ? AND fork_time_ns <= ?)
		    OR (fork_time_ns < ? AND exit_time_ns IS NULL)
		    OR (fork_time_ns < ? AND exit_time_ns >= ?)
		  )
		ORDER BY fork_time_ns DESC
		LIMIT ?`,
		hostID, tr.FromNs, tr.ToNs, tr.FromNs, tr.FromNs, tr.FromNs, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query process tree: %w", err)
	}
	return procs, nil
}

// GetProcessByPID returns the process that was active at the given
// timestamp. Satisfies api.GraphReader.
func (s *Store) GetProcessByPID(ctx context.Context, hostID string, pid int, atTimeNs int64) (*api.Process, error) {
	var proc api.Process
	err := s.db.GetContext(ctx, &proc, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash,
		       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
		       is_snapshot, last_seen_ns
		FROM processes
		WHERE host_id = ? AND pid = ? AND fork_time_ns <= ?
		  AND (exit_time_ns IS NULL OR exit_time_ns >= ?)
		ORDER BY fork_time_ns DESC
		LIMIT 1`,
		hostID, pid, atTimeNs, atTimeNs,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query process by pid: %w", err)
	}
	return &proc, nil
}

// GetChildProcesses returns processes whose PPID matches the given PID and were forked within the given time range. Satisfies
// api.GraphReader.
func (s *Store) GetChildProcesses(ctx context.Context, hostID string, ppid int, tr api.TimeRange) ([]api.Process, error) {
	var procs []api.Process
	err := s.db.SelectContext(ctx, &procs, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash,
		       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
		       is_snapshot, last_seen_ns
		FROM processes
		WHERE host_id = ? AND ppid = ? AND fork_time_ns >= ? AND fork_time_ns <= ?
		ORDER BY fork_time_ns`,
		hostID, ppid, tr.FromNs, tr.ToNs,
	)
	if err != nil {
		return nil, fmt.Errorf("query child processes: %w", err)
	}
	return procs, nil
}

// GetNetworkEventsForProcess returns network_connect and dns_query
// events attributed to the given PID within a time range. Filtered
// on ingested_at_ns (server-stamped) rather than timestamp_ns
// because ES and NE clocks drift (issue #7).
//
// The payload_pid predicate is index-backed by
// idx_events_host_type_pid_ingested (issue #92): the prior
// JSON_EXTRACT predicate forced a full scan of the events table.
// payload_pid is a STORED generated column; the index entry is
// populated on insert so this query is a range scan, not a JSON
// reparse, regardless of how many rows live in events.
func (s *Store) GetNetworkEventsForProcess(ctx context.Context, hostID string, pid int, tr api.TimeRange) ([]api.Event, error) {
	var events []api.Event
	err := s.db.SelectContext(ctx, &events, `
		SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload
		FROM events
		WHERE host_id = ? AND event_type IN ('network_connect', 'dns_query')
		  AND payload_pid = ?
		  AND ingested_at_ns >= ? AND ingested_at_ns <= ?
		ORDER BY timestamp_ns`,
		hostID, pid, tr.FromNs, tr.ToNs,
	)
	if err != nil {
		return nil, fmt.Errorf("query network events: %w", err)
	}
	return events, nil
}
