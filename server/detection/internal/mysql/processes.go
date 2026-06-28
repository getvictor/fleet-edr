package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/detection/api"
)

// snapshotBumpChunkPIDs caps the distinct PIDs folded into one set-based heartbeat UPDATE. Keeps the placeholder count well under
// MySQL's limit (3 per pid: two in the CASE, one in the IN list) while collapsing a heartbeat-heavy ingest batch into a handful of
// statements rather than one UPDATE per heartbeat.
const snapshotBumpChunkPIDs = 500

// insertProcessColumns and insertProcessPlaceholders pin the 21-column process INSERT shape in one place, shared by the per-event
// InsertProcess, the batched multi-row INSERT, and the per-row poison fallback (processbatch.go), so the column list and arg order
// can never drift between the per-event and set-based write paths.
const insertProcessColumns = `INSERT INTO processes
		(host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
		 fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		 exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
		 is_snapshot, last_seen_ns)`

const insertProcessPlaceholders = `(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// appendInsertProcessArgs appends the 21 INSERT bind values for p in insertProcessColumns order.
func appendInsertProcessArgs(args []any, p api.Process) []any {
	return append(args,
		p.HostID, p.PID, p.PPID, p.Path, p.Args, p.UID, p.GID,
		p.CodeSigning, p.SHA256, p.CDHash, p.PIDVersion, p.ForkTimeNs, p.ForkIngestedAtNs, p.ExecTimeNs, p.ExitTimeNs,
		p.ExitIngestedAtNs, p.ExitReason, p.ExitCode, p.PreviousExecID,
		p.IsSnapshot, p.LastSeenNs,
	)
}

// InsertProcess inserts a new process record (typically from a fork event). The caller is expected to pass the ingest timestamp of
// the originating fork event in ForkIngestedAtNs so cross-source correlation queries can anchor against a server-controlled clock;
// nil is tolerated for back-compat with pre-migration callers.
func (s *Store) InsertProcess(ctx context.Context, p api.Process) (int64, error) {
	res, err := s.db.ExecContext(ctx, insertProcessColumns+" VALUES "+insertProcessPlaceholders,
		appendInsertProcessArgs(nil, p)...)
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
// is_snapshot=TRUE AND exit_time_ns IS NULL: non-snapshot rows and already-exited rows are not touched, so a stray heartbeat for a
// recycled PID cannot resurrect an exited row. Returns nil on success (including the no-row-affected case, which is the common path
// when the heartbeat lands before the snapshot row arrives or after a re-exec flipped is_snapshot off).
func (s *Store) UpdateLastSeenForSnapshot(ctx context.Context, hostID string, pid int, lastSeenNs int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET last_seen_ns = ?
		WHERE host_id = ? AND pid = ? AND is_snapshot = TRUE AND exit_time_ns IS NULL
		ORDER BY fork_time_ns DESC, id DESC LIMIT 1`,
		lastSeenNs, hostID, pid,
	)
	return err
}

// SnapshotHeartbeat is one heartbeat's freshness signal: the PID it pings and the event timestamp to record as last_seen_ns.
type SnapshotHeartbeat struct {
	PID         int
	TimestampNs int64
}

// BumpSnapshotLastSeenBatch applies the live-snapshot freshness bump for a batch of heartbeats using set-based, chunked UPDATEs
// (one statement per chunk of distinct PIDs, not one per heartbeat). The scoping matches UpdateLastSeenForSnapshot (live,
// snapshot-originated rows for the host only), so the freshness semantics and no-op cases are those of the single-row path; this
// just relocates the bump to ingest time so the heartbeat never has to be persisted as a retained event row (issue #408). A
// heartbeat that matches no row is a no-op, as before. The chunks are independent best-effort bumps, not wrapped in a transaction:
// a partial failure simply leaves some PIDs to be re-bumped by the next heartbeat, well within the TTL window. All heartbeats in a
// request share one host_id (host-identity pinning guarantees it), so the caller passes hostID once.
func (s *Store) BumpSnapshotLastSeenBatch(ctx context.Context, hostID string, beats []SnapshotHeartbeat) error {
	if len(beats) == 0 {
		return nil
	}
	// Dedupe by PID, keeping the latest timestamp. A batch rarely repeats a PID, but if it does we want the freshest last_seen and a
	// single CASE arm per PID. `order` preserves first-seen PID order so the chunking is deterministic.
	latest := make(map[int]int64, len(beats))
	order := make([]int, 0, len(beats))
	for _, b := range beats {
		ts, ok := latest[b.PID]
		if !ok {
			order = append(order, b.PID)
		}
		if !ok || b.TimestampNs > ts {
			latest[b.PID] = b.TimestampNs
		}
	}
	// One set-based UPDATE per chunk (a CASE maps each PID to its timestamp) instead of one UPDATE per heartbeat, so the statement
	// count on the ingest hot path scales with distinct-PID chunks, not heartbeat volume. The per-PID `ORDER BY fork_time_ns DESC
	// LIMIT 1` of the single-row path is dropped: there is at most one live snapshot row per (host_id, pid) in normal operation, so
	// the scoped WHERE matches the same row; in the anomalous duplicate case all live snapshot rows for the PID are bumped to the
	// same fresh timestamp, which is harmless (they stay exempt from the TTL reconciler, the intended effect).
	for start := 0; start < len(order); start += snapshotBumpChunkPIDs {
		end := min(start+snapshotBumpChunkPIDs, len(order))
		if err := s.bumpSnapshotLastSeenChunk(ctx, hostID, order[start:end], latest); err != nil {
			return err
		}
	}
	return nil
}

// bumpSnapshotLastSeenChunk applies one set-based heartbeat UPDATE for up to snapshotBumpChunkPIDs distinct PIDs: a CASE maps each
// PID to its latest timestamp, scoped to live snapshot rows for the host.
func (s *Store) bumpSnapshotLastSeenChunk(ctx context.Context, hostID string, pids []int, latest map[int]int64) error {
	var sb strings.Builder
	sb.WriteString("UPDATE processes SET last_seen_ns = CASE pid")
	args := make([]any, 0, len(pids)*3+1)
	for _, pid := range pids {
		sb.WriteString(" WHEN ? THEN ?")
		args = append(args, pid, latest[pid])
	}
	sb.WriteString(" END WHERE host_id = ? AND is_snapshot = TRUE AND exit_time_ns IS NULL AND pid IN (")
	args = append(args, hostID)
	for i, pid := range pids {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("?")
		args = append(args, pid)
	}
	sb.WriteString(")")
	if _, err := s.db.ExecContext(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("bump snapshot last_seen chunk (host=%s, %d pids): %w", hostID, len(pids), err)
	}
	return nil
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
	// PIDVersion is the kernel PID generation from the exec event, when present. A re-exec keeps the same generation as the
	// forked process, so this normally equals what the fork already stored; the UPDATE fills it via COALESCE so a fork that
	// arrived without pidversion (or a missed fork) still gets the identity from the exec, without a present value clobbering
	// an existing one to NULL.
	PIDVersion *uint32
}

// UpdateProcessExec updates an existing process record with exec-time
// metadata.
func (s *Store) UpdateProcessExec(ctx context.Context, u ProcessExecUpdate) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET path = ?, args = ?, uid = ?, gid = ?, code_signing = ?, sha256 = ?, cdhash = ?, exec_time_ns = ?,
		                    pidversion = COALESCE(?, pidversion)
		WHERE host_id = ? AND pid = ? AND exit_time_ns IS NULL
		ORDER BY fork_time_ns DESC, id DESC LIMIT 1`,
		u.Path, u.Args, u.UID, u.GID, u.CodeSigning, u.SHA256, u.CDHash, u.ExecTimeNs, u.PIDVersion,
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
		ORDER BY fork_time_ns DESC, id DESC LIMIT 1`,
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
			(host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
			 fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
			 exit_ingested_at_ns, exit_code, previous_exec_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newRow.HostID, newRow.PID, newRow.PPID, newRow.Path, newRow.Args, newRow.UID, newRow.GID,
		newRow.CodeSigning, newRow.SHA256, newRow.CDHash, newRow.PIDVersion, newRow.ForkTimeNs, newRow.ForkIngestedAtNs,
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
// yields oldest-first, independent of fork_time_ns, which can tie or
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
			SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
			       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
			       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
			       is_snapshot, last_seen_ns,
			       0 AS depth
			FROM processes
			WHERE id = ? AND host_id = ?
			UNION ALL
			SELECT p.id, p.host_id, p.pid, p.ppid, p.path, p.args, p.uid, p.gid,
			       p.code_signing, p.sha256, p.cdhash, p.pidversion, p.fork_time_ns, p.fork_ingested_at_ns,
			       p.exec_time_ns, p.exit_time_ns, p.exit_ingested_at_ns,
			       p.exit_reason, p.exit_code, p.previous_exec_id,
			       p.is_snapshot, p.last_seen_ns,
			       c.depth + 1
			FROM processes p
			JOIN chain c ON p.id = c.previous_exec_id AND p.host_id = c.host_id
			WHERE c.depth < ?
		)
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
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
		ORDER BY fork_time_ns DESC, id DESC LIMIT 1`,
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
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
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
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
		       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
		       is_snapshot, last_seen_ns
		FROM processes
		WHERE host_id = ? AND pid = ? AND fork_time_ns <= ?
		  AND (exit_time_ns IS NULL OR exit_time_ns >= ?)
		ORDER BY fork_time_ns DESC, id DESC
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

// GetProcessByPIDVersion returns the process generation matching the exact (host_id, pid, pidversion) identity at the event time
// atNs, or nil when none matches. The kernel PID generation pins the lifetime directly, so the result is immune to PID reuse (a
// recycled PID gets a higher pidversion) without clock-drift padding. Backed by idx_processes_host_pid_pidversion. Rows whose
// pidversion is NULL (legacy agents, or a row whose audit token was unavailable) never match here, so correlation falls back to
// GetProcessByPID for events that carry no pidversion (issue #403).
//
// A same-PID re-exec chain (issue #10) shares one pidversion across its generations (execve keeps the kernel generation), so the
// identity can match more than one row. When it does, atNs disambiguates: the ORDER BY prefers the generation that was the
// running image at atNs, bracketing on COALESCE(exec_time_ns, fork_time_ns) <= atNs and (exit_time_ns IS NULL OR atNs <=
// exit_time_ns). The exit bound is inclusive, matching GetProcessByPID; at the exact re-exec instant the newer generation still
// wins because its exec_time_ns equals that instant and the COALESCE tiebreak prefers it. A re-exec chain preserves the original
// fork_time_ns on every generation, so fork_time_ns cannot order them; exec_time_ns (the image-replacement instant) is the
// running-image boundary, and COALESCE falls back to fork_time_ns for a pre-exec (pure fork) generation. When the identity
// matches a single row (the PID-reuse case) that row is returned regardless of atNs, so identity still beats clock skew; when no
// generation brackets atNs the lookup falls back to the live, then newest-image, generation within the set.
func (s *Store) GetProcessByPIDVersion(ctx context.Context, hostID string, pid int, pidversion uint32, atNs int64) (*api.Process, error) {
	var proc api.Process
	err := s.db.GetContext(ctx, &proc, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
		       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id,
		       is_snapshot, last_seen_ns
		FROM processes
		WHERE host_id = ? AND pid = ? AND pidversion = ?
		ORDER BY (COALESCE(exec_time_ns, fork_time_ns) <= ? AND (exit_time_ns IS NULL OR exit_time_ns >= ?)) DESC,
		         (exit_time_ns IS NULL) DESC,
		         COALESCE(exec_time_ns, fork_time_ns) DESC,
		         id DESC
		LIMIT 1`,
		hostID, pid, pidversion, atNs, atNs,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query process by pidversion: %w", err)
	}
	return &proc, nil
}

// GetChildProcesses returns processes whose PPID matches the given PID and were forked within the given time range. Satisfies
// api.GraphReader.
func (s *Store) GetChildProcesses(ctx context.Context, hostID string, ppid int, tr api.TimeRange) ([]api.Process, error) {
	var procs []api.Process
	err := s.db.SelectContext(ctx, &procs, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
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
// GetNetworkEventsForProcess delegates to the visibility EventArchive (ADR-0015): post-cutover the events live in ClickHouse, not the
// MySQL events table, so the detection store no longer owns this query. The method is kept on the store so its callers (the process-detail
// graph query and the DNS-C2 correlation rule, both reaching the store as a detection api.GraphReader) stay unchanged across the cutover.
func (s *Store) GetNetworkEventsForProcess(ctx context.Context, hostID string, pid int, tr api.TimeRange) ([]api.Event, error) {
	return s.archive.NetworkEventsForProcess(ctx, hostID, pid, tr)
}
