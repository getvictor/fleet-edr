package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// NullRawJSON is a json.RawMessage that correctly scans NULL from MySQL JSON columns.
// json.RawMessage alone fails because the MySQL driver returns nil for NULL JSON,
// and database/sql doesn't know how to assign nil to the named type json.RawMessage.
type NullRawJSON json.RawMessage

func (n *NullRawJSON) Scan(value any) error {
	if value == nil {
		*n = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("NullRawJSON.Scan: unsupported type %T", value)
	}
	// Copy the bytes — the MySQL driver may reuse the underlying buffer for subsequent rows.
	cp := make([]byte, len(b))
	copy(cp, b)
	*n = NullRawJSON(cp)
	return nil
}

func (n NullRawJSON) Value() (driver.Value, error) {
	if len(n) == 0 || string(n) == "null" {
		return nil, nil
	}
	return []byte(n), nil
}

func (n NullRawJSON) MarshalJSON() ([]byte, error) {
	if n == nil {
		return []byte("null"), nil
	}
	return json.RawMessage(n).MarshalJSON()
}

func (n *NullRawJSON) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*n = nil
		return nil
	}
	*n = NullRawJSON(data)
	return nil
}

// Process represents a materialized process record built from fork/exec/exit events.
type Process struct {
	ID               int64       `db:"id" json:"id"`
	HostID           string      `db:"host_id" json:"host_id"`
	PID              int         `db:"pid" json:"pid"`
	PPID             int         `db:"ppid" json:"ppid"`
	Path             string      `db:"path" json:"path"`
	Args             NullRawJSON `db:"args" json:"args,omitempty"`
	UID              *int        `db:"uid" json:"uid,omitempty"`
	GID              *int        `db:"gid" json:"gid,omitempty"`
	CodeSigning      NullRawJSON `db:"code_signing" json:"code_signing,omitempty"`
	SHA256           *string     `db:"sha256" json:"sha256,omitempty"`
	ForkTimeNs       int64       `db:"fork_time_ns" json:"fork_time_ns"`
	ForkIngestedAtNs *int64      `db:"fork_ingested_at_ns" json:"fork_ingested_at_ns,omitempty"`
	ExecTimeNs       *int64      `db:"exec_time_ns" json:"exec_time_ns,omitempty"`
	ExitTimeNs       *int64      `db:"exit_time_ns" json:"exit_time_ns,omitempty"`
	ExitIngestedAtNs *int64      `db:"exit_ingested_at_ns" json:"exit_ingested_at_ns,omitempty"`
	ExitReason       *string     `db:"exit_reason" json:"exit_reason,omitempty"`
	ExitCode         *int        `db:"exit_code" json:"exit_code,omitempty"`
	// PreviousExecID points at the row representing the prior generation in
	// a same-PID re-exec chain (issue #10). A process that calls execve()
	// multiple times without forking (e.g. `python → sh → bash → payload`
	// via shell exec-optimization) keeps its PID, so the processor inserts
	// a new row per exec and links it backward via this field. The first
	// exec after a fork has PreviousExecID == nil — that's the chain root.
	PreviousExecID *int64 `db:"previous_exec_id" json:"previous_exec_id,omitempty"`
}

// ExitReason values for Process.ExitReason.
const (
	ExitReasonEvent             = "event"              // normal — populated from an observed ES exit event
	ExitReasonTTLReconciliation = "ttl_reconciliation" // synthesized — process stayed "running" past the TTL; server forced a gray
	ExitReasonPIDReuse          = "pid_reuse"          // synthesized — an incoming fork on the same PID forced closure of the prior row
	ExitReasonReExec            = "reexec"             // synthesized — superseded by a new execve() on the same PID (issue #10 chain)
)

// HostSummary provides an overview of a host's event activity.
type HostSummary struct {
	HostID     string `db:"host_id" json:"host_id"`
	EventCount int64  `db:"event_count" json:"event_count"`
	LastSeenNs int64  `db:"last_seen_ns" json:"last_seen_ns"`
}

// TimeRange defines a nanosecond-precision time window for queries.
type TimeRange struct {
	FromNs int64
	ToNs   int64
}

// InsertProcess inserts a new process record (typically from a fork event).
// The caller is expected to pass the ingest timestamp of the originating fork
// event in ForkIngestedAtNs so cross-source correlation queries can anchor
// against a server-controlled clock; nil is tolerated for back-compat with
// pre-migration callers.
func (s *Store) InsertProcess(ctx context.Context, p Process) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO processes
			(host_id, pid, ppid, path, args, uid, gid, code_signing, sha256,
			 fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
			 exit_ingested_at_ns, exit_code, previous_exec_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.HostID, p.PID, p.PPID, p.Path, p.Args, p.UID, p.GID,
		p.CodeSigning, p.SHA256, p.ForkTimeNs, p.ForkIngestedAtNs, p.ExecTimeNs, p.ExitTimeNs,
		p.ExitIngestedAtNs, p.ExitCode, p.PreviousExecID,
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

// ProcessExecUpdate carries the exec-time metadata patched onto an existing process row.
// Grouped as a struct so callers don't pass a 10-parameter positional list.
type ProcessExecUpdate struct {
	HostID      string
	PID         int
	ExecTimeNs  int64
	Path        string
	Args        NullRawJSON
	UID         *int
	GID         *int
	CodeSigning NullRawJSON
	SHA256      *string
}

// UpdateProcessExec updates an existing process record with exec-time metadata.
func (s *Store) UpdateProcessExec(ctx context.Context, u ProcessExecUpdate) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET path = ?, args = ?, uid = ?, gid = ?, code_signing = ?, sha256 = ?, exec_time_ns = ?
		WHERE host_id = ? AND pid = ? AND exit_time_ns IS NULL
		ORDER BY fork_time_ns DESC LIMIT 1`,
		u.Path, u.Args, u.UID, u.GID, u.CodeSigning, u.SHA256, u.ExecTimeNs,
		u.HostID, u.PID,
	)
	return err
}

// UpdateProcessExit sets the exit timestamp and code for a running process.
// exitIngestedAtNs is the server-stamped ingest time of the originating exit
// event and anchors the upper bound of correlation queries against a
// server-controlled clock (issue #7). exit_reason is set to ExitReasonEvent
// so the TTL reconciler can tell observed exits from synthesized ones.
func (s *Store) UpdateProcessExit(ctx context.Context, hostID string, pid int,
	exitTimeNs, exitIngestedAtNs int64, exitCode int) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET exit_time_ns = ?, exit_ingested_at_ns = ?,
		                    exit_reason = ?, exit_code = ?
		WHERE host_id = ? AND pid = ? AND exit_time_ns IS NULL
		ORDER BY fork_time_ns DESC LIMIT 1`,
		exitTimeNs, exitIngestedAtNs, ExitReasonEvent, exitCode, hostID, pid,
	)
	return err
}

// ReconcileStaleProcesses forces an exit_time_ns on processes that have
// been "running" (no observed exit event) for longer than maxAgeNs since
// their fork. Addresses issue #6: agent drops, kernel back-pressure, and
// SQLite-queue pruning all cause exit events to go missing, leaving rows
// green forever. The synthesized exit is marked ExitReasonTTLReconciliation
// so the UI can show a "forced gray" badge rather than pretending it was an
// observed clean exit.
//
// cutoffNs is the fork-time cutoff: rows with fork_time_ns < cutoffNs and
// still no exit_time_ns are reconciled. maxAgeNs is the TTL delta added to
// fork_time_ns to form the synthesized exit_time_ns (so the UI shows the
// node as having exited at roughly the TTL boundary, not "just now", which
// would otherwise clump every reconciled row into one visual row at the
// current wall-clock moment). Returns rows affected.
func (s *Store) ReconcileStaleProcesses(ctx context.Context, cutoffNs, maxAgeNs int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE processes
		SET exit_time_ns = fork_time_ns + ?,
		    exit_ingested_at_ns = COALESCE(fork_ingested_at_ns, fork_time_ns) + ?,
		    exit_reason = ?
		WHERE exit_time_ns IS NULL
		  AND fork_time_ns < ?`,
		maxAgeNs, maxAgeNs, ExitReasonTTLReconciliation, cutoffNs,
	)
	if err != nil {
		return 0, fmt.Errorf("reconcile stale processes: %w", err)
	}
	return res.RowsAffected()
}

// CloseReExecGeneration finalizes the prior generation of a same-PID
// re-exec chain when a new execve() on that PID lands. The row's
// exit_time_ns is set to the new exec's kernel time and exit_reason to
// ExitReasonReExec so analytics can distinguish "died by re-exec" from
// normal exits, PID-reuse closes, and TTL reconciliations.
func (s *Store) CloseReExecGeneration(ctx context.Context, rowID int64, exitTimeNs, exitIngestedAtNs int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes
		SET exit_time_ns = ?, exit_ingested_at_ns = ?, exit_reason = ?
		WHERE id = ? AND exit_time_ns IS NULL`,
		exitTimeNs, exitIngestedAtNs, ExitReasonReExec, rowID,
	)
	return err
}

// GetExecChain walks previous_exec_id backward from the given current row
// and returns the chain oldest-first (NOT including the current row). For
// a non-re-exec process the result is an empty slice. Bounded to
// maxChainLen rows to stop a cycle (shouldn't happen — previous_exec_id
// is strictly decreasing — but FK cycles from bad data shouldn't lock up
// a query).
func (s *Store) GetExecChain(ctx context.Context, current Process) ([]Process, error) {
	const maxChainLen = 64
	var chain []Process
	prevID := current.PreviousExecID
	for depth := 0; prevID != nil && depth < maxChainLen; depth++ {
		var p Process
		err := s.db.GetContext(ctx, &p, `
			SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256,
			       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
			       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id
			FROM processes WHERE id = ?`, *prevID)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("walk exec chain at id=%d: %w", *prevID, err)
		}
		chain = append(chain, p)
		prevID = p.PreviousExecID
	}
	// Result is newest-first from the walk; reverse so the caller gets
	// chronological order (oldest exec first). Callers rendering a timeline
	// want that ordering implicitly.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, nil
}

// CloseStaleProcess force-closes a process record that hasn't exited yet.
// Used to handle PID reuse: when a fork arrives for a PID that already has an
// active (non-exited) record, close the old one first. closedAtNs is treated
// as both the kernel exit time and the ingest anchor because the close is
// synthesized from the new fork, not from an actual exit event. exit_reason
// is set to ExitReasonPIDReuse so analysts can distinguish this synthesis
// path from both observed exits (ExitReasonEvent) and the TTL reconciler
// (ExitReasonTTLReconciliation).
func (s *Store) CloseStaleProcess(ctx context.Context, hostID string, pid int, closedAtNs int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET exit_time_ns = ?, exit_ingested_at_ns = ?, exit_reason = ?
		WHERE host_id = ? AND pid = ? AND exit_time_ns IS NULL`,
		closedAtNs, closedAtNs, ExitReasonPIDReuse, hostID, pid,
	)
	return err
}

// GetParentPath returns the path of the most recent process with the given PID
// that is still alive (or was alive most recently). Used for fork-without-exec
// to inherit the parent's path.
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

// GetProcessTree returns all processes for a host within a time range.
func (s *Store) GetProcessTree(ctx context.Context, hostID string, tr TimeRange, limit int) ([]Process, error) {
	var procs []Process
	// Include any process that was alive at any point during the window:
	//   1. Forked during the window (fork_time_ns between from and to), OR
	//   2. Still running and forked before the window (fork < from AND no exit), OR
	//   3. Exited during the window but forked before it (fork < from AND exit >= from)
	// This ensures long-running processes like Safari that forked hours ago still appear
	// in the 15-min view while they're running. Order DESC so the most recent activity
	// survives the limit.
	err := s.db.SelectContext(ctx, &procs, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256,
		       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id
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

// GetProcessByPID returns the process that was active at the given timestamp.
func (s *Store) GetProcessByPID(ctx context.Context, hostID string, pid int, atTimeNs int64) (*Process, error) {
	var proc Process
	err := s.db.GetContext(ctx, &proc, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256,
		       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id
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

// GetChildProcesses returns processes whose PPID matches the given PID and were
// forked within the given time range. The range is kernel-time (fork_time_ns)
// because parent/child causality is an on-host property, not a server-clock
// one — that is the opposite of GetNetworkEventsForProcess (issue #7), whose
// cross-source correlation has to run on ingest time.
func (s *Store) GetChildProcesses(ctx context.Context, hostID string, ppid int, tr TimeRange) ([]Process, error) {
	var procs []Process
	err := s.db.SelectContext(ctx, &procs, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256,
		       fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns,
		       exit_ingested_at_ns, exit_reason, exit_code, previous_exec_id
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

// GetNetworkEventsForProcess returns network_connect and dns_query events
// attributed to the given PID within a time range.
//
// The range is filtered on ingested_at_ns (server-stamped) rather than on
// the source-kernel timestamp_ns, because ES and NE clocks drift by tens of
// milliseconds and NE-sourced events can arrive with timestamps before the
// ES-sourced fork event of the same process. See issue #7. Results are still
// ORDER BY timestamp_ns so the UI renders them in the order they happened
// on the host, not the order the server saw them.
func (s *Store) GetNetworkEventsForProcess(ctx context.Context, hostID string, pid int, tr TimeRange) ([]Event, error) {
	var events []Event
	err := s.db.SelectContext(ctx, &events, `
		SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload
		FROM events
		WHERE host_id = ? AND event_type IN ('network_connect', 'dns_query')
		  AND ingested_at_ns >= ? AND ingested_at_ns <= ?
		  AND JSON_EXTRACT(payload, '$.pid') = ?
		ORDER BY timestamp_ns`,
		hostID, tr.FromNs, tr.ToNs, pid,
	)
	if err != nil {
		return nil, fmt.Errorf("query network events: %w", err)
	}
	return events, nil
}

// ListHosts returns a summary of all hosts that have sent events.
func (s *Store) ListHosts(ctx context.Context) ([]HostSummary, error) {
	var hosts []HostSummary
	err := s.db.SelectContext(ctx, &hosts, `
		SELECT host_id, event_count, last_seen_ns
		FROM hosts
		ORDER BY last_seen_ns DESC`)
	if err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}
	return hosts, nil
}

// CountOfflineHosts returns how many rows in `hosts` have `last_seen_ns` at or
// before (now - threshold). Used by the Phase 4 OTel gauge `edr.offline.hosts`.
// The `<=` boundary matches `HostList.tsx`'s `Date.now() - lastSeenMs >= threshold`
// predicate so the UI pill and gauge agree on hosts seen exactly at the cutoff.
// A host with last_seen_ns == 0 (never seen) counts as offline.
func (s *Store) CountOfflineHosts(ctx context.Context, threshold time.Duration) (int, error) {
	cutoff := time.Now().Add(-threshold).UnixNano()
	var n int
	if err := s.db.GetContext(ctx, &n, `
		SELECT COUNT(*) FROM hosts WHERE last_seen_ns <= ?
	`, cutoff); err != nil {
		return 0, fmt.Errorf("count offline hosts: %w", err)
	}
	return n, nil
}

// UpdateHostLastSeen bumps `hosts.last_seen_ns` to `now.UnixNano()` for hostID. Phase 4
// uses this from the GET /api/v1/commands path so the 5-second commander poll doubles
// as a liveness heartbeat. The GREATEST guard stops a clock-skewed request from
// regressing an already-observed fresher timestamp.
//
// The INSERT path handles the "host enrolled but never sent events" case so the hosts
// row exists and the UI can render the host even before ingest touches it.
func (s *Store) UpdateHostLastSeen(ctx context.Context, hostID string, now time.Time) error {
	ts := now.UnixNano()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO hosts (host_id, event_count, last_seen_ns)
		VALUES (?, 0, ?)
		ON DUPLICATE KEY UPDATE
			last_seen_ns = GREATEST(last_seen_ns, VALUES(last_seen_ns))
	`, hostID, ts)
	if err != nil {
		return fmt.Errorf("update host last_seen %s: %w", hostID, err)
	}
	return nil
}

// UpsertHosts incrementally updates the hosts summary table for a batch of ingested events. It aggregates event counts
// and max timestamps per host, then upserts them in a single statement.
func (s *Store) UpsertHosts(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}

	// Aggregate per host.
	type hostStats struct {
		count   int64
		maxTSNs int64
	}
	byHost := make(map[string]*hostStats)
	for _, e := range events {
		st, ok := byHost[e.HostID]
		if !ok {
			st = &hostStats{}
			byHost[e.HostID] = st
		}
		st.count++
		if e.TimestampNs > st.maxTSNs {
			st.maxTSNs = e.TimestampNs
		}
	}

	for hostID, st := range byHost {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO hosts (host_id, event_count, last_seen_ns)
			VALUES (?, ?, ?)
			ON DUPLICATE KEY UPDATE
				event_count = event_count + VALUES(event_count),
				last_seen_ns = GREATEST(last_seen_ns, VALUES(last_seen_ns))`,
			hostID, st.count, st.maxTSNs)
		if err != nil {
			return fmt.Errorf("upsert host %s: %w", hostID, err)
		}
	}
	return nil
}

// DB exposes the underlying database connection for use by other packages
// that need transactional access (e.g., the graph builder).
func (s *Store) DB() *sqlx.DB {
	return s.db
}
