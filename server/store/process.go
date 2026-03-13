package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"

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
	ID          int64       `db:"id" json:"id"`
	HostID      string      `db:"host_id" json:"host_id"`
	PID         int         `db:"pid" json:"pid"`
	PPID        int         `db:"ppid" json:"ppid"`
	Path        string      `db:"path" json:"path"`
	Args        NullRawJSON `db:"args" json:"args,omitempty"`
	UID         *int        `db:"uid" json:"uid,omitempty"`
	GID         *int        `db:"gid" json:"gid,omitempty"`
	CodeSigning NullRawJSON `db:"code_signing" json:"code_signing,omitempty"`
	SHA256      *string     `db:"sha256" json:"sha256,omitempty"`
	ForkTimeNs  int64       `db:"fork_time_ns" json:"fork_time_ns"`
	ExecTimeNs  *int64      `db:"exec_time_ns" json:"exec_time_ns,omitempty"`
	ExitTimeNs  *int64      `db:"exit_time_ns" json:"exit_time_ns,omitempty"`
	ExitCode    *int        `db:"exit_code" json:"exit_code,omitempty"`
}

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
func (s *Store) InsertProcess(ctx context.Context, p Process) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO processes (host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, fork_time_ns, exec_time_ns, exit_time_ns, exit_code)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.HostID, p.PID, p.PPID, p.Path, p.Args, p.UID, p.GID,
		p.CodeSigning, p.SHA256, p.ForkTimeNs, p.ExecTimeNs, p.ExitTimeNs, p.ExitCode,
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

// UpdateProcessExec updates an existing process record with exec-time metadata.
func (s *Store) UpdateProcessExec(ctx context.Context, hostID string, pid int, execTimeNs int64,
	path string, args NullRawJSON, uid, gid *int, codeSigning NullRawJSON, sha256 *string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET path = ?, args = ?, uid = ?, gid = ?, code_signing = ?, sha256 = ?, exec_time_ns = ?
		WHERE host_id = ? AND pid = ? AND exit_time_ns IS NULL
		ORDER BY fork_time_ns DESC LIMIT 1`,
		path, args, uid, gid, codeSigning, sha256, execTimeNs,
		hostID, pid,
	)
	return err
}

// UpdateProcessExit sets the exit timestamp and code for a running process.
func (s *Store) UpdateProcessExit(ctx context.Context, hostID string, pid int, exitTimeNs int64, exitCode int) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET exit_time_ns = ?, exit_code = ?
		WHERE host_id = ? AND pid = ? AND exit_time_ns IS NULL
		ORDER BY fork_time_ns DESC LIMIT 1`,
		exitTimeNs, exitCode, hostID, pid,
	)
	return err
}

// CloseStaleProcess force-closes a process record that hasn't exited yet.
// Used to handle PID reuse: when a fork arrives for a PID that already has an
// active (non-exited) record, close the old one first.
func (s *Store) CloseStaleProcess(ctx context.Context, hostID string, pid int, closedAtNs int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE processes SET exit_time_ns = ?
		WHERE host_id = ? AND pid = ? AND exit_time_ns IS NULL`,
		closedAtNs, hostID, pid,
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
	err := s.db.SelectContext(ctx, &procs, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256,
		       fork_time_ns, exec_time_ns, exit_time_ns, exit_code
		FROM processes
		WHERE host_id = ? AND fork_time_ns >= ? AND fork_time_ns <= ?
		ORDER BY fork_time_ns
		LIMIT ?`,
		hostID, tr.FromNs, tr.ToNs, limit,
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
		       fork_time_ns, exec_time_ns, exit_time_ns, exit_code
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

// GetChildProcesses returns processes whose PPID matches the given PID and were forked within the given time range.
func (s *Store) GetChildProcesses(ctx context.Context, hostID string, ppid int, tr TimeRange) ([]Process, error) {
	var procs []Process
	err := s.db.SelectContext(ctx, &procs, `
		SELECT id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256,
		       fork_time_ns, exec_time_ns, exit_time_ns, exit_code
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
func (s *Store) GetNetworkEventsForProcess(ctx context.Context, hostID string, pid int, tr TimeRange) ([]Event, error) {
	var events []Event
	err := s.db.SelectContext(ctx, &events, `
		SELECT event_id, host_id, timestamp_ns, event_type, payload
		FROM events
		WHERE host_id = ? AND event_type IN ('network_connect', 'dns_query')
		  AND timestamp_ns >= ? AND timestamp_ns <= ?
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
		SELECT host_id, COUNT(*) AS event_count, MAX(timestamp_ns) AS last_seen_ns
		FROM events
		GROUP BY host_id
		ORDER BY last_seen_ns DESC`)
	if err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}
	return hosts, nil
}

// DB exposes the underlying database connection for use by other packages
// that need transactional access (e.g., the graph builder).
func (s *Store) DB() *sqlx.DB {
	return s.db
}
