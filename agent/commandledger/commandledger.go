// Package commandledger is the agent's durable command-execution ledger: a small SQLite table, keyed by the server command id, that
// records whether a command has been claimed (executing) or has reached a terminal outcome (completed / failed). Both the poll path
// (commander) and the push path (controlclient) consult it through the shared commander.Executor, so a command's side effect runs at
// most once across transports AND across agent restarts (issue #558). That closes the kill_process re-execution window: a re-delivered
// command replays its recorded outcome instead of signalling its PID again, which is the safety guard against killing a reused PID.
package commandledger

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	// modernc.org/sqlite is the CGo-free SQLite driver, registered under "sqlite"; same driver the event queue uses.
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS command_outcomes (
	command_id INTEGER PRIMARY KEY,
	status     TEXT NOT NULL,
	result     BLOB,
	updated_at INTEGER NOT NULL
);`

// Store is the durable command ledger. It is safe for concurrent use (a single pooled connection serializes writes).
type Store struct {
	db     *sql.DB
	logger *slog.Logger
}

// Options configures Open.
type Options struct {
	Logger *slog.Logger
}

// Open opens (creating if needed) the command ledger at dbPath. It mirrors the event queue's SQLite pragmas: a 5s busy timeout, WAL
// journaling, and a bounded WAL size, applied to every pooled connection via the DSN.
func Open(ctx context.Context, dbPath string, opts Options) (*Store, error) {
	dsn := dbPath +
		"?_pragma=busy_timeout%3d5000" +
		"&_pragma=journal_mode%3dwal" +
		"&_pragma=journal_size_limit%3d33554432"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open command ledger: %w", err)
	}
	// SQLite allows one writer at a time; a single connection avoids SQLITE_BUSY contention between pooled connections.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create command ledger schema: %w", err)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{db: db, logger: logger}, nil
}

// Close closes the ledger database.
func (s *Store) Close() error { return s.db.Close() }

// Lookup returns the recorded status and result for a command id. seen is false if the id is unknown.
func (s *Store) Lookup(ctx context.Context, id int64) (status string, result json.RawMessage, seen bool, err error) {
	var res []byte
	row := s.db.QueryRowContext(ctx, `SELECT status, result FROM command_outcomes WHERE command_id = ?`, id)
	switch scanErr := row.Scan(&status, &res); {
	case scanErr == sql.ErrNoRows:
		return "", nil, false, nil
	case scanErr != nil:
		return "", nil, false, fmt.Errorf("command ledger lookup: %w", scanErr)
	}
	return status, json.RawMessage(res), true, nil
}

// Claim atomically records a write-ahead claim (claimStatus, e.g. "executing") for a command id if no row exists yet. It returns
// won=true when THIS call recorded the claim, so the caller owns execution and must run the side effect. If a row already exists it
// returns won=false with the existing status/result, so the caller must NOT run the side effect: it replays a recorded terminal
// outcome, or terminalizes a prior interrupted claim. The INSERT...ON CONFLICT DO NOTHING is a single atomic statement, so two
// concurrent callers can never both win the claim (and therefore never both run a non-idempotent side effect).
func (s *Store) Claim(ctx context.Context, id int64, claimStatus string) (won bool, status string, result json.RawMessage, err error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO command_outcomes (command_id, status, result, updated_at) VALUES (?, ?, NULL, ?) ON CONFLICT(command_id) DO NOTHING`,
		id, claimStatus, time.Now().Unix())
	if err != nil {
		return false, "", nil, fmt.Errorf("command ledger claim: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return true, claimStatus, nil, nil
	}
	status, result, _, err = s.Lookup(ctx, id)
	return false, status, result, err
}

// Delete removes a command's ledger row. Used to roll back a write-ahead claim when the side effect was not started (the acknowledgement
// report failed), so the command stays eligible for a fresh claim on re-delivery instead of being stranded as a never-run "executing".
func (s *Store) Delete(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM command_outcomes WHERE command_id = ?`, id); err != nil {
		return fmt.Errorf("command ledger delete: %w", err)
	}
	return nil
}

// Mark upserts the status (and result) for a command id, stamping updated_at to now. result may be nil.
func (s *Store) Mark(ctx context.Context, id int64, status string, result json.RawMessage) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO command_outcomes (command_id, status, result, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(command_id) DO UPDATE SET status = excluded.status, result = excluded.result, updated_at = excluded.updated_at`,
		id, status, []byte(result), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("command ledger mark: %w", err)
	}
	return nil
}

// Prune deletes ledger rows older than maxAge and returns the number deleted, keeping the ledger bounded. A pruned row only matters if
// the same command id is re-delivered after maxAge, which the server's command lifetime makes implausible.
func (s *Store) Prune(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).Unix()
	res, err := s.db.ExecContext(ctx, `DELETE FROM command_outcomes WHERE updated_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("command ledger prune: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
