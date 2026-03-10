// Package store provides MySQL-backed event storage for the EDR ingestion server.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

// schemaStatements are executed sequentially to bootstrap the database.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS events (
		event_id     VARCHAR(255) PRIMARY KEY,
		host_id      VARCHAR(255) NOT NULL,
		timestamp_ns BIGINT       NOT NULL,
		event_type   VARCHAR(64)  NOT NULL,
		payload      JSON         NOT NULL,
		processed    TINYINT(1)   NOT NULL DEFAULT 0,
		created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
		INDEX idx_events_host_id (host_id),
		INDEX idx_events_type (event_type),
		INDEX idx_events_timestamp (timestamp_ns),
		INDEX idx_events_processed (processed, created_at)
	)`,
	`CREATE TABLE IF NOT EXISTS processes (
		id           BIGINT AUTO_INCREMENT PRIMARY KEY,
		host_id      VARCHAR(255) NOT NULL,
		pid          INT          NOT NULL,
		ppid         INT          NOT NULL,
		path         TEXT         NOT NULL,
		args         JSON,
		uid          INT,
		gid          INT,
		code_signing JSON,
		sha256       VARCHAR(64),
		fork_time_ns BIGINT       NOT NULL,
		exec_time_ns BIGINT,
		exit_time_ns BIGINT,
		exit_code    INT,
		INDEX idx_processes_host_pid (host_id, pid, fork_time_ns),
		INDEX idx_processes_host_ppid (host_id, ppid),
		INDEX idx_processes_host_time (host_id, fork_time_ns)
	)`,
}

// Event represents the canonical event envelope.
type Event struct {
	EventID     string          `db:"event_id" json:"event_id"`
	HostID      string          `db:"host_id" json:"host_id"`
	TimestampNs int64           `db:"timestamp_ns" json:"timestamp_ns"`
	EventType   string          `db:"event_type" json:"event_type"`
	Payload     json.RawMessage `db:"payload" json:"payload"`
}

// Store manages event persistence in MySQL.
type Store struct {
	db *sqlx.DB
}

// New opens a connection to MySQL and ensures the schema exists.
// The dsn should be in go-sql-driver/mysql format, e.g. "user:pass@tcp(127.0.0.1:3306)/edr?parseTime=true".
func New(ctx context.Context, dsn string) (*Store, error) {
	if !strings.Contains(dsn, "parseTime") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "parseTime=true"
	}

	db, err := sqlx.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	for _, stmt := range schemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("create schema: %w", err)
		}
	}

	// Run idempotent migrations for schema changes to existing tables.
	for _, m := range migrations {
		if _, err := db.ExecContext(ctx, m); err != nil {
			// Ignore "Duplicate column" errors for already-applied migrations.
			if !strings.Contains(err.Error(), "Duplicate column") && !strings.Contains(err.Error(), "Duplicate key name") {
				db.Close()
				return nil, fmt.Errorf("migration: %w", err)
			}
		}
	}

	return &Store{db: db}, nil
}

// migrations are idempotent ALTER TABLE statements applied after initial schema creation.
var migrations = []string{
	`ALTER TABLE events ADD COLUMN processed TINYINT(1) NOT NULL DEFAULT 0`,
	`ALTER TABLE events ADD INDEX idx_events_processed (processed, created_at)`,
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// InsertEvents upserts a batch of events. Duplicates (by event_id) are ignored.
func (s *Store) InsertEvents(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Rollback after commit is a no-op.

	stmt, err := tx.PrepareContext(ctx, `
		INSERT IGNORE INTO events (event_id, host_id, timestamp_ns, event_type, payload)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, e := range events {
		payloadBytes, err := json.Marshal(e.Payload)
		if err != nil {
			return fmt.Errorf("marshal payload for %s: %w", e.EventID, err)
		}
		if _, err := stmt.ExecContext(ctx, e.EventID, e.HostID, e.TimestampNs, e.EventType, payloadBytes); err != nil {
			return fmt.Errorf("insert %s: %w", e.EventID, err)
		}
	}

	return tx.Commit()
}

// CountEvents returns the total number of events.
func (s *Store) CountEvents(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM events")
	return count, err
}

// FetchUnprocessed returns up to limit events that have not yet been processed by the graph builder.
// Events are ordered by host_id and timestamp to ensure correct per-host ordering.
func (s *Store) FetchUnprocessed(ctx context.Context, limit int) ([]Event, error) {
	var events []Event
	err := s.db.SelectContext(ctx, &events, `
		SELECT event_id, host_id, timestamp_ns, event_type, payload
		FROM events
		WHERE processed = 0
		ORDER BY host_id, timestamp_ns
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch unprocessed: %w", err)
	}
	return events, nil
}

// MarkProcessed marks the given events as processed by the graph builder.
func (s *Store) MarkProcessed(ctx context.Context, eventIDs []string) error {
	if len(eventIDs) == 0 {
		return nil
	}
	query, args, err := sqlx.In("UPDATE events SET processed = 1 WHERE event_id IN (?)", eventIDs)
	if err != nil {
		return fmt.Errorf("mark processed build query: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("mark processed: %w", err)
	}
	return nil
}
