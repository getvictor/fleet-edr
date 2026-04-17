// Package store provides MySQL-backed event storage for the EDR ingestion server.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"
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
		INDEX idx_events_processed (processed, host_id, timestamp_ns)
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
		INDEX idx_processes_host_ppid (host_id, ppid, fork_time_ns),
		INDEX idx_processes_host_time (host_id, fork_time_ns)
	)`,
	`CREATE TABLE IF NOT EXISTS alerts (
		id           BIGINT AUTO_INCREMENT PRIMARY KEY,
		host_id      VARCHAR(255) NOT NULL,
		rule_id      VARCHAR(64)  NOT NULL,
		severity     ENUM('low', 'medium', 'high', 'critical') NOT NULL,
		title        VARCHAR(512) NOT NULL,
		description  TEXT         NOT NULL,
		process_id   BIGINT       NOT NULL,
		status       ENUM('open', 'acknowledged', 'resolved') NOT NULL DEFAULT 'open',
		created_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
		resolved_at  TIMESTAMP(6) NULL,
		UNIQUE KEY uk_alerts_dedup (host_id, rule_id, process_id),
		INDEX idx_alerts_host (host_id),
		INDEX idx_alerts_status_created (status, created_at),
		CONSTRAINT fk_alerts_process FOREIGN KEY (process_id) REFERENCES processes(id)
	)`,
	`CREATE TABLE IF NOT EXISTS alert_events (
		alert_id  BIGINT       NOT NULL,
		event_id  VARCHAR(255) NOT NULL,
		PRIMARY KEY (alert_id, event_id),
		CONSTRAINT fk_ae_alert FOREIGN KEY (alert_id) REFERENCES alerts(id),
		CONSTRAINT fk_ae_event FOREIGN KEY (event_id) REFERENCES events(event_id)
	)`,
	`CREATE TABLE IF NOT EXISTS commands (
		id           BIGINT AUTO_INCREMENT PRIMARY KEY,
		host_id      VARCHAR(255)  NOT NULL,
		command_type VARCHAR(64)   NOT NULL,
		payload      JSON          NOT NULL,
		status       ENUM('pending', 'acked', 'completed', 'failed') NOT NULL DEFAULT 'pending',
		created_at   TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		acked_at     TIMESTAMP(6)  NULL,
		completed_at TIMESTAMP(6)  NULL,
		result       JSON,
		INDEX idx_commands_host_status (host_id, status),
		INDEX idx_commands_created (created_at)
	)`,
	`CREATE TABLE IF NOT EXISTS hosts (
		host_id      VARCHAR(255) PRIMARY KEY,
		event_count  BIGINT       NOT NULL DEFAULT 0,
		last_seen_ns BIGINT       NOT NULL DEFAULT 0,
		updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
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
// The dsn should be in go-sql-driver/mysql format, e.g. "user:pass@tcp(127.0.0.1:3316)/edr?parseTime=true".
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
			var mysqlErr *mysql.MySQLError
			// 1060 = duplicate column, 1061 = duplicate key name — already applied.
			if errors.As(err, &mysqlErr) && (mysqlErr.Number == 1060 || mysqlErr.Number == 1061) {
				continue
			}
			db.Close()
			return nil, fmt.Errorf("migration: %w", err)
		}
	}

	// Post-schema data migrations (backfills, etc.). Safe to re-run.
	for _, m := range postSchemaMigrations {
		if _, err := db.ExecContext(ctx, m); err != nil {
			db.Close()
			return nil, fmt.Errorf("post-schema migration: %w", err)
		}
	}

	return &Store{db: db}, nil
}

// migrations are idempotent ALTER TABLE statements applied after initial schema creation.
var migrations = []string{
	`ALTER TABLE events ADD COLUMN processed TINYINT(1) NOT NULL DEFAULT 0`,
	`ALTER TABLE events ADD INDEX idx_events_processed (processed, host_id, timestamp_ns)`,
}

// postSchemaMigrations run after schema creation and idempotent ALTER migrations. They use INSERT IGNORE / INSERT ...
// ON DUPLICATE KEY UPDATE so they are safe to re-run.
var postSchemaMigrations = []string{
	// Backfill the hosts summary table from existing events.
	`INSERT INTO hosts (host_id, event_count, last_seen_ns)
	 SELECT host_id, COUNT(*), MAX(timestamp_ns) FROM events GROUP BY host_id
	 ON DUPLICATE KEY UPDATE
	   event_count = VALUES(event_count),
	   last_seen_ns = GREATEST(hosts.last_seen_ns, VALUES(last_seen_ns))`,
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

// CountUnprocessed returns the number of events that have not been fully processed (state 0 or 2).
// This is a read-only query useful for monitoring and testing.
func (s *Store) CountUnprocessed(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM events WHERE processed != 1")
	return count, err
}

// FetchUnprocessed atomically claims up to limit unprocessed events for the graph builder.
// It uses SELECT ... FOR UPDATE SKIP LOCKED to prevent concurrent processors from claiming the same rows,
// and transitions events from state 0 (unprocessed) to 2 (processing) within the same transaction.
// Events are ordered by host_id and timestamp to ensure correct per-host ordering.
func (s *Store) FetchUnprocessed(ctx context.Context, limit int) ([]Event, error) {
	if limit <= 0 {
		return nil, nil
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx for fetch unprocessed: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Rollback after commit is a no-op.

	var events []Event
	err = tx.SelectContext(ctx, &events, `
		SELECT event_id, host_id, timestamp_ns, event_type, payload
		FROM events
		WHERE processed = 0
		ORDER BY host_id, timestamp_ns
		LIMIT ?
		FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch unprocessed select: %w", err)
	}

	if len(events) == 0 {
		return events, tx.Commit()
	}

	eventIDs := make([]string, len(events))
	for i, e := range events {
		eventIDs[i] = e.EventID
	}

	claimQuery, args, err := sqlx.In("UPDATE events SET processed = 2 WHERE event_id IN (?)", eventIDs)
	if err != nil {
		return nil, fmt.Errorf("fetch unprocessed build claim query: %w", err)
	}
	if _, err := tx.ExecContext(ctx, claimQuery, args...); err != nil {
		return nil, fmt.Errorf("fetch unprocessed claim: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit fetch unprocessed tx: %w", err)
	}
	return events, nil
}

// MarkProcessed marks the given events as fully processed (state 2 -> 1) by the graph builder.
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

// UnclaimEvents transitions events from processing (state 2) back to unprocessed (state 0)
// so they can be retried by a future processing cycle.
func (s *Store) UnclaimEvents(ctx context.Context, eventIDs []string) error {
	if len(eventIDs) == 0 {
		return nil
	}
	query, args, err := sqlx.In("UPDATE events SET processed = 0 WHERE processed = 2 AND event_id IN (?)", eventIDs)
	if err != nil {
		return fmt.Errorf("unclaim events build query: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("unclaim events: %w", err)
	}
	return nil
}
