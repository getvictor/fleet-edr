// Package store provides MySQL-backed event storage for the EDR ingestion server.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/XSAM/otelsql"
	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
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
	// host_token_id is SHA-256 of the bearer token. It is a deterministic lookup key so Verify
	// can fetch a single candidate row by indexed equality rather than scan every active row.
	// The argon2id hash+salt is still the authenticator — token_id is one-way, so leaking the
	// column does not let an attacker recover the token. UNIQUE prevents accidental collisions
	// from two hosts somehow winning the 2^-256 lottery.
	`CREATE TABLE IF NOT EXISTS enrollments (
		host_id          VARCHAR(255) PRIMARY KEY,
		host_token_id    VARBINARY(32)  NOT NULL,
		host_token_hash  VARBINARY(255) NOT NULL,
		host_token_salt  VARBINARY(32)  NOT NULL,
		hostname         VARCHAR(255)   NOT NULL,
		agent_version    VARCHAR(64)    NOT NULL,
		os_version       VARCHAR(128)   NOT NULL,
		source_ip        VARCHAR(45)    NOT NULL,
		enrolled_at      TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		expires_at       TIMESTAMP(6)   NULL,
		revoked_at       TIMESTAMP(6)   NULL,
		revoke_reason    VARCHAR(128)   NULL,
		revoked_by       VARCHAR(255)   NULL,
		UNIQUE KEY uk_enrollments_token_id (host_token_id)
	)`,
	// policies holds the Phase 2 server-driven blocklist. For MVP we keep a single "default"
	// row — `name` is a UNIQUE key now so v1.1 can add per-team targeting without a schema
	// migration. `version` is a monotonically-increasing integer bumped on every admin PUT;
	// agents cache the last-applied version and skip no-op updates.
	`CREATE TABLE IF NOT EXISTS policies (
		id          BIGINT AUTO_INCREMENT PRIMARY KEY,
		name        VARCHAR(64)  NOT NULL,
		version     BIGINT       NOT NULL DEFAULT 1,
		blocklist   JSON         NOT NULL,
		updated_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_by  VARCHAR(255) NOT NULL DEFAULT 'system',
		UNIQUE KEY uk_policies_name (name)
	)`,
	// Seed the default policy row. Using INSERT IGNORE so restarts don't clobber an edited
	// row. The initial blocklist is empty — operators opt in to blocking via PUT.
	`INSERT IGNORE INTO policies (name, version, blocklist, updated_by)
	 VALUES ('default', 1, JSON_OBJECT('paths', JSON_ARRAY(), 'hashes', JSON_ARRAY()), 'system')`,
	// Phase 3: users table for UI auth. password_hash is argon2id output (32 bytes);
	// password_salt is 16 random bytes (same argon params as enrollment host tokens).
	// email is UNIQUE so duplicate invites fail cleanly at the DB boundary.
	`CREATE TABLE IF NOT EXISTS users (
		id             BIGINT AUTO_INCREMENT PRIMARY KEY,
		email          VARCHAR(255)   NOT NULL,
		password_hash  VARBINARY(255) NOT NULL,
		password_salt  VARBINARY(32)  NOT NULL,
		created_at     TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_at     TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
		                              ON UPDATE CURRENT_TIMESTAMP(6),
		UNIQUE KEY uk_users_email (email)
	)`,
	// Phase 3: sessions table for UI cookie auth. id is 32 random bytes (~256 bits of
	// entropy) — acts as its own unguessable lookup key, no separate index needed.
	// csrf_token is 32 random bytes; compared constant-time against X-CSRF-Token header
	// on unsafe methods.
	`CREATE TABLE IF NOT EXISTS sessions (
		id            VARBINARY(32)  PRIMARY KEY,
		user_id       BIGINT         NOT NULL,
		csrf_token    VARBINARY(32)  NOT NULL,
		created_at    TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		last_seen_at  TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
		                             ON UPDATE CURRENT_TIMESTAMP(6),
		expires_at    TIMESTAMP(6)   NOT NULL,
		INDEX idx_sessions_expires (expires_at)
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

	// Open the driver through otelsql so each query emits a span. The no-op tracer provider
	// keeps this cheap when OTel is disabled.
	sqldb, err := otelsql.Open("mysql", dsn, otelsql.WithAttributes(
		semconv.DBSystemNameMySQL,
	))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// Register db.client.connection metrics (idle/in_use/max) via the global meter provider.
	// observability.Init installs a real MeterProvider when OTEL_EXPORTER_OTLP_ENDPOINT is set;
	// otherwise these register against the SDK's no-op meter and cost nothing.
	_, err = otelsql.RegisterDBStatsMetrics(sqldb, otelsql.WithAttributes(
		semconv.DBSystemNameMySQL,
	))
	if err != nil {
		// Surface both the registration failure and any close-path issue rather than swallowing
		// the latter — a stuck close is often what explains the underlying problem.
		if cerr := sqldb.Close(); cerr != nil {
			return nil, fmt.Errorf("register db stats metrics: %w (close: %w)", err, cerr)
		}
		return nil, fmt.Errorf("register db stats metrics: %w", err)
	}

	db := sqlx.NewDb(sqldb, "mysql")

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
			// Already-applied variants:
			//   1060 = duplicate column
			//   1061 = duplicate key name
			//   1826 = duplicate FK name
			//   1022 = duplicate key on add (older MySQL error code for FK name clash)
			if errors.As(err, &mysqlErr) &&
				(mysqlErr.Number == 1060 || mysqlErr.Number == 1061 ||
					mysqlErr.Number == 1826 || mysqlErr.Number == 1022) {
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
	// Phase 3: alert audit trail. updated_by references users.id for SOC forensics.
	// NULL is allowed so pre-Phase-3 rows (written before the column existed) continue
	// to render. The migration loop above swallows "duplicate column name" errors, so
	// re-running on an already-migrated DB is a no-op.
	`ALTER TABLE alerts ADD COLUMN updated_by BIGINT NULL`,
	// Phase 3 FK constraints: enforce that sessions point at live users (CASCADE on
	// user delete so stale sessions die with their owner) and alert audit references
	// are either a real user or NULL (SET NULL on delete so a removed admin doesn't
	// erase their historical acknowledgements). Indexes on the FK columns are
	// required for InnoDB to accept the constraint and make JOIN-based queries cheap.
	`ALTER TABLE sessions ADD INDEX idx_sessions_user_id (user_id)`,
	`ALTER TABLE sessions ADD CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE`,
	`ALTER TABLE alerts ADD INDEX idx_alerts_updated_by (updated_by)`,
	`ALTER TABLE alerts ADD CONSTRAINT fk_alerts_updated_by FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL`,
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

// PingContext verifies connectivity to the underlying database. Used by the readiness probe.
func (s *Store) PingContext(ctx context.Context) error {
	return s.db.PingContext(ctx)
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
