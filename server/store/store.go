// Package store provides MySQL-backed event storage for the EDR ingestion server.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/XSAM/otelsql"
	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
)

// schemaStatements are executed sequentially to bootstrap the database.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS events (
		event_id        VARCHAR(255) PRIMARY KEY,
		host_id         VARCHAR(255) NOT NULL,
		timestamp_ns    BIGINT       NOT NULL,
		ingested_at_ns  BIGINT       NOT NULL DEFAULT 0,
		event_type      VARCHAR(64)  NOT NULL,
		payload         JSON         NOT NULL,
		processed       TINYINT(1)   NOT NULL DEFAULT 0,
		created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
		INDEX idx_events_host_id (host_id),
		INDEX idx_events_type (event_type),
		INDEX idx_events_timestamp (timestamp_ns),
		INDEX idx_events_host_type_ingested (host_id, event_type, ingested_at_ns),
		INDEX idx_events_processed (processed, host_id, timestamp_ns)
	)`,
	`CREATE TABLE IF NOT EXISTS processes (
		id                   BIGINT AUTO_INCREMENT PRIMARY KEY,
		host_id              VARCHAR(255) NOT NULL,
		pid                  INT          NOT NULL,
		ppid                 INT          NOT NULL,
		path                 TEXT         NOT NULL,
		args                 JSON,
		uid                  INT,
		gid                  INT,
		code_signing         JSON,
		sha256               VARCHAR(64),
		fork_time_ns         BIGINT       NOT NULL,
		fork_ingested_at_ns  BIGINT,
		exec_time_ns         BIGINT,
		exit_time_ns         BIGINT,
		exit_ingested_at_ns  BIGINT,
		exit_reason          VARCHAR(32),
		exit_code            INT,
		previous_exec_id     BIGINT,
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
		techniques   JSON         NULL,
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
	// enrollments DDL is owned by the endpoint bounded context (see
	// server/endpoint/bootstrap/schema.go). cmd/main calls
	// endpointCtx.ApplySchema before this list runs. No FK referencing
	// or referenced; ordering between identity / endpoint / store is
	// not load-bearing for the enrollments table itself.
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
	// users + sessions DDL is owned by the identity bounded context (see
	// server/identity/bootstrap/schema.go). cmd/main calls
	// identityCtx.ApplySchema before this list runs so the cross-context
	// FK fk_alerts_updated_by below can resolve. Phase 5 will drop that FK
	// and the call ordering will no longer matter.
}

// Event represents the canonical event envelope.
//
// TimestampNs is the source-kernel time recorded by the emitting extension
// (ES or NE). IngestedAtNs is the server-side wall-clock stamp set by
// InsertEvents when the row lands. Cross-source correlation queries
// (ProcessDetail network window, detection windows, tree time-range) use
// IngestedAtNs because the ES and NE clocks drift by tens of milliseconds
// and can even invert order on a single host.
type Event struct {
	EventID      string          `db:"event_id" json:"event_id"`
	HostID       string          `db:"host_id" json:"host_id"`
	TimestampNs  int64           `db:"timestamp_ns" json:"timestamp_ns"`
	IngestedAtNs int64           `db:"ingested_at_ns" json:"ingested_at_ns,omitempty"`
	EventType    string          `db:"event_type" json:"event_type"`
	Payload      json.RawMessage `db:"payload" json:"payload"`
}

// Store manages event persistence in MySQL.
type Store struct {
	db *sqlx.DB
}

// OpenDB opens a connection pool to MySQL and pings it. cmd/main calls this
// once and injects the returned handle into each bounded context's bootstrap
// + into store.New, so all contexts share one connection budget. The dsn
// should be in go-sql-driver/mysql format, e.g.
// "user:pass@tcp(127.0.0.1:3316)/edr?parseTime=true". parseTime=true is
// appended automatically when missing.
func OpenDB(ctx context.Context, dsn string) (*sqlx.DB, error) {
	sqldb, err := openInstrumentedDB(ensureParseTime(dsn))
	if err != nil {
		return nil, err
	}
	db := sqlx.NewDb(sqldb, "mysql")
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return db, nil
}

// New ensures the schema this store owns exists, then returns the Store
// wrapping the provided db handle. cmd/main is responsible for opening the
// db (via OpenDB) and for calling each bounded context's ApplySchema in the
// right order before this function runs (so cross-table FKs resolve).
//
// Note: the db handle is shared across the process; closing it is the
// caller's responsibility, not Store.Close (which is intentionally a no-op
// to avoid yanking other contexts' connection pool out from under them).
func New(ctx context.Context, db *sqlx.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("store.New: db handle must not be nil")
	}
	if err := applySchema(ctx, db); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// ensureParseTime appends parseTime=true to a MySQL DSN if it is missing, so
// sql.DB returns time.Time for DATETIME columns instead of raw bytes.
func ensureParseTime(dsn string) string {
	if strings.Contains(dsn, "parseTime") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "parseTime=true"
}

// openInstrumentedDB opens the MySQL driver through otelsql (so every query emits a
// span + connection metrics) and returns the raw *sql.DB. Keeping this split out of
// New keeps New focused on lifecycle.
func openInstrumentedDB(dsn string) (*sql.DB, error) {
	sqldb, err := otelsql.Open("mysql", dsn, otelsql.WithAttributes(semconv.DBSystemNameMySQL))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := otelsql.RegisterDBStatsMetrics(sqldb, otelsql.WithAttributes(semconv.DBSystemNameMySQL)); err != nil {
		// Surface both the registration failure and any close-path issue rather than
		// swallowing the latter — a stuck close is often what explains the problem.
		if cerr := sqldb.Close(); cerr != nil {
			return nil, fmt.Errorf("register db stats metrics: %w (close: %w)", err, cerr)
		}
		return nil, fmt.Errorf("register db stats metrics: %w", err)
	}
	return sqldb, nil
}

// applySchema runs initial CREATE TABLEs, idempotent ALTERs, and post-schema backfills.
func applySchema(ctx context.Context, db *sqlx.DB) error {
	for _, stmt := range schemaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
	}
	for _, m := range migrations {
		if _, err := db.ExecContext(ctx, m); err != nil && !isAlreadyAppliedMigration(err) {
			return fmt.Errorf("migration: %w", err)
		}
	}
	for _, m := range postSchemaMigrations {
		if _, err := db.ExecContext(ctx, m); err != nil {
			return fmt.Errorf("post-schema migration: %w", err)
		}
	}
	return nil
}

// isAlreadyAppliedMigration returns true when err is one of the MySQL "this ALTER is
// already applied" codes, so we can treat the re-run as a no-op.
func isAlreadyAppliedMigration(err error) bool {
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	// 1060 duplicate column, 1061 duplicate key name, 1826 duplicate FK name,
	// 1022 duplicate key on add (older MySQL code for FK name clash).
	switch mysqlErr.Number {
	case 1060, 1061, 1826, 1022:
		return true
	}
	return false
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
	// alerts.updated_by FK references users.id from another bounded context
	// (identity). The ALTER ADD COLUMN above stays here because the column
	// belongs to the alerts table that this store owns; the FK is created
	// here for now and dropped in phase 5, after which the alert-update
	// handler validates user existence in code (identity.api.Service.UserExists)
	// instead of through the database constraint. Index required for InnoDB.
	`ALTER TABLE alerts ADD INDEX idx_alerts_updated_by (updated_by)`,
	`ALTER TABLE alerts ADD CONSTRAINT fk_alerts_updated_by FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL`,
	// Phase 7 / issue #7: server-stamped ingest time. ES and NE clocks drift,
	// so cross-source correlation queries have to run off a clock we control.
	// Default 0 keeps the migration cheap; a backfill in postSchemaMigrations
	// copies timestamp_ns into old rows so historical data still correlates.
	`ALTER TABLE events ADD COLUMN ingested_at_ns BIGINT NOT NULL DEFAULT 0`,
	`ALTER TABLE events ADD INDEX idx_events_host_type_ingested (host_id, event_type, ingested_at_ns)`,
	`ALTER TABLE processes ADD COLUMN fork_ingested_at_ns BIGINT NULL`,
	`ALTER TABLE processes ADD COLUMN exit_ingested_at_ns BIGINT NULL`,
	// Phase 7 / issue #6: freshness TTL reconciliation. exit_reason
	// distinguishes observed exits (NULL or "event") from synthesized ones
	// ("ttl_reconciliation") so analysts don't misread a stale green node
	// that the server later forced-gray as a confirmed clean exit.
	`ALTER TABLE processes ADD COLUMN exit_reason VARCHAR(32) NULL`,
	// Phase 7 / MITRE ATT&CK mapping on alerts. Nullable because the rule
	// engine can register rules whose author hasn't supplied a mapping yet,
	// and existing pre-migration rows shouldn't be touched — the UI treats
	// missing + empty as "no techniques declared".
	`ALTER TABLE alerts ADD COLUMN techniques JSON NULL`,
	// Phase 7 / issue #10: same-PID re-exec chains. previous_exec_id points
	// at the prior generation's row when a process execs multiple times on
	// the same PID without forking (shell exec-optimization). Nullable; the
	// first generation in any chain has NULL here.
	`ALTER TABLE processes ADD COLUMN previous_exec_id BIGINT NULL`,
	`ALTER TABLE processes ADD INDEX idx_processes_previous_exec (previous_exec_id)`,
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
	// Phase 7 / issue #7: backfill ingested_at_ns for pre-migration rows.
	// Uses timestamp_ns as a lower-fidelity proxy so correlation queries on
	// old data still return something reasonable; new rows get a real
	// server-stamped value from InsertEvents. Idempotent: already-backfilled
	// rows have ingested_at_ns != 0 and are skipped.
	`UPDATE events SET ingested_at_ns = timestamp_ns WHERE ingested_at_ns = 0`,
	// Mirror backfill on processes: anchor fork_ingested_at_ns to fork_time_ns
	// where the column is still NULL (pre-migration rows).
	`UPDATE processes SET fork_ingested_at_ns = fork_time_ns WHERE fork_ingested_at_ns IS NULL`,
}

// Close is a no-op. The db handle is shared across bounded contexts and owned
// by cmd/main; closing it here would yank the pool out from under sibling
// contexts. cmd/main is responsible for db.Close on shutdown.
//
// Kept as a method (rather than removed) so callers that defer s.Close() out
// of habit do no harm; the existing test helpers also call this.
func (s *Store) Close() error {
	return nil
}

// PingContext verifies connectivity to the underlying database. Used by the readiness probe.
func (s *Store) PingContext(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// InsertEvents upserts a batch of events. Duplicates (by event_id) are ignored.
// Each row is stamped with a server-controlled ingested_at_ns; the caller's
// Event.IngestedAtNs is ignored so agents can't set it.
func (s *Store) InsertEvents(ctx context.Context, events []Event) error {
	return s.insertEventsAt(ctx, events, time.Now().UnixNano())
}

// InsertEventsAt is a test-only variant that takes a deterministic ingest
// timestamp. Production callers go through InsertEvents; this path exists
// so cross-source correlation tests can simulate the ES/NE clock-drift
// scenario (issue #7) without relying on wall-clock timing.
func (s *Store) InsertEventsAt(ctx context.Context, events []Event, ingestedAtNs int64) error {
	return s.insertEventsAt(ctx, events, ingestedAtNs)
}

func (s *Store) insertEventsAt(ctx context.Context, events []Event, ingestedAtNs int64) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Rollback after commit is a no-op.

	stmt, err := tx.PrepareContext(ctx, `
		INSERT IGNORE INTO events (event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	// Stamp the caller's slice with the server-chosen ingest time so callers
	// that hand the same slice straight to the graph builder (tests, the
	// in-process processor when we add one) see the persisted value.
	//
	// Only stamp rows that were actually INSERTed. INSERT IGNORE silently
	// drops duplicates, and in that case the DB already holds a different
	// ingested_at_ns from the original insert — mutating the caller's slice
	// to a value that doesn't match the persisted row would silently break
	// any correlation the caller tries to do in-memory (e.g. an idempotent
	// retry feeding the same events to the graph builder).
	for i := range events {
		payloadBytes, err := json.Marshal(events[i].Payload)
		if err != nil {
			return fmt.Errorf("marshal payload for %s: %w", events[i].EventID, err)
		}
		res, err := stmt.ExecContext(ctx, events[i].EventID, events[i].HostID, events[i].TimestampNs,
			ingestedAtNs, events[i].EventType, payloadBytes)
		if err != nil {
			return fmt.Errorf("insert %s: %w", events[i].EventID, err)
		}
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("rows affected for %s: %w", events[i].EventID, err)
		}
		if rowsAffected > 0 {
			events[i].IngestedAtNs = ingestedAtNs
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
		SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload
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
