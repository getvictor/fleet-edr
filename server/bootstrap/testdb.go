package bootstrap

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
)

// OpenTestDB creates an isolated test database with a unique name
// derived from the test name. The database is dropped when the test
// completes. This allows test packages to run in parallel without
// interfering with each other.
//
// Requires EDR_TEST_DSN to be set (e.g.
// "root:@tcp(127.0.0.1:3316)/edr_test?parseTime=true"). The database
// name in the DSN is used only to connect initially; the test runs
// against its own temporary database.
//
// Phase 5 moved this fixture from server/store.OpenTestStore here:
// detection now owns the persistence schema and OpenTestStore would
// have to be a thin shim around bootstrap + detection bootstrap. This
// helper applies the identity preamble (so cross-context tests can
// exercise users + sessions) and the detection schema, then hands
// back the raw *sqlx.DB. Callers that need the detection persistence
// layer wrap with mysql.New(db).
func OpenTestDB(t *testing.T) *sqlx.DB {
	t.Helper()

	dsn := testDSN(t)

	baseDSN := stripDBName(dsn)
	adminDB, err := sqlx.Open("mysql", baseDSN)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	defer adminDB.Close()

	dbName := sanitizeDBName(t.Name())
	ctx := t.Context()

	if _, err := adminDB.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName)); err != nil {
		t.Fatalf("drop test db: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE `%s`", dbName)); err != nil {
		t.Fatalf("create test db: %v", err)
	}
	t.Cleanup(func() {
		cleanupDB, err := sqlx.Open("mysql", baseDSN)
		if err != nil {
			return
		}
		defer cleanupDB.Close()
		_, _ = cleanupDB.ExecContext(context.Background(), fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName))
	})

	testDSN := replaceDBName(dsn, dbName)
	db, err := OpenDB(ctx, testDSN)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}

	// Apply the identity preamble + the detection schema so tests run
	// against the same DDL + ALTERs production uses. Other contexts'
	// schemas (commands, enrollments, policies) are applied per-test by
	// the relevant bootstrap; this fixture only ensures the platform
	// (users, sessions) + detection tables are in place since most
	// tests touch those.
	for _, stmt := range identitySchemaForTests {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			_ = db.Close()
			t.Fatalf("apply identity schema for test: %v", err)
		}
	}
	for _, stmt := range detectionSchemaForTests {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			_ = db.Close()
			t.Fatalf("apply detection schema for test: %v", err)
		}
	}

	t.Cleanup(func() { _ = db.Close() })
	return db
}

// identitySchemaForTests duplicates the identity bounded context's
// CREATE TABLE statements. Authoritative copy lives at
// server/identity/bootstrap/schema.go.
var identitySchemaForTests = []string{
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
	`ALTER TABLE sessions ADD INDEX idx_sessions_user_id (user_id)`,
	`ALTER TABLE sessions ADD CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE`,
}

// detectionSchemaForTests duplicates the detection bounded context's
// CREATE TABLE statements. Authoritative copy lives at
// server/detection/bootstrap/schema.go. Phase 6 may extract a single
// "fixture all schemas" helper; phase 5 keeps the duplication so
// every cross-context test is self-contained.
var detectionSchemaForTests = []string{
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
		INDEX idx_processes_host_time (host_id, fork_time_ns),
		INDEX idx_processes_previous_exec (previous_exec_id)
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
		updated_by   BIGINT       NULL,
		created_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
		resolved_at  TIMESTAMP(6) NULL,
		UNIQUE KEY uk_alerts_dedup (host_id, rule_id, process_id),
		INDEX idx_alerts_host (host_id),
		INDEX idx_alerts_status_created (status, created_at),
		INDEX idx_alerts_updated_by (updated_by),
		CONSTRAINT fk_alerts_process FOREIGN KEY (process_id) REFERENCES processes(id)
	)`,
	`CREATE TABLE IF NOT EXISTS alert_events (
		alert_id  BIGINT       NOT NULL,
		event_id  VARCHAR(255) NOT NULL,
		PRIMARY KEY (alert_id, event_id),
		CONSTRAINT fk_ae_alert FOREIGN KEY (alert_id) REFERENCES alerts(id),
		CONSTRAINT fk_ae_event FOREIGN KEY (event_id) REFERENCES events(event_id)
	)`,
	`CREATE TABLE IF NOT EXISTS hosts (
		host_id      VARCHAR(255) PRIMARY KEY,
		event_count  BIGINT       NOT NULL DEFAULT 0,
		last_seen_ns BIGINT       NOT NULL DEFAULT 0,
		updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
	)`,
}

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("EDR_TEST_DSN")
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping MySQL tests")
	}
	return dsn
}

func sanitizeDBName(testName string) string {
	name := "edr_test_" + testName
	replacer := strings.NewReplacer("/", "_", " ", "_", "-", "_", ".", "_")
	name = replacer.Replace(name)
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func stripDBName(dsn string) string {
	slashIdx := strings.LastIndex(dsn, ")/")
	if slashIdx == -1 {
		return dsn
	}
	afterSlash := dsn[slashIdx+2:]
	qIdx := strings.Index(afterSlash, "?")
	if qIdx == -1 {
		return dsn[:slashIdx+2]
	}
	return dsn[:slashIdx+2] + afterSlash[qIdx:]
}

func replaceDBName(dsn, newDB string) string {
	slashIdx := strings.LastIndex(dsn, ")/")
	if slashIdx == -1 {
		return dsn
	}
	afterSlash := dsn[slashIdx+2:]
	qIdx := strings.Index(afterSlash, "?")
	if qIdx == -1 {
		return dsn[:slashIdx+2] + newDB
	}
	return dsn[:slashIdx+2] + newDB + afterSlash[qIdx:]
}
