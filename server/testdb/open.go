package testdb

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/bootstrap"
)

// Open creates an isolated test database with a unique name derived
// from the test name and returns the open *sqlx.DB. The database is
// dropped when the test completes.
//
// Schemas are NOT applied. The caller is responsible for invoking
// each context's ApplySchema (and detection's MigrateSchema). For
// tests that need every bounded context's schema, use
// server/testdb/full.Open(t) instead, which is the canonical fixture
// for cross-context integration tests.
//
// Requires EDR_TEST_DSN to be set (e.g.
// "root:@tcp(127.0.0.1:3316)/edr_test?parseTime=true"). The database
// name in the DSN is used only to connect initially; the test runs
// against its own temporary database.
//
// This package intentionally does NOT import any bounded-context
// bootstrap, which lets per-package unit tests inside a context's
// internal/ tree use Open without an import cycle (the cycle would
// otherwise go: pkg → testdb → ctx/bootstrap → pkg).
func Open(t *testing.T) *sqlx.DB {
	t.Helper()

	dsn := testDSN(t)

	// Parse the DSN once and fail fast if it's malformed. Returning
	// the original DSN on parse error would silently strip our
	// "isolated test database" guarantee — the admin connection would
	// keep the original DBName and any DDL we run would land on the
	// shared dev DB.
	baseDSN, err := stripDBName(dsn)
	if err != nil {
		t.Fatalf("parse EDR_TEST_DSN: %v", err)
	}
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

	perTestDSN, err := replaceDBName(dsn, dbName)
	if err != nil {
		t.Fatalf("replace DSN db name: %v", err)
	}
	db, err := bootstrap.OpenDB(ctx, perTestDSN)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}

	t.Cleanup(func() { _ = db.Close() })
	return db
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

// stripDBName clears the DBName field on a parsed DSN so the caller
// can connect to the MySQL server without selecting a specific
// database. Returns the parse error so callers fail fast instead of
// silently running tests against the shared DSN's database.
func stripDBName(dsn string) (string, error) {
	cfg, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return "", fmt.Errorf("parse DSN: %w", err)
	}
	cfg.DBName = ""
	return cfg.FormatDSN(), nil
}

// replaceDBName swaps the DBName field on a parsed DSN. Uses
// go-sql-driver/mysql's ParseDSN+FormatDSN round-trip so passwords
// containing `)/` and other DSN-flavoured punctuation don't fool
// naive substring manipulation. Returns the parse error so callers
// fail fast (silently falling back to the original DSN would route
// the test to the shared database, breaking isolation).
func replaceDBName(dsn, newDB string) (string, error) {
	cfg, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return "", fmt.Errorf("parse DSN: %w", err)
	}
	cfg.DBName = newDB
	return cfg.FormatDSN(), nil
}
