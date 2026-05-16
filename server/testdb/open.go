package testdb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/bootstrap"
)

// maxOpenConnsPerTest caps each per-test DB's connection pool. See SetMaxOpenConns call below for rationale.
const maxOpenConnsPerTest = 4

// maxAdminConns caps the shared admin pool used for CREATE/DROP DATABASE operations across the suite. Small but non-trivial so
// many tests can DROP+CREATE in flight without queueing on a single connection.
const maxAdminConns = 8

// adminPool is a process-wide DB handle used for DROP/CREATE DATABASE. Sharing across tests is critical for parallel runs: a per-
// test admin connection (one per testdb.Open) would balloon the open-connection count past MySQL's max_connections under the
// t.Parallel() rollout from issue #172. The pool is built once per (DSN-stripped-of-db-name) and reused for the rest of the run.
var (
	adminPoolOnce sync.Once
	adminPool     *sqlx.DB
	adminPoolDSN  string
	adminPoolErr  error
)

// processSalt is a per-process random suffix mixed into every test DB name. Different packages run in separate `go test` processes
// but share the same MySQL; two tests in different packages with the same name (e.g. TestCountPending in response/internal/mysql
// and response/internal/tests) would otherwise collide on the derived DB name and race each other's DROP DATABASE. Random salt
// makes the collision space astronomically small without coordinating between processes.
var processSalt = func() string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// rand.Read failing means the OS RNG is unavailable; falling back to a static salt would re-enable the
		// cross-process collision. Failing loudly here surfaces the (unlikely) environment problem to operators.
		panic(fmt.Sprintf("testdb: read random salt: %v", err))
	}
	return hex.EncodeToString(buf[:])
}()

func getAdminPool(baseDSN string) (*sqlx.DB, error) {
	adminPoolOnce.Do(func() {
		db, err := sqlx.Open("mysql", baseDSN)
		if err != nil {
			adminPoolErr = err
			return
		}
		db.SetMaxOpenConns(maxAdminConns)
		db.SetMaxIdleConns(maxAdminConns)
		adminPool = db
		adminPoolDSN = baseDSN
	})
	if adminPoolErr != nil {
		return nil, adminPoolErr
	}
	if adminPoolDSN != baseDSN {
		// Different DSN than the one used to initialise — fall back to a one-shot pool. This is rare; typically
		// every test in a run shares the same EDR_TEST_DSN.
		return nil, fmt.Errorf("admin pool already initialised with a different DSN (%q vs %q)", adminPoolDSN, baseDSN)
	}
	return adminPool, nil
}

// Open creates an isolated test database with a unique name derived
// from the test name and returns the open *sqlx.DB. The database is
// dropped when the test completes.
//
// Schemas are NOT applied. The caller is responsible for invoking
// each context's ApplySchema. For tests that need every bounded
// context's schema, use server/testdb/full.Open(t) instead, which
// is the canonical fixture for cross-context integration tests.
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
func Open(tb testing.TB) *sqlx.DB {
	tb.Helper()

	dsn := testDSN(tb)

	// Parse the DSN once and fail fast if it's malformed. Returning the original DSN on parse error would silently strip our "isolated
	// test database" guarantee — the admin connection would keep the original DBName and any DDL we run would land on the shared dev DB.
	baseDSN, err := stripDBName(dsn)
	if err != nil {
		tb.Fatalf("parse EDR_TEST_DSN: %v", err)
	}
	adminDB, err := getAdminPool(baseDSN)
	if err != nil {
		tb.Fatalf("open admin connection: %v", err)
	}

	dbName := sanitizeDBName(tb.Name())
	ctx := tb.Context()

	if _, err := adminDB.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName)); err != nil {
		tb.Fatalf("drop test db: %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE `%s`", dbName)); err != nil {
		tb.Fatalf("create test db: %v", err)
	}
	tb.Cleanup(func() {
		// Use context.Background() because tb.Context() is cancelled by the time cleanup runs.
		_, _ = adminDB.ExecContext(context.Background(), fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName))
	})

	perTestDSN, err := replaceDBName(dsn, dbName)
	if err != nil {
		tb.Fatalf("replace DSN db name: %v", err)
	}
	db, err := bootstrap.OpenDB(ctx, perTestDSN)
	if err != nil {
		tb.Fatalf("open test db: %v", err)
	}
	// Cap the per-test connection pool. With t.Parallel() enabled across the integration suite (issue #172), uncapped pools quickly
	// exhaust the dev MySQL's default max_connections=151. 4 connections per test covers the heaviest concurrent-write integration
	// tests we have and keeps the total well under the (raised) cap.
	db.SetMaxOpenConns(maxOpenConnsPerTest)
	db.SetMaxIdleConns(maxOpenConnsPerTest)

	tb.Cleanup(func() { _ = db.Close() })
	return db
}

func testDSN(tb testing.TB) string {
	tb.Helper()
	dsn := os.Getenv("EDR_TEST_DSN") //nolint:forbidigo // approved test-DB boundary; see issue #172
	if dsn == "" {
		tb.Skip("EDR_TEST_DSN not set; skipping MySQL tests")
	}
	return dsn
}

func sanitizeDBName(testName string) string {
	const maxLen = 64
	name := "edr_test_" + processSalt + "_" + testName
	replacer := strings.NewReplacer("/", "_", " ", "_", "-", "_", ".", "_")
	name = replacer.Replace(name)
	if len(name) <= maxLen {
		return name
	}
	// Long subtest paths overflow MySQL's 64-char DB-name limit; naive truncation collapses cases that share a long prefix into the
	// same DB and races their drops. Append a short hash of the original name to keep distinct subtests distinct after truncation.
	suffix := sha256.Sum256([]byte(name))
	suffixHex := hex.EncodeToString(suffix[:4]) // 8 hex chars
	return name[:maxLen-1-len(suffixHex)] + "_" + suffixHex
}

// stripDBName clears the DBName field on a parsed DSN so the caller can connect to the MySQL server without selecting a specific
// database. Returns the parse error so callers fail fast instead of silently running tests against the shared DSN's database.
func stripDBName(dsn string) (string, error) {
	cfg, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return "", fmt.Errorf("parse DSN: %w", err)
	}
	cfg.DBName = ""
	return cfg.FormatDSN(), nil
}

// replaceDBName swaps the DBName field on a parsed DSN. Uses go-sql-driver/mysql's ParseDSN+FormatDSN round-trip so passwords
// containing `)/` and other DSN-flavoured punctuation don't fool naive substring manipulation. Returns the parse error so callers fail
// fast (silently falling back to the original DSN would route the test to the shared database, breaking isolation).
func replaceDBName(dsn, newDB string) (string, error) {
	cfg, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return "", fmt.Errorf("parse DSN: %w", err)
	}
	cfg.DBName = newDB
	return cfg.FormatDSN(), nil
}
