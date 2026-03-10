package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
)

// OpenTestStore creates an isolated test database with a unique name derived
// from the test name. The database is dropped when the test completes. This
// allows test packages to run in parallel without interfering with each other.
//
// Requires EDR_TEST_DSN to be set (e.g., "root:@tcp(127.0.0.1:3306)/edr_test?parseTime=true").
// The database name in the DSN is used only to connect initially; the test
// runs against its own temporary database.
func OpenTestStore(t *testing.T) *Store {
	t.Helper()

	dsn := testDSN(t)

	// Connect to the server (without a specific database) to create the test DB.
	baseDSN := stripDBName(dsn)
	adminDB, err := sqlx.Open("mysql", baseDSN)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	defer adminDB.Close()

	// Create a unique database name from the test name.
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

	// Build a DSN pointing to the new database.
	testDSN := replaceDBName(dsn, dbName)
	s, err := New(ctx, testDSN)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("EDR_TEST_DSN")
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping MySQL tests")
	}
	return dsn
}

// sanitizeDBName converts a test name into a valid MySQL database name.
// MySQL identifiers are limited to 64 characters.
func sanitizeDBName(testName string) string {
	name := "edr_test_" + testName
	// Replace characters invalid in MySQL identifiers.
	replacer := strings.NewReplacer("/", "_", " ", "_", "-", "_", ".", "_")
	name = replacer.Replace(name)
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// stripDBName removes the database name from a MySQL DSN, returning a DSN
// that connects to the server without selecting a database.
// Input:  "root:@tcp(127.0.0.1:3306)/edr_test?parseTime=true"
// Output: "root:@tcp(127.0.0.1:3306)/?parseTime=true"
func stripDBName(dsn string) string {
	// Find the slash after the address.
	slashIdx := strings.LastIndex(dsn, ")/")
	if slashIdx == -1 {
		return dsn
	}
	afterSlash := dsn[slashIdx+2:]
	// Find the next ? or end of string.
	qIdx := strings.Index(afterSlash, "?")
	if qIdx == -1 {
		return dsn[:slashIdx+2]
	}
	return dsn[:slashIdx+2] + afterSlash[qIdx:]
}

// replaceDBName replaces the database name in a MySQL DSN.
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
