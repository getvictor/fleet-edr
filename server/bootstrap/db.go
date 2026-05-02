package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/XSAM/otelsql"
	_ "github.com/go-sql-driver/mysql" // register driver
	"github.com/jmoiron/sqlx"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
)

// OpenDB opens a connection pool to MySQL and pings it. cmd/main
// calls this once and shares the returned handle across every
// bounded context's bootstrap so all contexts share one connection
// budget. The dsn should be in go-sql-driver/mysql format, e.g.
// "user:pass@tcp(127.0.0.1:3316)/edr?parseTime=true". parseTime=true
// is appended automatically when missing.
//
// Phase 5 moved this from server/store to the platform bootstrap
// package: the connection pool is process-wide infrastructure, not
// owned by any single bounded context.
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

// ensureParseTime appends parseTime=true to a MySQL DSN if missing,
// so sql.DB returns time.Time for DATETIME columns instead of raw
// bytes.
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

// openInstrumentedDB opens the MySQL driver through otelsql so every
// query emits a span + connection metrics.
func openInstrumentedDB(dsn string) (*sql.DB, error) {
	sqldb, err := otelsql.Open("mysql", dsn, otelsql.WithAttributes(semconv.DBSystemNameMySQL))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := otelsql.RegisterDBStatsMetrics(sqldb, otelsql.WithAttributes(semconv.DBSystemNameMySQL)); err != nil {
		if cerr := sqldb.Close(); cerr != nil {
			return nil, fmt.Errorf("register db stats metrics: %w (close: %w)", err, cerr)
		}
		return nil, fmt.Errorf("register db stats metrics: %w", err)
	}
	return sqldb, nil
}
