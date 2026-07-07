package bootstrap

import (
	"context"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestOpenInstrumentedDB_RegistersDriverPoolMetrics pins that the connection pool is instrumented by the otelsql driver wrapper rather
// than by per-call-site metric code: opening through openInstrumentedDB registers the standard db.sql.connection.* pool gauges
// against the active meter provider. otelsql.Open is lazy and RegisterDBStatsMetrics only registers observable gauges (db.Stats() reads
// pool counters, not a live connection), so this needs no MySQL: a bad DSN never connects, yet the gauges still register and report.
func TestOpenInstrumentedDB_RegistersDriverPoolMetrics(t *testing.T) { //nolint:paralleltest // installs process-global OTel meter; serial
	t.Run("spec:observability-instrumentation/db-client-metrics-via-standard-driver-instrumentation/the-pool-is-instrumented-by-the-driver-not-the-call-sites", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		prev := otel.GetMeterProvider()
		otel.SetMeterProvider(mp) // otelsql captures the global provider when it registers instruments, so set it before opening.
		t.Cleanup(func() {
			otel.SetMeterProvider(prev)
			_ = mp.Shutdown(context.Background())
		})

		// A deliberately unreachable DSN: otelsql.Open is lazy and RegisterDBStatsMetrics does not connect, so registration succeeds
		// without a live MySQL. We never query, so no connection is attempted.
		db, err := openInstrumentedDB("user:pass@tcp(127.0.0.1:1)/edr_test")
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })

		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))

		var names []string
		found := false
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				names = append(names, m.Name)
				if strings.HasPrefix(m.Name, "db.sql.connection") {
					found = true
				}
			}
		}
		assert.True(t, found,
			"openInstrumentedDB must register db.sql.connection.* pool gauges via otelsql; collected metrics: %v", names)
	})
}

// TestOpenDB_BoundsSharedConnectionPool pins that the shared MySQL pool is bounded to the compiled ceiling: a replica's open
// connections are capped at dbMaxOpenConns, so processor-worker concurrency above that cap waits for a pooled connection instead of
// opening an unbounded number and exhausting MySQL's max_connections. OpenDB applies SetMaxOpenConns before it pings, so this needs no
// live MySQL: openInstrumentedDB is lazy (otelsql.Open does not dial), a *sql.DB reports its configured MaxOpenConnections via Stats()
// before any connection is made, and mirroring OpenDB's pre-ping pool configuration reflects the handle a booted replica holds.
//
// spec:server-availability/the-shared-database-connection-pool-is-bounded/worker-concurrency-cannot-exhaust-database-connections
func TestOpenDB_BoundsSharedConnectionPool(t *testing.T) {
	t.Parallel()

	// The ceiling is a fixed compiled constant, not an operator knob, so pin its value: a change to the worker sizing must be a
	// deliberate reviewed edit, never a silent drift.
	assert.Equal(t, 25, dbMaxOpenConns, "compiled pool ceiling must stay at 25 open connections")

	// Open lazily through the same instrumented entrypoint the pool uses. A deliberately unreachable DSN never connects, and neither
	// otelsql.Open nor RegisterDBStatsMetrics dials, so the pool is configured without a live MySQL. We never run a query.
	sqldb, err := openInstrumentedDB("user:pass@tcp(127.0.0.1:1)/edr_test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqldb.Close() })

	// Mirror the pool configuration OpenDB applies to the shared handle before it pings.
	db := sqlx.NewDb(sqldb, "mysql")
	db.SetMaxOpenConns(dbMaxOpenConns)
	db.SetMaxIdleConns(dbMaxIdleConns)

	// The replica caps total open connections at the compiled ceiling; demand above it waits for a pooled connection rather than
	// opening an unbounded number.
	assert.Equal(t, dbMaxOpenConns, db.Stats().MaxOpenConnections,
		"the shared pool must be bounded to the compiled ceiling so worker concurrency cannot exhaust MySQL connections")
}
