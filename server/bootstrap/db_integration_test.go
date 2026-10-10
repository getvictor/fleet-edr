//go:build integration

package bootstrap

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestOpenDB_BoundsSharedConnectionPool_RealMySQL exercises the shipped OpenDB path end-to-end against a real MySQL and asserts the
// returned shared handle caps total open connections at the compiled ceiling, so processor-worker concurrency above that cap waits for a
// pooled connection instead of opening an unbounded number and exhausting MySQL's max_connections. This is the shipped-path counterpart
// to the lazy unit pin in db_test.go: it proves OpenDB itself applies the bound, not merely that a *sql.DB reflects a SetMaxOpenConns
// call, so a refactor that dropped the SetMaxOpenConns line would fail here.
//
// spec:server-availability/the-shared-database-connection-pool-is-bounded/worker-concurrency-cannot-exhaust-database-connections
func TestOpenDB_BoundsSharedConnectionPool_RealMySQL(t *testing.T) {
	t.Parallel()
	dsn := os.Getenv("EDR_TEST_DSN") //nolint:forbidigo // approved test-DB boundary; see issue #172
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set")
	}

	db, err := OpenDB(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	assert.Equal(t, dbMaxOpenConns, db.Stats().MaxOpenConnections,
		"OpenDB must bound the shared pool to the compiled ceiling so worker concurrency cannot exhaust MySQL connections")
}

// TestOpenInstrumentedDB_TracesQueriesOnlyUnderASpan drives the shipped span policy through a real MySQL round trip: the parametrized
// query takes the driver's prepare path, which is the one that produced the reset, prepare, and rows spans this policy omits.
//
// spec:observability-instrumentation/background-work-is-traced-under-a-sampled-root-span/a-query-outside-any-span-records-no-span
func TestOpenInstrumentedDB_TracesQueriesOnlyUnderASpan(t *testing.T) { //nolint:paralleltest // installs the global tracer provider
	dsn := os.Getenv("EDR_TEST_DSN") //nolint:forbidigo // approved test-DB boundary; see issue #172
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set")
	}
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider) // otelsql resolves the global provider at open, so install it first.
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	})
	db, err := openInstrumentedDB(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	selectOne := func(ctx context.Context) {
		t.Helper()
		var one int
		require.NoError(t, db.QueryRowContext(ctx, "SELECT ?", 1).Scan(&one))
	}
	spanNames := func() []string {
		var names []string
		for _, s := range recorder.Ended() {
			names = append(names, s.Name())
		}
		return names
	}

	selectOne(context.Background())
	assert.Empty(t, spanNames(), "a query outside any span records no span")

	ctx, parent := provider.Tracer("test").Start(context.Background(), "detection.batch.process")
	selectOne(ctx)
	parent.End()
	names := spanNames()
	assert.Contains(t, names, "sql.stmt.query", "a query under a span records its query span")
	for _, housekeeping := range []string{"sql.conn.reset_session", "sql.conn.prepare", "sql.rows"} {
		assert.NotContains(t, names, housekeeping)
	}
}
