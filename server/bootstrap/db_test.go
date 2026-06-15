package bootstrap

import (
	"context"
	"strings"
	"testing"

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
func TestOpenInstrumentedDB_RegistersDriverPoolMetrics(t *testing.T) {
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
