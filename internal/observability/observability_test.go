package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	otellog "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
)

// restoreGlobals captures the current global OTel providers + propagator and registers a
// cleanup that restores them after the test. Tests that call Init with a non-empty endpoint
// MUST call this first, otherwise their providers leak into subsequent tests.
func restoreGlobals(t *testing.T) {
	t.Helper()
	prevTP := otel.GetTracerProvider()
	prevMP := otel.GetMeterProvider()
	prevLP := otellog.GetLoggerProvider()
	prevProp := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetMeterProvider(prevMP)
		otellog.SetLoggerProvider(prevLP)
		otel.SetTextMapPropagator(prevProp)
	})
}

func TestInit_Disabled(t *testing.T) {
	restoreGlobals(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := Init(t.Context(), Options{ServiceName: "test-svc"})
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	// Shutdown must be idempotent and fast on the no-op path.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, shutdown(ctx))

	// The W3C propagator must be installed even when the SDK is no-op; otherwise incoming
	// traceparent headers would be dropped.
	assert.NotNil(t, otel.GetTextMapPropagator(), "TextMapPropagator should be installed")
}

func TestInit_Enabled_BogusEndpoint(t *testing.T) {
	restoreGlobals(t)
	// Dial a port we are confident nothing is listening on. gRPC dialing is lazy and the
	// BatchProcessor export happens asynchronously, so Init must still return quickly and
	// Shutdown must not block on the dead endpoint for longer than the deadline we pass.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")

	start := time.Now()
	shutdown, err := Init(t.Context(), Options{
		ServiceName: "test-svc",
		InitTimeout: 2 * time.Second,
	})
	// Init itself may or may not return an error depending on how aggressively the exporter
	// validates; what we care about is that it returns quickly.
	assert.Less(t, time.Since(start), 3*time.Second, "Init should not block on bogus endpoint")

	require.NotNil(t, shutdown)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	// Shutdown may return an error, but must return within the deadline.
	shutdownStart := time.Now()
	_ = shutdown(ctx)
	assert.Less(t, time.Since(shutdownStart), 3*time.Second, "Shutdown should respect deadline")
	// If Init succeeded, err is nil; if it errored, so be it. The assertion is about latency.
	_ = err
}

func TestInit_PropagatorInstalled(t *testing.T) {
	restoreGlobals(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := Init(t.Context(), Options{ServiceName: "test-svc"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = shutdown(t.Context()) })

	// Inject a carrier using a traceparent; the propagator must accept it.
	carrier := propagation.MapCarrier{
		"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
	}
	ctx := otel.GetTextMapPropagator().Extract(t.Context(), carrier)
	// Round-trip injection onto a fresh carrier must preserve the traceparent format.
	out := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, out)
	tp, ok := out["traceparent"]
	require.True(t, ok, "traceparent header must be injected by the W3C propagator")
	assert.NotEmpty(t, tp)
}
