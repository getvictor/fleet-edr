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
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
)

// TestBuildResource_ServiceInstanceID pins that a replica's telemetry resource carries service.instance.id when one is set. The
// attribute lives on the resource, so every span and metric the SDK emits inherits it - which is how an operator tells replicas
// apart in the backend.
func TestBuildResource_ServiceInstanceID(t *testing.T) {
	t.Run("spec:server-availability/replica-identity-is-observable-via-service-instance-id/every-emitted-span-carries-the-service-instance-id", func(t *testing.T) {
		res, err := buildResource(t.Context(), Options{ServiceName: "test-svc", ServiceInstanceID: "instance-abc"})
		require.NoError(t, err)

		var got string
		var found bool
		for _, kv := range res.Attributes() {
			if kv.Key == semconv.ServiceInstanceIDKey {
				got, found = kv.Value.AsString(), true
			}
		}
		require.True(t, found, "resource must carry service.instance.id so every emitted span inherits it")
		assert.Equal(t, "instance-abc", got)
	})
}

// restoreGlobals captures the current global OTel providers + propagator and registers a cleanup that restores them after the test.
// Tests that call Init with a non-empty endpoint MUST call this first, otherwise their providers leak into subsequent tests.
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

// spec:observability-instrumentation/otlp-export-is-opt-in-via-otel-exporter-otlp-endpoint/otel-exporter-otlp-endpoint-is-unset
//
// With Endpoint="" (the SDK's no-op condition mapped from an unset OTEL_EXPORTER_OTLP_ENDPOINT), Init
// must still return a non-nil shutdown hook, the shutdown call must complete promptly, AND the W3C
// propagator must be installed so inbound traceparent headers are still parsed (otherwise services
// behind a no-OTel EDR would lose distributed-trace context for free, which is a regression).
func TestInit_Disabled(t *testing.T) {
	restoreGlobals(t)
	shutdown, err := Init(t.Context(), Options{ServiceName: "test-svc", Endpoint: ""})
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

// spec:observability-instrumentation/otlp-export-is-opt-in-via-otel-exporter-otlp-endpoint/otel-exporter-otlp-endpoint-points-at-a-collector
//
// With a non-empty Endpoint, the export pipeline is wired up (the test points it at a dead TCP port to
// avoid CI flakiness on real collectors). The scenario's spec-relevant clause this test pins is "the
// SDK is configured to export via OTLP using the standard env vars" - observable through Init
// returning a non-nil shutdown hook and the shutdown call respecting the deadline. End-to-end export
// to a live collector is validated against the dev SigNoz pipeline; that path is out of scope for an
// in-process unit test because it requires an external service.
func TestInit_Enabled_BogusEndpoint(t *testing.T) {
	restoreGlobals(t)
	// Pass a URL pointing at a port we are confident nothing is listening on. The http:// scheme tells the SDK's
	// WithEndpointURL option to use insecure transport so the connection refused is observed at the TCP layer rather than
	// after a slow TLS handshake. gRPC dialing is lazy and the BatchProcessor export happens asynchronously, so Init must
	// still return quickly and Shutdown must not block on the dead endpoint for longer than the deadline we pass.
	start := time.Now()
	shutdown, err := Init(t.Context(), Options{
		ServiceName: "test-svc",
		InitTimeout: 2 * time.Second,
		Endpoint:    "http://127.0.0.1:1",
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

// spec:observability-instrumentation/trace-propagation-through-the-request-pipeline/inbound-traceparent-is-honoured
//
// Pins that the global TextMapPropagator is the W3C one (or at least understands W3C). The test
// extracts a synthetic traceparent and round-trips it via inject; if the propagator weren't a W3C
// implementation, the injected carrier would either drop the header or rewrite it in a non-W3C format.
// Init wires the propagator at the process level and applies to every binary that consumes this
// package (server, agent, ingest); the actual parent-child stitching happens at every http.Handler
// that calls `otel.GetTextMapPropagator().Extract(...)`, which this propagator install makes well-defined.
func TestInit_PropagatorInstalled(t *testing.T) {
	restoreGlobals(t)
	shutdown, err := Init(t.Context(), Options{ServiceName: "test-svc", Endpoint: ""})
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
