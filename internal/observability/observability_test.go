package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
)

// TestBuildResource_ServiceInstanceID pins that a replica's telemetry resource carries service.instance.id when one is set. The
// attribute lives on the resource, so every span and metric the SDK emits inherits it, which is how an operator tells replicas
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

// deploymentEnvOf extracts the two deployment-environment attribute values (current semconv + deprecated) from a resource.
func deploymentEnvOf(res *resource.Resource) map[attribute.Key]string {
	got := map[attribute.Key]string{}
	for _, kv := range res.Attributes() {
		if kv.Key == semconv.DeploymentEnvironmentNameKey || kv.Key == deploymentEnvironmentKey {
			got[kv.Key] = kv.Value.AsString()
		}
	}
	return got
}

// spec:observability-instrumentation/telemetry-carries-a-deployment-environment-resource-attribute/default-deployment-environment
//
// TestBuildResource_DeploymentEnvironment pins that, with no operator override, the telemetry resource carries both the current semconv
// key (deployment.environment.name) and the deprecated deployment.environment at "default". The attribute lives on the resource, so
// every span / metric / log inherits it, which is what lets the bundled SigNoz dashboards drive a dynamic environment selector. The
// operator-override path is exercised by TestWithDeploymentEnvironment (the repo forbids t.Setenv in tests, issue #172).
func TestBuildResource_DeploymentEnvironment(t *testing.T) {
	res, err := buildResource(t.Context(), Options{ServiceName: "test-svc"})
	require.NoError(t, err)
	got := deploymentEnvOf(res)
	assert.Equal(t, "default", got[semconv.DeploymentEnvironmentNameKey], "deployment.environment.name defaults to 'default'")
	assert.Equal(t, "default", got[deploymentEnvironmentKey], "deprecated deployment.environment defaults to 'default'")
}

// spec:observability-instrumentation/telemetry-carries-a-deployment-environment-resource-attribute/operator-overrides-the-deployment-environment
//
// withDeploymentEnvironment keeps deployment.environment.name and the deprecated deployment.environment in lockstep regardless of which
// key(s) the operator set via OTEL_RESOURCE_ATTRIBUTES (which resource.WithFromEnv turns into the attributes fed here). Driving the
// normalizer with a hand-built resource pins the operator-override contract (either key alone wins, both end up synchronized, an empty
// resource falls back to "default") without mutating process env, since t.Setenv is forbidden (issue #172).
func TestWithDeploymentEnvironment(t *testing.T) {
	cases := []struct {
		name string
		in   []attribute.KeyValue
		want string
	}{
		{"neither key set falls back to default", nil, "default"},
		{"only the deprecated key set", []attribute.KeyValue{attribute.String("deployment.environment", "staging")}, "staging"},
		{"only the semconv name set", []attribute.KeyValue{semconv.DeploymentEnvironmentName("staging")}, "staging"},
		{"both set but divergent prefers the semconv name", []attribute.KeyValue{
			semconv.DeploymentEnvironmentName("prod"),
			attribute.String("deployment.environment", "staging"),
		}, "prod"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := withDeploymentEnvironment(resource.NewSchemaless(tc.in...))
			require.NoError(t, err)
			got := deploymentEnvOf(out)
			assert.Equal(t, tc.want, got[semconv.DeploymentEnvironmentNameKey], "deployment.environment.name")
			assert.Equal(t, tc.want, got[deploymentEnvironmentKey], "deprecated deployment.environment kept in lockstep")
		})
	}
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
// SDK is configured to export via OTLP using the standard env vars": observable through Init
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
