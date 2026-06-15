// Package observability wires up the OpenTelemetry SDK for every fleet-edr
// binary (server, ingest, agent). One Init call installs global tracer +
// meter + logger providers backed by OTLP/gRPC when
// OTEL_EXPORTER_OTLP_ENDPOINT is set, and leaves the SDK defaults (no-op) in
// place when it isn't. Callers can therefore invoke otel.Tracer / otel.Meter
// / otelslog unconditionally; offline dev, CI, and unit tests do not need a
// running collector.
//
// The globals are published atomically: every provider is constructed and
// wired up before `otel.SetTracerProvider` / `global.SetLoggerProvider` /
// `otel.SetMeterProvider` is called. A failure to create any exporter leaves
// the globals untouched and returns an error, so callers never observe a
// half-initialised observability stack.
//
// The W3C tracecontext + baggage propagators are installed as the global
// propagator so traceparent headers flow in and out of HTTP boundaries
// automatically.
package observability

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
)

// defaultInitTimeout caps the OTLP dial during Init when Options.InitTimeout is zero. 5s is well above a healthy collector's ack
// latency but bounded enough that a misconfigured endpoint surfaces during boot rather than stalling the agent / server's startup
// path.
const defaultInitTimeout = 5 * time.Second

// Options configure the OTel SDK. Only the fields we rely on at startup are exposed; the SDK reads every other OTEL_* env var
// (OTEL_BSP_*, OTEL_EXPORTER_OTLP_HEADERS, OTEL_RESOURCE_ATTRIBUTES, etc.) directly. The two env vars Init used to read in-line
// (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_SERVICE_NAME) are now resolved at the wiring boundary via OptionsFromEnv so library code
// stays test-parallel-safe (issue #179).
type Options struct {
	// ServiceName is the service.name resource attribute. When non-empty it is added unconditionally; callers that want the
	// SDK's OTEL_SERVICE_NAME detector to win should pass empty here. OptionsFromEnv handles this resolution at the boundary.
	ServiceName string
	// ServiceVersion is injected at build time via -ldflags.
	ServiceVersion string
	// ServiceInstanceID is typically the hostname or a random UUID; useful for
	// distinguishing replicas in the backend UI.
	ServiceInstanceID string
	// InitTimeout caps how long we wait for the OTLP dial during Init.
	// Default 5s.
	InitTimeout time.Duration
	// Endpoint is the resolved OTLP target (e.g. "http://localhost:4317"). Empty puts Init on the no-op path so offline dev,
	// CI, and unit tests do not need a running collector. OptionsFromEnv populates this from OTEL_EXPORTER_OTLP_ENDPOINT.
	Endpoint string
}

// OptionsFromEnv resolves the env-derived fields on o from the process environment and returns the result. The only place
// observability code reads OTEL_* env vars; callers in cmd/main pass an Options with hardcoded service-identity fields and let
// this helper layer in the operator-supplied env overrides. Approved env-read boundary (issue #179).
func OptionsFromEnv(o Options) Options {
	if o.Endpoint == "" {
		o.Endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") //nolint:forbidigo // approved OTel-env boundary; see issue #179
	}
	if os.Getenv("OTEL_SERVICE_NAME") != "" { //nolint:forbidigo // approved OTel-env boundary; see issue #179
		// Defer to the SDK's resource.WithFromEnv() detector so OTEL_SERVICE_NAME overrides the binary's default.
		o.ServiceName = ""
	}
	return o
}

// ShutdownFunc flushes buffered telemetry to the collector and releases SDK resources. Call from main on SIGTERM. Safe to call on a
// no-op provider; it returns nil.
type ShutdownFunc func(ctx context.Context) error

// Init configures global OTel providers. Returns a ShutdownFunc that is always non-nil. When opts.Endpoint is empty, Init is a
// no-op and the returned function returns nil immediately. Callers in cmd/main usually wrap their Options with OptionsFromEnv so
// OTEL_EXPORTER_OTLP_ENDPOINT can flip Init into export mode without library code reaching into the process environment.
func Init(ctx context.Context, opts Options) (ShutdownFunc, error) {
	// Install the W3C propagator unconditionally; it is harmless on a no-op tracer and crucial when a real tracer is installed later (e.g.
	// a test swaps in a provider via otel.SetTracerProvider).
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if opts.Endpoint == "" {
		// No-op path: leave the SDK defaults in place and return a shutdown
		// that does nothing.
		return func(context.Context) error { return nil }, nil
	}

	res, err := buildResource(ctx, opts)
	if err != nil {
		return noopShutdown, fmt.Errorf("build resource: %w", err)
	}

	initDeadline := opts.InitTimeout
	if initDeadline == 0 {
		initDeadline = defaultInitTimeout
	}
	initCtx, cancel := context.WithTimeout(ctx, initDeadline)
	defer cancel()

	// Construct every exporter + provider BEFORE publishing any of them globally. If any step fails, previously-created providers are shut
	// down and no global is modified, so callers never see a half-initialised observability stack. Passing opts.Endpoint via
	// WithEndpointURL on each exporter bypasses the SDK's OTEL_EXPORTER_OTLP_ENDPOINT env read; OptionsFromEnv is the single boundary
	// that resolves that value.
	traceExp, err := otlptracegrpc.New(initCtx, otlptracegrpc.WithEndpointURL(opts.Endpoint))
	if err != nil {
		return noopShutdown, fmt.Errorf("create trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)

	logExp, err := otlploggrpc.New(initCtx, otlploggrpc.WithEndpointURL(opts.Endpoint))
	if err != nil {
		cleanupCtx, cancel := shutdownCtxFrom(initCtx)
		defer cancel()
		_ = tp.Shutdown(cleanupCtx)
		return noopShutdown, fmt.Errorf("create log exporter: %w", err)
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
		sdklog.WithResource(res),
	)

	metricExp, err := otlpmetricgrpc.New(initCtx, otlpmetricgrpc.WithEndpointURL(opts.Endpoint))
	if err != nil {
		cleanupCtx, cancel := shutdownCtxFrom(initCtx)
		defer cancel()
		_ = tp.Shutdown(cleanupCtx)
		_ = lp.Shutdown(cleanupCtx)
		return noopShutdown, fmt.Errorf("create metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
	)

	// Atomic publish -- the code below is infallible.
	otel.SetTracerProvider(tp)
	global.SetLoggerProvider(lp)
	otel.SetMeterProvider(mp)

	bundle := &providerBundle{tracer: tp, logger: lp, meter: mp}
	return bundle.shutdown, nil
}

// Ensure otellog is referenced even when only used transitively via the
// global provider.
var _ otellog.LoggerProvider = (*sdklog.LoggerProvider)(nil)

// providerBundle holds the providers we need to shut down together.
type providerBundle struct {
	tracer *sdktrace.TracerProvider
	logger *sdklog.LoggerProvider
	meter  *sdkmetric.MeterProvider
}

func (p *providerBundle) shutdown(ctx context.Context) error {
	var errs []error
	if p.tracer != nil {
		if err := p.tracer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("tracer shutdown: %w", err))
		}
	}
	if p.logger != nil {
		if err := p.logger.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("logger shutdown: %w", err))
		}
	}
	if p.meter != nil {
		if err := p.meter.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("meter shutdown: %w", err))
		}
	}
	return errors.Join(errs...)
}

func noopShutdown(context.Context) error { return nil }

// shutdownCtxFrom derives a best-effort cleanup context from the init context. On an init failure the parent may already be at/past
// cancellation (timeout, operator Ctrl-C), in which case calling tp.Shutdown(parent) is a no-op and leaks the partially-constructed
// provider. context.WithoutCancel strips the parent's cancellation signal so the timeout added below is the only deadline; values
// (trace correlation, logger attrs) still propagate. Caller must defer the returned cancel func so the context is released on return.
func shutdownCtxFrom(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
}

func buildResource(ctx context.Context, opts Options) (*resource.Resource, error) {
	var attrs []attribute.KeyValue
	// opts.ServiceName is added unconditionally when non-empty; callers that want OTEL_SERVICE_NAME to win pass empty here. The
	// resolution happens in OptionsFromEnv at the wiring boundary so this function is env-free (issue #179).
	if opts.ServiceName != "" {
		attrs = append(attrs, semconv.ServiceName(opts.ServiceName))
	}
	if opts.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(opts.ServiceVersion))
	}
	if opts.ServiceInstanceID != "" {
		attrs = append(attrs, semconv.ServiceInstanceID(opts.ServiceInstanceID))
	}

	// The resource detectors below read OTEL_RESOURCE_ATTRIBUTES, OTEL_SERVICE_NAME, host, and process info. Merging with the explicit
	// attributes gives operator-supplied values priority while still picking up free metadata.
	return resource.New(ctx,
		// deployment.environment defaults FIRST so the OTEL_RESOURCE_ATTRIBUTES detector below overrides them on conflict (resource.New
		// merges later options over earlier ones). Emitting both the current semconv key (deployment.environment.name) and the deprecated
		// deployment.environment unconditionally keeps the attribute present in every SigNoz instance a fleet-edr binary reports to, which
		// is what lets the config/observability dashboards drive a dynamic environment selector. Fixed to "default" (single-environment
		// product today); an operator scopes per environment by setting OTEL_RESOURCE_ATTRIBUTES=deployment.environment=<name>.
		resource.WithAttributes(
			semconv.DeploymentEnvironmentName("default"),
			attribute.String("deployment.environment", "default"), // deprecated attribute still consumed by SigNoz
		),
		resource.WithFromEnv(),
		resource.WithHost(),
		resource.WithProcess(),
		resource.WithAttributes(attrs...),
	)
}
