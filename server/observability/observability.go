// Package observability wires up the OpenTelemetry SDK for the EDR server.
//
// Init installs global tracer, meter, and logger providers backed by OTLP/gRPC when
// OTEL_EXPORTER_OTLP_ENDPOINT is set, and leaves the SDK defaults (no-op) in place when it
// isn't. Callers can therefore invoke otel.Tracer / otel.Meter / otelslog unconditionally;
// offline dev, CI, and unit tests do not need a running collector.
//
// The globals are published atomically: every provider is constructed and wired up before
// `otel.SetTracerProvider` / `global.SetLoggerProvider` / `otel.SetMeterProvider` is called.
// A failure to create any exporter leaves the globals untouched and returns an error, so
// callers never observe a half-initialised observability stack.
//
// The W3C tracecontext + baggage propagators are installed as the global propagator so
// traceparent headers flow in and out of our HTTP boundaries automatically.
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

// Options configure the OTel SDK. Only the fields we rely on at startup are exposed; the SDK reads
// every other OTEL_* env var (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_BSP_*, etc.) directly.
type Options struct {
	// ServiceName is used when OTEL_SERVICE_NAME is not set in the environment.
	ServiceName string
	// ServiceVersion is injected at build time via -ldflags.
	ServiceVersion string
	// ServiceInstanceID is typically the hostname or a random UUID; useful for distinguishing
	// replicas in the backend UI.
	ServiceInstanceID string
	// InitTimeout caps how long we wait for the OTLP dial during Init. Default 5s.
	InitTimeout time.Duration
}

// ShutdownFunc flushes buffered telemetry to the collector and releases SDK resources.
// Call from main on SIGTERM. Safe to call on a no-op provider; it returns nil.
type ShutdownFunc func(ctx context.Context) error

// Init configures global OTel providers. Returns a ShutdownFunc that is always non-nil.
// When OTEL_EXPORTER_OTLP_ENDPOINT is empty, Init is a no-op and the returned function
// returns nil immediately.
func Init(ctx context.Context, opts Options) (ShutdownFunc, error) {
	// Install the W3C propagator unconditionally; it is harmless on a no-op tracer and crucial
	// when a real tracer is installed later (e.g. a test swaps in a provider via otel.SetTracerProvider).
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		// No-op path: leave the SDK defaults in place and return a shutdown that does nothing.
		return func(context.Context) error { return nil }, nil
	}

	res, err := buildResource(ctx, opts)
	if err != nil {
		return noopShutdown, fmt.Errorf("build resource: %w", err)
	}

	initDeadline := opts.InitTimeout
	if initDeadline == 0 {
		initDeadline = 5 * time.Second
	}
	initCtx, cancel := context.WithTimeout(ctx, initDeadline)
	defer cancel()

	// Construct every exporter + provider BEFORE publishing any of them globally. If any step
	// fails, previously-created providers are shut down and no global is modified, so callers
	// never see a half-initialised observability stack.
	traceExp, err := otlptracegrpc.New(initCtx)
	if err != nil {
		return noopShutdown, fmt.Errorf("create trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)

	logExp, err := otlploggrpc.New(initCtx)
	if err != nil {
		_ = tp.Shutdown(initCtx)
		return noopShutdown, fmt.Errorf("create log exporter: %w", err)
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
		sdklog.WithResource(res),
	)

	metricExp, err := otlpmetricgrpc.New(initCtx)
	if err != nil {
		_ = tp.Shutdown(initCtx)
		_ = lp.Shutdown(initCtx)
		return noopShutdown, fmt.Errorf("create metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
	)

	// Atomic publish — the code below is infallible.
	otel.SetTracerProvider(tp)
	global.SetLoggerProvider(lp)
	otel.SetMeterProvider(mp)

	bundle := &providerBundle{tracer: tp, logger: lp, meter: mp}
	return bundle.shutdown, nil
}

// Ensure otellog is referenced even when only used transitively via the global provider.
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

func buildResource(ctx context.Context, opts Options) (*resource.Resource, error) {
	var attrs []attribute.KeyValue
	if opts.ServiceName != "" && os.Getenv("OTEL_SERVICE_NAME") == "" {
		attrs = append(attrs, semconv.ServiceName(opts.ServiceName))
	}
	if opts.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(opts.ServiceVersion))
	}
	if opts.ServiceInstanceID != "" {
		attrs = append(attrs, semconv.ServiceInstanceID(opts.ServiceInstanceID))
	}

	// The resource detectors below read OTEL_RESOURCE_ATTRIBUTES, OTEL_SERVICE_NAME, host, and process
	// info. Merging with the explicit attributes gives operator-supplied values priority while still
	// picking up free metadata.
	return resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithHost(),
		resource.WithProcess(),
		resource.WithAttributes(attrs...),
	)
}
