// Package observability configures the OpenTelemetry SDK for the EDR agent.
//
// Init installs global tracer, meter, and logger providers backed by OTLP/gRPC when
// OTEL_EXPORTER_OTLP_ENDPOINT is set, and leaves the SDK defaults (no-op) in place when it
// isn't. The W3C tracecontext + baggage propagators are installed either way so inbound
// traceparent headers are honoured the moment a tracer provider is swapped in later (e.g. by
// a test).
//
// The globals are published atomically: every provider is constructed and wired up before any
// of them becomes visible through `otel.SetTracerProvider` / `global.SetLoggerProvider` /
// `otel.SetMeterProvider`. A failure to create any exporter leaves the globals untouched and
// returns an error, so callers never observe a half-initialised observability stack.
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
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
)

// Options configure the OTel SDK.
type Options struct {
	ServiceName       string
	ServiceVersion    string
	ServiceInstanceID string
	InitTimeout       time.Duration
}

// ShutdownFunc flushes buffered telemetry to the collector.
type ShutdownFunc func(ctx context.Context) error

// Init configures global providers. Safe to call even when OTel is disabled.
func Init(ctx context.Context, opts Options) (ShutdownFunc, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
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

	// Stand up every exporter + provider BEFORE publishing any of them. If any step fails, any
	// previously-created providers are shut down and no global is modified.
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
		cleanupCtx, cancel := shutdownCtxFrom(initCtx)
		defer cancel()
		_ = tp.Shutdown(cleanupCtx)
		return noopShutdown, fmt.Errorf("create log exporter: %w", err)
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
		sdklog.WithResource(res),
	)

	metricExp, err := otlpmetricgrpc.New(initCtx)
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

	// Atomic publish — everything below is infallible.
	otel.SetTracerProvider(tp)
	global.SetLoggerProvider(lp)
	otel.SetMeterProvider(mp)

	bundle := &providerBundle{tracer: tp, logger: lp, meter: mp}
	return bundle.shutdown, nil
}

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

// shutdownCtxFrom derives a best-effort cleanup context from the init context.
// On an init failure the parent may already be at/past cancellation (timeout,
// operator Ctrl-C), in which case calling tp.Shutdown(parent) is a no-op and
// leaks the partially-constructed provider. context.WithoutCancel strips the
// parent's cancellation signal so the timeout added below is the only
// deadline; values (trace correlation, logger attrs) still propagate. Caller
// must defer the returned cancel func so the context is released on return.
func shutdownCtxFrom(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
}

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
	return resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithHost(),
		resource.WithProcess(),
		resource.WithAttributes(attrs...),
	)
}
