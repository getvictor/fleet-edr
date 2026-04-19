// Package logging builds the *slog.Logger used by the EDR server.
//
// The returned logger fans records across two handlers:
//  1. A stderr handler (JSON or text), wrapped in an enricher that stamps trace_id+span_id from
//     the context span onto every record.
//  2. An OTel slog bridge handler that exports the same records via the OTel LoggerProvider so
//     they show up alongside traces in the backend (SigNoz, Tempo, Datadog, etc.).
//
// The bridge is wired against the global LoggerProvider installed by observability.Init; when
// OTel is disabled, the global provider is a no-op and records simply do not leave the process.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/trace"
)

// Options selects the handler flavor.
type Options struct {
	// Level is one of "debug", "info", "warn", "error". Case-insensitive.
	Level string
	// Format is "json" or "text". JSON is the production default.
	Format string
	// InstrumentationName is the slog "logger name" passed to the OTel bridge. Use your binary name.
	InstrumentationName string
	// BaseAttrs are attached to every record from this logger. Useful for host_id on the agent.
	BaseAttrs []slog.Attr
}

// New builds a *slog.Logger per Options writing to w (typically os.Stderr) and the OTel bridge.
func New(w io.Writer, opts Options) (*slog.Logger, error) {
	lvl, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}
	if opts.Format == "" {
		opts.Format = "json"
	}

	var stderr slog.Handler
	hOpts := &slog.HandlerOptions{Level: lvl}
	switch strings.ToLower(opts.Format) {
	case "json":
		stderr = slog.NewJSONHandler(w, hOpts)
	case "text":
		stderr = slog.NewTextHandler(w, hOpts)
	default:
		return nil, fmt.Errorf("log format %q must be 'json' or 'text'", opts.Format)
	}

	// Enrich stderr records with trace context drawn from ctx. The OTel bridge handler below
	// already adds these fields on its own side, so we only decorate the stderr handler.
	stderr = &traceEnricher{next: stderr}

	name := opts.InstrumentationName
	if name == "" {
		name = "fleet-edr"
	}
	// otelslog.NewHandler reads the global LoggerProvider. When OTel is disabled this becomes a
	// cheap no-op emitter. Upstream's Enabled() always returns true, so we wrap it in a level
	// filter that matches the stderr handler — otherwise DEBUG and INFO records would be
	// exported to OTLP even when the configured level is WARN or ERROR.
	otelHandler := slog.Handler(&levelFilter{level: lvl, next: otelslog.NewHandler(name)})

	h := slog.Handler(&multiHandler{handlers: []slog.Handler{stderr, otelHandler}})
	if len(opts.BaseAttrs) > 0 {
		h = h.WithAttrs(opts.BaseAttrs)
	}
	return slog.New(h), nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("log level %q must be one of debug, info, warn, error", s)
}

// levelFilter drops records below the configured level before they reach the wrapped handler.
// Applied to the otelslog bridge because its own Enabled() always returns true — without this
// filter, DEBUG/INFO records would leak to OTLP even when EDR_LOG_LEVEL is WARN or ERROR.
type levelFilter struct {
	level slog.Level
	next  slog.Handler
}

func (l *levelFilter) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= l.level && l.next.Enabled(ctx, level)
}

func (l *levelFilter) Handle(ctx context.Context, r slog.Record) error {
	if r.Level < l.level {
		return nil
	}
	return l.next.Handle(ctx, r)
}

func (l *levelFilter) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &levelFilter{level: l.level, next: l.next.WithAttrs(attrs)}
}

func (l *levelFilter) WithGroup(name string) slog.Handler {
	return &levelFilter{level: l.level, next: l.next.WithGroup(name)}
}

// traceEnricher adds trace_id and span_id attrs from the context span, when present, to every
// record passing through. It delegates to the wrapped handler for everything else.
type traceEnricher struct {
	next slog.Handler
}

func (t *traceEnricher) Enabled(ctx context.Context, level slog.Level) bool {
	return t.next.Enabled(ctx, level)
}

func (t *traceEnricher) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return t.next.Handle(ctx, r)
}

func (t *traceEnricher) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceEnricher{next: t.next.WithAttrs(attrs)}
}

func (t *traceEnricher) WithGroup(name string) slog.Handler {
	return &traceEnricher{next: t.next.WithGroup(name)}
}

// multiHandler fans a record to every wrapped handler.
type multiHandler struct {
	handlers []slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range m.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		// Each handler must get its own copy because Handle is allowed to mutate the record (add
		// attrs, advance the PC walk, etc.).
		if err := h.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		out[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: out}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		out[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: out}
}
