// Package logging builds the *slog.Logger used by the EDR agent. It mirrors server/logging:
// multi-handler fans to stderr and the otelslog bridge, plus span-context enrichment so every
// record carries trace_id+span_id when a span is active.
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

// Options selects the handler flavor and base attrs.
type Options struct {
	Level               string
	Format              string
	InstrumentationName string
	BaseAttrs           []slog.Attr
}

// New returns a *slog.Logger per Options.
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
	stderr = &traceEnricher{next: stderr}

	name := opts.InstrumentationName
	if name == "" {
		name = "fleet-edr-agent"
	}
	otelHandler := otelslog.NewHandler(name)

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

type traceEnricher struct{ next slog.Handler }

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

type multiHandler struct{ handlers []slog.Handler }

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
