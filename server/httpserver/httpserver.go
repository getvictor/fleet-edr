// Package httpserver wires the EDR server's HTTP stack.
//
// Build composes otelhttp (auto-instrumentation and W3C trace context extraction), an
// X-Request-ID echo layer, a panic-recovery layer, and an access-log layer around the
// provided mux. Layer order:
//
//	otelhttp( xRequestIDEcho( accessLog( recover( mux ) ) ) )
//
// The span from otelhttp covers the entire request including the access log overhead, so the
// span duration matches what shows up in SigNoz. xRequestIDEcho copies the span's trace-id
// onto the response `X-Request-ID` header (or falls back to an inbound header) so humans have a
// stable handle. The access log runs inside the span so it can stamp trace_id on its lines
// and so the slow-request warn path reflects real handler latency. Recovery runs inside the
// access log so the log entry captures the 500 status set by recovery.
package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Options configures the middleware chain.
type Options struct {
	// Logger is required; all middleware logs through it.
	Logger *slog.Logger
	// ServiceName is the operation name passed to otelhttp.NewHandler; used in the span name prefix.
	ServiceName string
	// SlowThreshold upgrades access-log lines to warn when the handler took longer than this.
	// Zero disables the upgrade. Default 500ms.
	SlowThreshold time.Duration
	// TLSEnabled toggles the HSTS response header. Only set this true when the server actually
	// speaks TLS; emitting HSTS over plain HTTP is a footgun that can make users unreachable if
	// they accidentally deploy the next process without TLS.
	TLSEnabled bool
}

// Build wraps the provided handler with the full middleware chain.
func Build(handler http.Handler, opts Options) http.Handler {
	if opts.Logger == nil {
		panic("httpserver.Build: Logger is required")
	}
	if opts.SlowThreshold == 0 {
		opts.SlowThreshold = 500 * time.Millisecond
	}
	if opts.ServiceName == "" {
		opts.ServiceName = "fleet-edr"
	}

	h := handler
	h = recoverMiddleware(opts.Logger)(h)
	h = accessLog(opts.Logger, opts.SlowThreshold)(h)
	if opts.TLSEnabled {
		h = hstsHeader()(h)
	}
	h = xRequestIDEcho()(h)
	h = otelhttp.NewHandler(h, opts.ServiceName,
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			// otelhttp calls the formatter inside its own handler, so r.Pattern may be empty.
			// Use method + path; patterns like "/api/v1/hosts/{host_id}/tree" appear as literal
			// paths, which is acceptable for a pilot-scale product.
			return r.Method + " " + r.URL.Path
		}),
	)
	return h
}

// hstsHeader adds the Strict-Transport-Security header on every response. Two years, including
// subdomains, matching modern best practice. Only installed when the server speaks TLS.
func hstsHeader() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			next.ServeHTTP(w, r)
		})
	}
}

// xRequestIDEcho sets the X-Request-ID response header to the hex trace-id when a span is active,
// or to the inbound X-Request-ID header when it is present and no span is running.
// This header is for humans (curl output, load balancer logs) and does not drive correlation.
func xRequestIDEcho() func(http.Handler) http.Handler {
	const header = "X-Request-ID"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if sc := trace.SpanContextFromContext(r.Context()); sc.IsValid() {
				w.Header().Set(header, sc.TraceID().String())
			} else if v := r.Header.Get(header); v != "" {
				w.Header().Set(header, v)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// recoverMiddleware catches panics, records them on the active span, logs at error, and returns 500.
func recoverMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					ctx := r.Context()
					span := trace.SpanFromContext(ctx)
					err := fmt.Errorf("panic: %v", rec)
					span.RecordError(err)
					span.SetStatus(codes.Error, "panic recovered")
					logger.ErrorContext(ctx, "panic recovered",
						"path", r.URL.Path,
						"method", r.Method,
						"panic", rec,
						"stack", string(debug.Stack()),
					)
					// Only write the header if nothing has been written yet; we cannot know for sure,
					// so we try and rely on http.ResponseWriter.WriteHeader being idempotent-ish
					// (superfluous calls just log a warning).
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// accessLog emits one log line per request. Status 5xx or duration > slowThreshold upgrade to warn.
func accessLog(logger *slog.Logger, slowThreshold time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusCapture{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			dur := time.Since(start)

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
				"bytes", rw.bytes,
				"duration_ms", dur.Milliseconds(),
				"remote_addr", remoteAddr(r),
			}

			ctx := r.Context()
			switch {
			case rw.status >= http.StatusInternalServerError:
				logger.WarnContext(ctx, "http request", attrs...)
			case slowThreshold > 0 && dur > slowThreshold:
				logger.WarnContext(ctx, "http request (slow)", append(attrs, "slow", true)...)
			default:
				logger.InfoContext(ctx, "http request", attrs...)
			}
		})
	}
}

// statusCapture wraps http.ResponseWriter to record status code and bytes written.
type statusCapture struct {
	http.ResponseWriter
	status   int
	bytes    int
	wroteHdr bool
}

func (s *statusCapture) WriteHeader(code int) {
	if !s.wroteHdr {
		s.status = code
		s.wroteHdr = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusCapture) Write(b []byte) (int, error) {
	if !s.wroteHdr {
		s.wroteHdr = true
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Flush exposes the underlying flusher if present, for SSE / streaming endpoints.
func (s *statusCapture) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// remoteAddr returns the peer address for access logging. We intentionally do NOT consult
// `X-Forwarded-For`: that header is client-settable and trusting it without a trusted-proxy
// allowlist lets any caller spoof their logged source IP. When the server moves behind a
// real reverse proxy (Phase 5 packaging), revisit this with an explicit trusted-proxies
// config knob; until then, r.RemoteAddr is the only trustworthy source.
func remoteAddr(r *http.Request) string {
	return r.RemoteAddr
}

// NoStoreJSON is a small helper for health handlers: writes JSON with no-store cache headers.
func NoStoreJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.ErrorContext(ctx, "encode response", "err", err)
	}
}
