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
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// defaultSlowThreshold is the access-log "this request is slow" cutoff used when Options.SlowThreshold is zero. Lines past this
// latency upgrade from info to warn so SigNoz can alert on regressions without sampling every request.
const defaultSlowThreshold = 500 * time.Millisecond

// RequestMetrics is the access-log middleware's hook for recording per-request latency on a metric. *metrics.Recorder satisfies
// it. Kept as a local interface (rather than importing the metrics package) so httpserver stays decoupled and tests can pass a
// fake. nil disables the recording.
type RequestMetrics interface {
	// ObserveHTTPRequest records one request's latency. route is the matched route TEMPLATE ("/api/hosts/{host_id}/tree") or
	// "unmatched"; the implementation owns label cardinality.
	ObserveHTTPRequest(ctx context.Context, method, route string, statusCode int, d time.Duration)
}

// Options configures the middleware chain.
type Options struct {
	// Logger is required; all middleware logs through it.
	Logger *slog.Logger
	// Metrics, when set, receives one ObserveHTTPRequest call per request from the access-log layer. nil disables it (e.g. the
	// ingest-only binary or unit tests that don't assert metrics).
	Metrics RequestMetrics
	// ServiceName is the operation name passed to otelhttp.NewHandler; used in the span name prefix.
	ServiceName string
	// SlowThreshold upgrades access-log lines to warn when the handler took longer than this. Zero uses the default (defaultSlowThreshold
	// = 500ms). A negative value disables the upgrade entirely: Build leaves negatives untouched and accessLog's `slowThreshold > 0` gate
	// then short-circuits.
	SlowThreshold time.Duration
	// TLSEnabled toggles the HSTS response header. Only set this true when the server actually speaks TLS; emitting HSTS over plain HTTP
	// is a footgun that can make users unreachable if they accidentally deploy the next process without TLS.
	TLSEnabled bool
	// ClientIPResolver, when set, runs as middleware that resolves the trusted client IP once per request and stashes it on ctx so
	// downstream rate-limit + audit code reads the same value (issue #81). nil disables the middleware: handlers fall back to the direct
	// TCP peer via httpserver.ClientIP.
	ClientIPResolver *ClientIPResolver
}

// Build wraps the provided handler with the full middleware chain.
func Build(handler http.Handler, opts Options) http.Handler {
	if opts.Logger == nil {
		panic("httpserver.Build: Logger is required")
	}
	if opts.SlowThreshold == 0 {
		opts.SlowThreshold = defaultSlowThreshold
	}
	if opts.ServiceName == "" {
		opts.ServiceName = "fleet-edr"
	}

	h := handler
	h = recoverMiddleware(opts.Logger)(h)
	h = accessLog(opts.Logger, opts.SlowThreshold, opts.Metrics)(h)
	if opts.TLSEnabled {
		h = hstsHeader()(h)
	}
	h = xRequestIDEcho()(h)
	// Client-IP resolution wraps xRequestIDEcho so the resolver runs outermost in the application layer (still inside otelhttp's span).
	// The resolved IP is therefore on ctx by the time accessLog + downstream handlers read it via ClientIP(r). Skipped entirely when no
	// proxies are configured: the empty trusted list yields the same value httpserver.ClientIP's fallback does, with one fewer per-request
	// allocation.
	if opts.ClientIPResolver != nil {
		h = opts.ClientIPResolver.Middleware(h)
	}
	h = otelhttp.NewHandler(h, opts.ServiceName,
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			// otelhttp calls the formatter inside its own handler, so r.Pattern may be empty. Use method + path; patterns like
			// "/api/hosts/{host_id}/tree" appear as literal paths, which is acceptable for a pilot-scale product.
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

// xRequestIDEcho sets the X-Request-ID response header to the hex trace-id when a span is active, or to the inbound X-Request-ID
// header when it is present and no span is running. This header is for humans (curl output, load balancer logs) and does not drive
// correlation.
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
			defer func() { //nolint:contextcheck // closure pulls ctx from r.Context() below; contextcheck can't see through the defer.
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

// routeTemplate extracts the path template from a ServeMux pattern: "POST /api/events" -> "/api/events", "/healthz" -> "/healthz".
// The path begins at the first '/', after any optional "METHOD " and host. Returns "" for an empty pattern (no route matched).
func routeTemplate(pattern string) string {
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		return pattern[i:]
	}
	return ""
}

// accessLog records each request's latency on the metrics hook and logs the noteworthy ones. The per-request line is NOT an
// info-level firehose: healthy 2xx/3xx requests log at debug (off in prod), client errors (4xx) at info, and 5xx or
// slow (> slowThreshold) requests at warn. The volume + latency signal for every request, including the healthy ones, lives in
// the http.server.request.duration metric instead, so high-frequency endpoints (POST /api/events) no longer drown the log.
func accessLog(logger *slog.Logger, slowThreshold time.Duration, recorder RequestMetrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusCapture{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			dur := time.Since(start)
			ctx := r.Context()

			// r.Pattern is the route template the ServeMux matched (set on this request before the handler ran); it is bounded by
			// the route table. Strip the leading "METHOD " (and any host) so the metric label is just the path template. Empty
			// means no route matched (404 / scanner traffic): record it as "unmatched" rather than the raw path to bound cardinality.
			route := routeTemplate(r.Pattern)
			if recorder != nil {
				recorder.ObserveHTTPRequest(ctx, r.Method, route, rw.status, dur)
			}

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"route", route,
				"status", rw.status,
				"bytes", rw.bytes,
				"duration_ms", dur.Milliseconds(),
				"remote_addr", ClientIP(r),
			}

			switch {
			case rw.status >= http.StatusInternalServerError:
				logger.WarnContext(ctx, "http request", attrs...)
			case slowThreshold > 0 && dur > slowThreshold:
				logger.WarnContext(ctx, "http request (slow)", append(attrs, "slow", true)...)
			case rw.status >= http.StatusBadRequest:
				logger.InfoContext(ctx, "http request", attrs...)
			default:
				// Healthy 2xx/3xx: debug only. The metric carries the rate + latency; logging every one is the noise this avoids.
				logger.DebugContext(ctx, "http request", attrs...)
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

// NoStoreJSON is a small helper for health handlers: writes JSON with no-store cache headers.
func NoStoreJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.ErrorContext(ctx, "encode response", "err", err)
	}
}
