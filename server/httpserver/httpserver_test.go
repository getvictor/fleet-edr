package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// installTracer installs a real SDK tracer provider so otelhttp produces valid SpanContexts (the global no-op provider returns zero
// trace IDs, which defeats the test). Both the tracer provider and the text-map propagator are restored on cleanup so the global state
// does not leak into subsequent tests.
func installTracer(t *testing.T) {
	t.Helper()
	tp := sdktrace.NewTracerProvider()
	prevProvider := otel.GetTracerProvider()
	prevPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prevProvider)
		otel.SetTextMapPropagator(prevPropagator)
	})
}

func newLogger(buf io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestBuild_GeneratesTraceAndEchoesRequestID(t *testing.T) { //nolint:paralleltest // installs/depends on the process-global OTel tracer provider; the Build tests must run serially
	installTracer(t)
	var logs bytes.Buffer
	logger := newLogger(&logs)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := Build(mux, Options{Logger: logger, ServiceName: "test"})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/ping", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", string(body))

	got := resp.Header.Get("X-Request-ID")
	assert.Len(t, got, 32, "X-Request-ID should be a 32-hex trace id: %q", got)
}

func TestBuild_HonoursInboundTraceparent(t *testing.T) { //nolint:paralleltest // installs/depends on the process-global OTel tracer provider; the Build tests must run serially
	installTracer(t)
	var logs bytes.Buffer
	logger := newLogger(&logs)

	capturedSpan := make(chan trace.SpanContext, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /probe", func(w http.ResponseWriter, r *http.Request) {
		capturedSpan <- trace.SpanContextFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	h := Build(mux, Options{Logger: logger})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// Known trace and span from the W3C spec example; middleware should produce a child span
	// under this trace id.
	inboundTP := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/probe", nil)
	require.NoError(t, err)
	req.Header.Set("Traceparent", inboundTP)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })

	sc := <-capturedSpan
	assert.Equal(t, "0af7651916cd43dd8448eb211c80319c", sc.TraceID().String())
	// span id must be a new (non-zero) child, not the inbound parent id.
	assert.NotEqual(t, "b7ad6b7169203331", sc.SpanID().String())
	assert.True(t, sc.IsValid())
}

func TestBuild_AccessLogLevels(t *testing.T) { //nolint:paralleltest // installs/depends on the process-global OTel tracer provider; the Build tests must run serially
	installTracer(t)
	var logs bytes.Buffer
	logger := newLogger(&logs)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ok", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /bad", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(30 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	rec := &fakeRequestMetrics{}
	h := Build(mux, Options{Logger: logger, SlowThreshold: 10 * time.Millisecond, Metrics: rec})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	for _, path := range []string{"/ok", "/bad", "/slow", "/boom"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
	}

	lines := splitLines(t, logs.Bytes())
	require.Len(t, lines, 4)

	byPath := map[string]map[string]any{}
	for _, ln := range lines {
		var rec map[string]any
		require.NoError(t, json.Unmarshal(ln, &rec))
		byPath[rec["path"].(string)] = rec
	}

	// Healthy 2xx drops to debug (the noise fix); client errors stay at info; slow + 5xx stay at warn.
	assert.Equal(t, "DEBUG", byPath["/ok"]["level"])
	assert.Equal(t, "INFO", byPath["/bad"]["level"])
	assert.Equal(t, "WARN", byPath["/slow"]["level"])
	assert.Equal(t, true, byPath["/slow"]["slow"])
	assert.Equal(t, "WARN", byPath["/boom"]["level"])
	// The route template (not the raw path) is stamped on the line and is what the metric is labeled by.
	assert.Equal(t, "/ok", byPath["/ok"]["route"])

	// Every request, including the healthy 2xx that no longer logs at info, is recorded on the metric.
	require.Len(t, rec.calls, 4)
	got := map[string]metricCall{}
	for _, c := range rec.calls {
		got[c.route] = c
	}
	assert.Equal(t, http.MethodGet, got["/ok"].method)
	assert.Equal(t, http.StatusOK, got["/ok"].status)
	assert.Equal(t, http.StatusBadRequest, got["/bad"].status)
	assert.Equal(t, http.StatusInternalServerError, got["/boom"].status)
}

type metricCall struct {
	method, route string
	status        int
	dur           time.Duration
}

// fakeRequestMetrics captures ObserveHTTPRequest calls so the access-log test can assert the metric is recorded for every
// request (including the healthy ones that no longer log) with the route template, not the raw path.
type fakeRequestMetrics struct{ calls []metricCall }

func (f *fakeRequestMetrics) ObserveHTTPRequest(_ context.Context, method, route string, status int, d time.Duration) {
	f.calls = append(f.calls, metricCall{method: method, route: route, status: status, dur: d})
}

func TestBuild_RecoversPanic(t *testing.T) { //nolint:paralleltest // installs/depends on the process-global OTel tracer provider; the Build tests must run serially
	installTracer(t)
	var logs bytes.Buffer
	logger := newLogger(&logs)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /panic", func(_ http.ResponseWriter, _ *http.Request) {
		panic("test panic")
	})
	h := Build(mux, Options{Logger: logger})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/panic", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	// Must see a panic-recovered log with trace_id stamped by the enricher (when logging is
	// wired through that package). This test uses raw slog so no enricher; just assert the msg.
	assert.Contains(t, logs.String(), "panic recovered")
	assert.Contains(t, logs.String(), "test panic")
}

func TestBuild_XRequestIDFallbackWithoutTracer(t *testing.T) { //nolint:paralleltest // installs/depends on the process-global OTel tracer provider; the Build tests must run serially
	// Do NOT install a tracer provider; otelhttp will still add a span via the no-op provider,
	// whose SpanContext is invalid. In that case we must fall back to the inbound X-Request-ID.
	var logs bytes.Buffer
	logger := newLogger(&logs)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /noop", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Build(mux, Options{Logger: logger})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/noop", nil)
	require.NoError(t, err)
	req.Header.Set("X-Request-ID", "legacy-id-42")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })

	assert.Equal(t, "legacy-id-42", resp.Header.Get("X-Request-ID"))
}

func splitLines(t *testing.T, b []byte) [][]byte {
	t.Helper()
	if len(b) == 0 {
		return nil
	}
	lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	return lines
}

// TestBuild_AccessLog_UnmatchedRouteLabel pins the Gemini + Copilot fix: a request matching no route logs and records the route
// as "unmatched" (not ""), so the access-log attribute and the metric label agree.
func TestBuild_AccessLog_UnmatchedRouteLabel(t *testing.T) { //nolint:paralleltest // installs/depends on the process-global OTel tracer provider; the Build tests must run serially
	installTracer(t)
	var logs bytes.Buffer
	logger := newLogger(&logs)
	rec := &fakeRequestMetrics{}
	h := Build(http.NewServeMux(), Options{Logger: logger, Metrics: rec}) // empty mux: every request is an unmatched 404

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/no/such/path", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	lines := splitLines(t, logs.Bytes())
	require.Len(t, lines, 1)
	var line map[string]any
	require.NoError(t, json.Unmarshal(lines[0], &line))
	assert.Equal(t, "unmatched", line["route"])
	require.Len(t, rec.calls, 1)
	assert.Equal(t, "unmatched", rec.calls[0].route)
}
