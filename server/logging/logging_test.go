package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func TestNew_JSONDefault(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(&buf, Options{Level: "info", Format: "json"})
	require.NoError(t, err)

	log.InfoContext(t.Context(), "hello", "key", "value")

	line := firstLine(t, &buf)
	var rec map[string]any
	require.NoError(t, json.Unmarshal(line, &rec))
	assert.Equal(t, "hello", rec["msg"])
	assert.Equal(t, "INFO", rec["level"])
	assert.Equal(t, "value", rec["key"])
	assert.NotContains(t, rec, "trace_id", "no trace id when context has no span")
}

func TestNew_Text(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(&buf, Options{Level: "info", Format: "text"})
	require.NoError(t, err)
	log.InfoContext(t.Context(), "human-readable")
	got := buf.String()
	assert.Contains(t, got, "msg=human-readable")
	// Text format is not JSON; must not parse.
	var rec map[string]any
	assert.Error(t, json.Unmarshal([]byte(strings.TrimSpace(got)), &rec))
}

func TestNew_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(&buf, Options{Level: "warn", Format: "json"})
	require.NoError(t, err)
	log.InfoContext(t.Context(), "dropped")
	log.WarnContext(t.Context(), "kept")
	out := buf.String()
	assert.NotContains(t, out, "dropped")
	assert.Contains(t, out, "kept")
}

func TestNew_InvalidLevel(t *testing.T) {
	var buf bytes.Buffer
	_, err := New(&buf, Options{Level: "spam", Format: "json"})
	assert.ErrorContains(t, err, "spam")
}

func TestNew_InvalidFormat(t *testing.T) {
	var buf bytes.Buffer
	_, err := New(&buf, Options{Level: "info", Format: "xml"})
	assert.ErrorContains(t, err, "xml")
}

func TestNew_TraceEnrichment(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(&buf, Options{Level: "info", Format: "json"})
	require.NoError(t, err)

	// Build a valid SpanContext manually. We don't need an SDK provider for the enricher; the
	// enricher only reads the span context from ctx.
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		SpanID:     trace.SpanID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		TraceFlags: trace.FlagsSampled,
	})
	require.True(t, sc.IsValid())
	ctx := trace.ContextWithSpanContext(t.Context(), sc)

	log.InfoContext(ctx, "with-span")

	line := firstLine(t, &buf)
	var rec map[string]any
	require.NoError(t, json.Unmarshal(line, &rec))
	assert.Equal(t, sc.TraceID().String(), rec["trace_id"])
	assert.Equal(t, sc.SpanID().String(), rec["span_id"])
}

func TestNew_BaseAttrs(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(&buf, Options{
		Level:     "info",
		Format:    "json",
		BaseAttrs: []slog.Attr{slog.String("host_id", "ABC-123")},
	})
	require.NoError(t, err)

	log.InfoContext(t.Context(), "agent-start")
	line := firstLine(t, &buf)
	var rec map[string]any
	require.NoError(t, json.Unmarshal(line, &rec))
	assert.Equal(t, "ABC-123", rec["host_id"])
}

func TestMultiHandler_FanOut(t *testing.T) {
	var a, b bytes.Buffer
	ha := slog.NewJSONHandler(&a, &slog.HandlerOptions{Level: slog.LevelDebug})
	hb := slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})
	mh := &multiHandler{handlers: []slog.Handler{ha, hb}}

	log := slog.New(mh)
	log.InfoContext(context.Background(), "both")
	assert.Contains(t, a.String(), "both")
	assert.Contains(t, b.String(), "both")
}

func firstLine(t *testing.T, buf *bytes.Buffer) []byte {
	t.Helper()
	line, err := buf.ReadBytes('\n')
	require.NoError(t, err)
	return line
}
