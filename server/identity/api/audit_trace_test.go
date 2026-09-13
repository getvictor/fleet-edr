package api_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/identity/api"
)

func TestTraceIDFromContext(t *testing.T) {
	t.Parallel()
	assert.Empty(t, api.TraceIDFromContext(context.Background()), "no span, no trace")

	traceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	require.NoError(t, err)
	spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	require.NoError(t, err)
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", api.TraceIDFromContext(ctx))
}
