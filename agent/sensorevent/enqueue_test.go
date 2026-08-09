package sensorevent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnqueueEmitterBuildsTheIngestEnvelope(t *testing.T) {
	t.Parallel()
	var got []byte
	emit := NewEnqueueEmitter(
		func() string { return "HOST-1" },
		func(_ context.Context, b []byte) error { got = b; return nil },
		func() int64 { return 1_700_000_000_000_000_000 },
	)
	require.NoError(t, emit(context.Background(), EventType, map[string]any{"provider": "content_filter", "state": StateStopped}))

	var env map[string]any
	require.NoError(t, json.Unmarshal(got, &env))
	// The ingest handler requires these four alongside the payload; a missing one is a 4xx for the whole batch, not just
	// this event, so the shape is pinned rather than assumed.
	assert.Equal(t, "HOST-1", env["host_id"])
	assert.Equal(t, EventType, env["event_type"])
	assert.InDelta(t, 1.7e18, env["timestamp_ns"], 1e3)
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, env["event_id"],
		"event_id is declared uuid-format in schema/events.json")
	assert.Equal(t, map[string]any{"provider": "content_filter", "state": "stopped"}, env["payload"])
}

// spec:agent-status-reporting/a-transition-record-is-not-lost-to-a-transient-failure/nothing-is-recorded-before-enrollment-completes
func TestEnqueueEmitterRefusesToEmitBeforeEnrollment(t *testing.T) {
	t.Parallel()
	// An event nothing can be attributed to is not evidence. The extension re-publishes liveness on every handshake, so
	// the state is re-observed once enrollment lands.
	called := false
	emit := NewEnqueueEmitter(
		func() string { return "" },
		func(context.Context, []byte) error { called = true; return nil },
		func() int64 { return 1 },
	)
	require.Error(t, emit(context.Background(), EventType, map[string]any{}))
	assert.False(t, called)
}

func TestEnqueueEmitterSurfacesQueueFailures(t *testing.T) {
	t.Parallel()
	// Transitions relies on the error to retry rather than drop the transition.
	emit := NewEnqueueEmitter(
		func() string { return "HOST-1" },
		func(context.Context, []byte) error { return errors.New("queue full") },
		func() int64 { return 1 },
	)
	assert.Error(t, emit(context.Background(), EventType, map[string]any{}))
}
