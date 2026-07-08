package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// scriptedEventLog is an EventLog fake that hands ProcessOnce a fixed batch and records which IDs were acked vs nacked. Only the
// methods the processor's single-cycle path touches (Claim, Ack, Nack) do anything; the rest are inert.
type scriptedEventLog struct {
	batch  []visibilityapi.Event
	acked  []string
	nacked []string
}

func (s *scriptedEventLog) Append(context.Context, []visibilityapi.Event) error { return nil }
func (s *scriptedEventLog) Claim(context.Context, int) ([]visibilityapi.Event, error) {
	return s.batch, nil
}
func (s *scriptedEventLog) Ack(_ context.Context, ids []string) error {
	s.acked = append(s.acked, ids...)
	return nil
}
func (s *scriptedEventLog) Nack(_ context.Context, ids []string) error {
	s.nacked = append(s.nacked, ids...)
	return nil
}
func (s *scriptedEventLog) CountPending(context.Context) (int64, error)        { return 0, nil }
func (s *scriptedEventLog) PruneProcessed(context.Context, int) (int64, error) { return 0, nil }

// stubBuilder / stubEvaluator return a scripted error so a processor test can drive each nack/ack branch without a graph store.
type stubBuilder struct{ err error }

func (b stubBuilder) ProcessBatch(context.Context, []visibilityapi.Event) error { return b.err }

type stubEvaluator struct{ err error }

func (e stubEvaluator) Evaluate(context.Context, []visibilityapi.Event) error { return e.err }

// capturingLogHandler records every emitted record (at any level, so a debug line is observable) for level assertions.
type capturingLogHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingLogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingLogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *capturingLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingLogHandler) WithGroup(string) slog.Handler      { return h }

// levelOf returns the level of the first record whose message contains substr, and whether one was found.
func (h *capturingLogHandler) levelOf(substr string) (slog.Level, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if strings.Contains(r.Message, substr) {
			return r.Level, true
		}
	}
	return 0, false
}

func oneEventBatch() []visibilityapi.Event {
	return []visibilityapi.Event{{EventID: "evt-1", HostID: "host-a", EventType: "network_connect"}}
}

// spec:observability-instrumentation/detection-materialization-miss-retries-are-bounded-in-log-volume/a-materialization-miss-retry-is-debug-logged-and-counted
// spec:observability-instrumentation/detection-materialization-miss-retries-are-bounded-in-log-volume/a-genuine-detection-failure-still-warn-logs
//
// The processor's classification of a nacked detection batch: a not-yet-materialized subject/flow process (the retryable
// ErrProcessNotYetMaterialized class, issue #631) is an expected transient race, so it must debug-log and increment the
// materialization-retry counter rather than warn-log per retry; any other failure keeps its warn line and does not count.
func TestProcessor_DetectionRetryClassification(t *testing.T) {
	t.Parallel()

	t.Run("materialization miss debug-logs and counts", func(t *testing.T) {
		t.Parallel()
		log := &scriptedEventLog{batch: oneEventBatch()}
		handler := &capturingLogHandler{}
		rec := &capturingRecorder{}
		// A wrapped sentinel mirrors how the engine returns it (fmt.Errorf("rule %s: %w", ...)).
		eval := stubEvaluator{err: fmt.Errorf("rule dns_c2_beacon: %w", rulesapi.ErrProcessNotYetMaterialized)}
		p := NewProcessor(log, stubBuilder{}, eval, slog.New(handler), 0, 1, 1)
		p.SetMetrics(rec)

		p.ProcessOnce(context.Background())

		lvl, ok := handler.levelOf("awaiting process materialization")
		require.True(t, ok, "the materialization-miss retry must be logged")
		assert.Equal(t, slog.LevelDebug, lvl, "a materialization miss logs at debug, not warn")
		_, warned := handler.levelOf("detection failure, will retry batch")
		assert.False(t, warned, "a materialization miss must not emit the warn line")
		assert.Equal(t, int64(1), rec.materializationRetries, "the retry is counted")
		assert.Equal(t, []string{"evt-1"}, log.nacked, "the batch is nacked for retry")
		assert.Empty(t, log.acked, "a failed batch is never acked")
	})

	t.Run("genuine failure warn-logs and does not count", func(t *testing.T) {
		t.Parallel()
		log := &scriptedEventLog{batch: oneEventBatch()}
		handler := &capturingLogHandler{}
		rec := &capturingRecorder{}
		eval := stubEvaluator{err: errors.New("persist detection alert: db down")}
		p := NewProcessor(log, stubBuilder{}, eval, slog.New(handler), 0, 1, 1)
		p.SetMetrics(rec)

		p.ProcessOnce(context.Background())

		lvl, ok := handler.levelOf("detection failure, will retry batch")
		require.True(t, ok, "a genuine failure must be logged")
		assert.Equal(t, slog.LevelWarn, lvl, "a genuine failure logs at warn")
		assert.Zero(t, rec.materializationRetries, "a genuine failure is not counted as a materialization retry")
		assert.Equal(t, []string{"evt-1"}, log.nacked, "the batch is nacked for retry")
	})

	t.Run("materialization miss is nil-metrics safe", func(t *testing.T) {
		t.Parallel()
		log := &scriptedEventLog{batch: oneEventBatch()}
		eval := stubEvaluator{err: fmt.Errorf("rule x: %w", rulesapi.ErrProcessNotYetMaterialized)}
		p := NewProcessor(log, stubBuilder{}, eval, slog.New(&capturingLogHandler{}), 0, 1, 1)
		// No SetMetrics: the retry path must not dereference a nil recorder.
		assert.NotPanics(t, func() { p.ProcessOnce(context.Background()) })
		assert.Equal(t, []string{"evt-1"}, log.nacked)
	})
}

// TestProcessor_BuilderFailureAndHappyPath covers the two non-detection outcomes of a cycle: a graph-builder failure nacks + warns
// (its log is unchanged by issue #631), and a fully successful cycle acks the batch and counts no retry.
func TestProcessor_BuilderFailureAndHappyPath(t *testing.T) {
	t.Parallel()

	t.Run("builder failure nacks and warn-logs", func(t *testing.T) {
		t.Parallel()
		log := &scriptedEventLog{batch: oneEventBatch()}
		handler := &capturingLogHandler{}
		rec := &capturingRecorder{}
		p := NewProcessor(log, stubBuilder{err: errors.New("graph write failed")}, stubEvaluator{}, slog.New(handler), 0, 1, 1)
		p.SetMetrics(rec)

		p.ProcessOnce(context.Background())

		lvl, ok := handler.levelOf("graph builder failure, will retry batch")
		require.True(t, ok, "a builder failure must be logged")
		assert.Equal(t, slog.LevelWarn, lvl, "a builder failure logs at warn")
		assert.Equal(t, []string{"evt-1"}, log.nacked)
		assert.Zero(t, rec.materializationRetries, "a builder failure is not a materialization retry")
	})

	t.Run("successful cycle acks and counts no retry", func(t *testing.T) {
		t.Parallel()
		log := &scriptedEventLog{batch: oneEventBatch()}
		rec := &capturingRecorder{}
		p := NewProcessor(log, stubBuilder{}, stubEvaluator{}, slog.New(&capturingLogHandler{}), 0, 1, 1)
		p.SetMetrics(rec)

		p.ProcessOnce(context.Background())

		assert.Equal(t, []string{"evt-1"}, log.acked, "a clean batch is acked")
		assert.Empty(t, log.nacked, "a clean batch is never nacked")
		assert.Zero(t, rec.materializationRetries)
	})
}
