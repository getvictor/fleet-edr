package metrics

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// spec:observability-instrumentation/stable-counter-names/already-delivered-queue-trim-is-distinguishable-from-data-loss
//
// Agent-side counterpart to server/metrics's TestRecorder_RecordsCounters (which pins the same scenario
// from the consolidated Recorder API). Proves the agent's Recorder emits the lossy=true vs lossy=false
// distinction on edr.agent.queue.dropped: the assertions on losslessSum (3) and lossySum (5) split the
// data points by attribute so a regression that dropped the `lossy` attribute would mix the totals.
func TestRecorder_QueueDropped(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	m := mp.Meter("test")
	r := &Recorder{}
	var err error
	r.queueDropped, err = m.Int64Counter("edr.agent.queue.dropped")
	require.NoError(t, err)

	ctx := context.Background()
	r.QueueDropped(ctx, 3, false)
	r.QueueDropped(ctx, 5, true)
	r.QueueDropped(ctx, 0, false) // n<=0 must be a no-op
	r.QueueDropped(ctx, -1, true)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &rm))

	var losslessSum, lossySum int64
	for _, sm := range rm.ScopeMetrics {
		for _, im := range sm.Metrics {
			if im.Name != "edr.agent.queue.dropped" {
				continue
			}
			sum, ok := im.Data.(metricdata.Sum[int64])
			require.True(t, ok)
			for _, dp := range sum.DataPoints {
				lossy, present := dp.Attributes.Value("lossy")
				require.True(t, present)
				if lossy.AsBool() {
					lossySum += dp.Value
				} else {
					losslessSum += dp.Value
				}
			}
		}
	}
	assert.Equal(t, int64(3), losslessSum)
	assert.Equal(t, int64(5), lossySum)
}

// spec:observability-instrumentation/instrumentation-is-safe-on-a-nil-receiver/call-sites-do-not-guard-the-recorder
//
// Companion to server/metrics's TestNilRecorder_AllMethodsSafe; pins the agent-side half of the
// nil-recorder safety contract. The agent queue drives this directly on every Enqueue cap-eviction path,
// so the regression bar is real even though the assertion is trivially small.
func TestNilRecorder_QueueDropped_Safe(t *testing.T) {
	var r *Recorder
	assert.NotPanics(t, func() {
		r.QueueDropped(context.Background(), 1, false)
	})
}

// TestNew exercises the production constructor that wires the global OTel meter, covering the path that the agent main package takes
// at startup. We can't inspect the resulting counter through the global meter without leaking state across tests, so we just verify
// the Recorder is shaped correctly and that recording against it does not panic - the no-op SDK swallows the sample when no OTLP
// endpoint is configured.
func TestNew(t *testing.T) {
	r := New(nil)
	require.NotNil(t, r)
	require.NotNil(t, r.queueDropped)
	require.NotNil(t, r.eventsDroppedTooLarge)
	assert.NotPanics(t, func() {
		r.QueueDropped(context.Background(), 7, true)
		r.EventsDroppedTooLarge(context.Background(), 1)
	})
}

// fakeDepthSource is a deterministic QueueDepthSource that returns a fixed value or a fixed error. Used by the queue-depth
// observable-gauge tests to drive both the happy-path Observe and the callback-error swallow branches without spinning up a
// real SQLite queue.
type fakeDepthSource struct {
	depth int64
	err   error
}

func (f *fakeDepthSource) Depth(_ context.Context) (int64, error) {
	return f.depth, f.err
}

// spec:agent-event-uploader/over-cap-server-responses-split-and-retry-the-batch/server-returns-413-for-a-single-event-batch
//
// Pins the counter-name + nil-safe + n<=0 no-op contract on the agent's events_dropped_too_large counter. Mirrors the
// TestRecorder_QueueDropped shape: a ManualReader-backed meter so the collect cycle is synchronous, then sum the data
// points by the documented attribute set (none for this counter - host identity rides on the OTLP resource).
func TestRecorder_EventsDroppedTooLarge(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	r := NewWithMeter(nil, mp.Meter("test"))

	ctx := context.Background()
	r.EventsDroppedTooLarge(ctx, 1)
	r.EventsDroppedTooLarge(ctx, 4)
	r.EventsDroppedTooLarge(ctx, 0)  // n<=0 must be a no-op
	r.EventsDroppedTooLarge(ctx, -1) // negative must be a no-op

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &rm))

	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, im := range sm.Metrics {
			if im.Name != "edr.agent.uploader.events_dropped_too_large" {
				continue
			}
			sum, ok := im.Data.(metricdata.Sum[int64])
			require.True(t, ok, "counter must be exported as a Sum")
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
		}
	}
	assert.Equal(t, int64(5), total, "1 + 4 = 5; the 0 and -1 calls are no-ops")
}

// spec:observability-instrumentation/instrumentation-is-safe-on-a-nil-receiver/call-sites-do-not-guard-the-recorder
//
// Companion to TestNilRecorder_QueueDropped_Safe; pins the same nil-safety bar for EventsDroppedTooLarge so call sites
// in the uploader's recursive split-and-drop path can fire the counter unconditionally.
func TestNilRecorder_EventsDroppedTooLarge_Safe(t *testing.T) {
	var r *Recorder
	assert.NotPanics(t, func() {
		r.EventsDroppedTooLarge(context.Background(), 1)
	})
}

// TestRecorder_QueueDepthGauge pins the agent's queue-depth observable-gauge contract: every collection cycle invokes the
// depth source's callback and reports the returned value. The ManualReader's synchronous Collect makes the test deterministic
// (production code reads the same gauge through the OTel reader's periodic Collect on the OTLP push cadence, which is
// configured by `observability.Init`).
func TestRecorder_QueueDepthGauge(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	src := &fakeDepthSource{depth: 42}
	r := NewWithMeter(src, mp.Meter("test"))
	require.NotNil(t, r.queueDepth, "gauge must be registered when depth source is non-nil")

	ctx := context.Background()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &rm))

	var observed int64 = -1
	for _, sm := range rm.ScopeMetrics {
		for _, im := range sm.Metrics {
			if im.Name != "edr.agent.queue.depth" {
				continue
			}
			gauge, ok := im.Data.(metricdata.Gauge[int64])
			require.True(t, ok, "queue-depth must be exported as a Gauge")
			require.Len(t, gauge.DataPoints, 1)
			observed = gauge.DataPoints[0].Value
		}
	}
	assert.Equal(t, int64(42), observed)

	// Update the source and collect again - the gauge tracks the live value, not a snapshot at registration.
	src.depth = 7
	require.NoError(t, reader.Collect(ctx, &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, im := range sm.Metrics {
			if im.Name != "edr.agent.queue.depth" {
				continue
			}
			gauge := im.Data.(metricdata.Gauge[int64])
			require.Len(t, gauge.DataPoints, 1)
			observed = gauge.DataPoints[0].Value
		}
	}
	assert.Equal(t, int64(7), observed)
}

// TestQueueDepthGauge_CallbackErrorSwallowed pins the soft-fail contract on the depth-source callback. A failing source
// must NOT propagate the error to the OTel collection cycle (which would drop every other gauge in the same cycle);
// instead the callback logs and returns nil. The post-condition is that no panic and no propagated error reach Collect.
func TestQueueDepthGauge_CallbackErrorSwallowed(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	src := &fakeDepthSource{err: errors.New("boom")}
	NewWithMeter(src, mp.Meter("test"))

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
}

// TestQueueDepthGauge_NilSourceSkipsRegistration pins the "nil depth source disables the gauge" contract. Callers that have no
// queue yet (early startup, tests) pass nil; the constructor must not register a gauge that would crash on invocation.
func TestQueueDepthGauge_NilSourceSkipsRegistration(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	r := NewWithMeter(nil, mp.Meter("test"))
	assert.Nil(t, r.queueDepth, "gauge must NOT be registered when depth source is nil")

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, im := range sm.Metrics {
			if im.Name == "edr.agent.queue.depth" {
				t.Fatalf("gauge unexpectedly present with nil source")
			}
		}
	}
}
