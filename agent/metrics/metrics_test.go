package metrics

import (
	"context"
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
// the Recorder is shaped correctly and that recording against it does not panic — the no-op SDK swallows the sample when no OTLP
// endpoint is configured.
func TestNew(t *testing.T) {
	r := New()
	require.NotNil(t, r)
	require.NotNil(t, r.queueDropped)
	assert.NotPanics(t, func() {
		r.QueueDropped(context.Background(), 7, true)
	})
}
