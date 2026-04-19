package metrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestRecorder_QueueDropped proves the Recorder emits the expected counter samples
// with `lossy` attributes that downstream alerts key on. We build a local
// MeterProvider + ManualReader rather than overriding the global one so the test can
// run in parallel with any other that happens to touch otel.Meter.
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

func TestNilRecorder_QueueDropped_Safe(t *testing.T) {
	var r *Recorder
	assert.NotPanics(t, func() {
		r.QueueDropped(context.Background(), 1, false)
	})
}
