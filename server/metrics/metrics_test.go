package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/ingest"
	"github.com/fleetdm/edr/server/retention"
)

// newTestRecorder builds a Recorder backed by a ManualReader so tests can collect
// metrics synchronously rather than racing a periodic reader. Returns both the
// Recorder and a snapshot function.
func newTestRecorder(t *testing.T, gauges GaugeSource, opts Options) (*Recorder, func() metricdata.ResourceMetrics) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	opts.Meter = mp.Meter("test")
	r := New(gauges, opts)
	return r, func() metricdata.ResourceMetrics {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		return rm
	}
}

// findSum extracts a Sum[int64] data point for the given metric name + required
// attribute subset. Returns -1 if nothing matches so assertion failures read naturally.
func findSum(t *testing.T, rm metricdata.ResourceMetrics, name string, want map[string]any) int64 {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				if attrsMatch(dp.Attributes.ToSlice(), want) {
					return dp.Value
				}
			}
		}
	}
	return -1
}

func findGauge(t *testing.T, rm metricdata.ResourceMetrics, name string) int64 {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			g, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				continue
			}
			if len(g.DataPoints) == 0 {
				return -1
			}
			return g.DataPoints[0].Value
		}
	}
	return -1
}

func findHistogramCount(t *testing.T, rm metricdata.ResourceMetrics, name string, want map[string]any) uint64 {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				continue
			}
			for _, dp := range h.DataPoints {
				if attrsMatch(dp.Attributes.ToSlice(), want) {
					return dp.Count
				}
			}
		}
	}
	return 0
}

func attrsMatch(got []attribute.KeyValue, want map[string]any) bool {
	if len(want) == 0 {
		return true
	}
	found := 0
	for _, kv := range got {
		if expected, ok := want[string(kv.Key)]; ok {
			if kv.Value.AsInterface() == expected {
				found++
			}
		}
	}
	return found == len(want)
}

// stubGauges returns canned values for the observable gauges.
type stubGauges struct {
	enrolled int
	offline  int
}

func (s stubGauges) EnrolledHosts(context.Context) (int, error) { return s.enrolled, nil }
func (s stubGauges) OfflineHosts(context.Context, time.Duration) (int, error) {
	return s.offline, nil
}

func TestRecorder_RecordsCounters(t *testing.T) {
	r, collect := newTestRecorder(t, stubGauges{enrolled: 3, offline: 1}, Options{})
	ctx := context.Background()

	r.EventsIngested(ctx, "host-a", 5)
	r.EventsIngested(ctx, "host-b", 2)
	r.AlertCreated(ctx, "dyld_insert", "high")
	r.ObserveDBQuery(ctx, "insert_event", 12*time.Millisecond)
	r.RetentionRowsDeleted(ctx, 42)
	r.QueueDropped(ctx, 3, false)
	r.QueueDropped(ctx, 5, true)

	rm := collect()

	assert.Equal(t, int64(5), findSum(t, rm, "edr.events.ingested", map[string]any{"host_id": "host-a"}))
	assert.Equal(t, int64(2), findSum(t, rm, "edr.events.ingested", map[string]any{"host_id": "host-b"}))
	assert.Equal(t, int64(1), findSum(t, rm, "edr.alerts.created", map[string]any{"rule_id": "dyld_insert", "severity": "high"}))
	assert.Equal(t, int64(42), findSum(t, rm, "edr.retention.rows_deleted", nil))
	assert.Equal(t, int64(3), findSum(t, rm, "edr.agent.queue.dropped", map[string]any{"lossy": false}))
	assert.Equal(t, int64(5), findSum(t, rm, "edr.agent.queue.dropped", map[string]any{"lossy": true}))
	assert.Equal(t, uint64(1), findHistogramCount(t, rm, "edr.db.query.duration", map[string]any{"op": "insert_event"}))
	assert.Equal(t, int64(3), findGauge(t, rm, "edr.enrolled.hosts"))
	assert.Equal(t, int64(1), findGauge(t, rm, "edr.offline.hosts"))
}

func TestRecorder_NilGaugesSkipsGauges(t *testing.T) {
	_, collect := newTestRecorder(t, nil, Options{})
	rm := collect()
	assert.Equal(t, int64(-1), findGauge(t, rm, "edr.enrolled.hosts"))
	assert.Equal(t, int64(-1), findGauge(t, rm, "edr.offline.hosts"))
}

func TestGauges_UseConfiguredThreshold(t *testing.T) {
	var gotThreshold time.Duration
	gauges := thresholdCapturingGauges{out: &gotThreshold}

	_, collect := newTestRecorder(t, gauges, Options{OfflineThreshold: 30 * time.Second})
	_ = collect()
	assert.Equal(t, 30*time.Second, gotThreshold, "offline gauge must pass the configured threshold to the source")
}

type thresholdCapturingGauges struct {
	out *time.Duration
}

func (g thresholdCapturingGauges) EnrolledHosts(context.Context) (int, error) { return 0, nil }
func (g thresholdCapturingGauges) OfflineHosts(_ context.Context, t time.Duration) (int, error) {
	*g.out = t
	return 0, nil
}

func TestNilRecorder_AllMethodsSafe(t *testing.T) {
	// Methods short-circuit on nil so call sites can tolerate "no metrics configured"
	// without defensive checks. Lock that property in as a test.
	var r *Recorder
	ctx := context.Background()
	assert.NotPanics(t, func() {
		r.EventsIngested(ctx, "h", 1)
		r.AlertCreated(ctx, "r", "s")
		r.ObserveDBQuery(ctx, "op", time.Millisecond)
		r.RetentionRowsDeleted(ctx, 1)
		r.QueueDropped(ctx, 1, false)
		r.QueueDropped(ctx, 1, true)
	})
}

// Compile-time guards: *Recorder must satisfy every hook interface its callers
// expect. Renaming or changing the signature of any of these hook methods will
// break compilation here before the consumer packages — catches signature drift
// during phase-4-style refactors.
var (
	_ ingest.MetricsHook        = (*Recorder)(nil)
	_ detection.MetricsHook     = (*Recorder)(nil)
	_ retention.MetricsRecorder = (*Recorder)(nil)
)
