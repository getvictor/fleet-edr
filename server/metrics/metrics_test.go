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

	detectionapi "github.com/fleetdm/edr/server/detection/api"
)

// newTestRecorder builds a Recorder backed by a ManualReader so tests can collect metrics synchronously rather than racing a periodic
// reader. Returns both the Recorder and a snapshot function.
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

// findMetricData walks rm and returns the first metric named `name` whose Data is
// of type T. Returns the zero value of T and false if no match.
func findMetricData[T any](rm metricdata.ResourceMetrics, name string) (T, bool) {
	var zero T
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			if data, ok := m.Data.(T); ok {
				return data, true
			}
		}
	}
	return zero, false
}

// findSum extracts a Sum[int64] data point for the given metric name + required
// attribute subset. Returns -1 if nothing matches so assertion failures read naturally.
func findSum(t *testing.T, rm metricdata.ResourceMetrics, name string, want map[string]any) int64 {
	t.Helper()
	sum, ok := findMetricData[metricdata.Sum[int64]](rm, name)
	if !ok {
		return -1
	}
	for _, dp := range sum.DataPoints {
		if attrsMatch(dp.Attributes.ToSlice(), want) {
			return dp.Value
		}
	}
	return -1
}

func findGauge(t *testing.T, rm metricdata.ResourceMetrics, name string) int64 {
	t.Helper()
	g, ok := findMetricData[metricdata.Gauge[int64]](rm, name)
	if !ok || len(g.DataPoints) == 0 {
		return -1
	}
	return g.DataPoints[0].Value
}

func findHistogramCount(t *testing.T, rm metricdata.ResourceMetrics, name string, want map[string]any) uint64 {
	t.Helper()
	h, ok := findMetricData[metricdata.Histogram[float64]](rm, name)
	if !ok {
		return 0
	}
	for _, dp := range h.DataPoints {
		if attrsMatch(dp.Attributes.ToSlice(), want) {
			return dp.Count
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

// spec:observability-instrumentation/stable-counter-names/ingested-events-are-counted-by-host
// spec:observability-instrumentation/stable-counter-names/alerts-are-counted-only-on-creation
// spec:observability-instrumentation/stable-counter-names/already-delivered-queue-trim-is-distinguishable-from-data-loss
// spec:observability-instrumentation/observable-host-fleet-gauges/gauges-evaluate-on-the-reader-cadence
//
// Four scenarios share this test because they describe the same observation from different angles: every
// counter / gauge that the spec names is fired once by Recorder methods and then collected via the
// ManualReader. The asserts pin (a) host_id attr on edr.events.ingested, (b) rule_id+severity attrs on
// edr.alerts.created, (c) the lossy=true vs lossy=false distinction on edr.agent.queue.dropped
// (server-side mirror of the agent-side TestRecorder_QueueDropped), and (d) that collect() drives the
// gauge callbacks and observes their values (stubGauges feeds enrolled=3, offline=1).
//
// spec:observability-instrumentation/aggregate-latency-and-alerting-derive-from-metrics-not-sampled-spans/event-counts-are-unaffected-by-the-sample-ratio
// The recorder counts every ingested event with no reference to the trace sampler, so counts are authoritative regardless of the
// trace sample ratio in effect.
func TestRecorder_RecordsCounters(t *testing.T) {
	t.Parallel()
	r, collect := newTestRecorder(t, stubGauges{enrolled: 3, offline: 1}, Options{})
	ctx := context.Background()

	r.EventsIngested(ctx, "host-a", 5)
	r.EventsIngested(ctx, "host-b", 2)
	r.AlertCreated(ctx, "dyld_insert", "high")
	r.RetentionRowsDeleted(ctx, 42)
	r.ProcessRetentionRowsDeleted(ctx, 7)
	r.QueueDropped(ctx, 3, false)
	r.QueueDropped(ctx, 5, true)

	rm := collect()

	assert.Equal(t, int64(5), findSum(t, rm, "edr.events.ingested", map[string]any{"host_id": "host-a"}))
	assert.Equal(t, int64(2), findSum(t, rm, "edr.events.ingested", map[string]any{"host_id": "host-b"}))
	assert.Equal(t, int64(1), findSum(t, rm, "edr.alerts.created", map[string]any{"rule_id": "dyld_insert", "severity": "high"}))
	assert.Equal(t, int64(42), findSum(t, rm, "edr.retention.rows_deleted", nil))
	assert.Equal(t, int64(7), findSum(t, rm, "edr.retention.processes.rows_deleted", nil))
	assert.Equal(t, int64(3), findSum(t, rm, "edr.agent.queue.dropped", map[string]any{"lossy": false}))
	assert.Equal(t, int64(5), findSum(t, rm, "edr.agent.queue.dropped", map[string]any{"lossy": true}))
	assert.Equal(t, int64(3), findGauge(t, rm, "edr.enrolled.hosts"))
	assert.Equal(t, int64(1), findGauge(t, rm, "edr.offline.hosts"))
}

func TestRecorder_NilGaugesSkipsGauges(t *testing.T) {
	t.Parallel()
	_, collect := newTestRecorder(t, nil, Options{})
	rm := collect()
	assert.Equal(t, int64(-1), findGauge(t, rm, "edr.enrolled.hosts"))
	assert.Equal(t, int64(-1), findGauge(t, rm, "edr.offline.hosts"))
}

func TestGauges_UseConfiguredThreshold(t *testing.T) {
	t.Parallel()
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

// spec:observability-instrumentation/instrumentation-is-safe-on-a-nil-receiver/call-sites-do-not-guard-the-recorder
//
// Methods short-circuit on nil so call sites can tolerate "no metrics configured" without defensive
// checks. Companion agent-side coverage in TestNilRecorder_QueueDropped_Safe.
func TestNilRecorder_AllMethodsSafe(t *testing.T) {
	t.Parallel()
	// Methods short-circuit on nil so call sites can tolerate "no metrics configured"
	// without defensive checks. Lock that property in as a test.
	var r *Recorder
	ctx := context.Background()
	assert.NotPanics(t, func() {
		r.EventsIngested(ctx, "h", 1)
		r.AlertCreated(ctx, "r", "s")
		r.RetentionRowsDeleted(ctx, 1)
		r.ProcessRetentionRowsDeleted(ctx, 1)
		r.QueueDropped(ctx, 1, false)
		r.QueueDropped(ctx, 1, true)
	})
}

// Compile-time guards: *Recorder must satisfy every hook interface its callers
// expect. Renaming or changing the signature of any of these hook methods will
// break compilation here before the consumer packages: catches signature drift
// during refactors.
//
// detection/api.MetricsRecorder is the consolidated hook surface; the retention
// runner gets its rows-deleted hook through the same interface
// (RetentionRowsDeleted method). The guard asserts the consolidated surface.
var (
	_ detectionapi.MetricsRecorder = (*Recorder)(nil)
)

// spec:observability-instrumentation/observable-host-fleet-gauges/a-failing-gauge-callback-is-contained
//
// A GaugeSource that returns an error from EnrolledHosts MUST NOT take down the whole collection cycle.
// The contract: the failed gauge observes no value, but the other gauges and counters still report.
// Pins that contract by wiring a failingGauges source whose EnrolledHosts returns an error while
// OfflineHosts succeeds, then asserting (a) collect() returns without error, (b) the failed gauge has
// no datapoint, and (c) the offline gauge reports its value.
func TestRecorder_FailingGaugeCallbackIsContained(t *testing.T) {
	t.Parallel()
	gauges := failingGauges{offline: 7}
	_, collect := newTestRecorder(t, gauges, Options{})

	// collect itself must not panic or fail even though one gauge callback errors. The test helper would call require.NoError on
	// the Collect; if the implementation propagated the error here we'd see a failure at that line.
	rm := collect()

	assert.Equal(t, int64(-1), findGauge(t, rm, "edr.enrolled.hosts"),
		"failed gauge callback must observe no value this cycle")
	assert.Equal(t, int64(7), findGauge(t, rm, "edr.offline.hosts"),
		"the rest of the gauge collection must still succeed")
}

// failingGauges has EnrolledHosts return an error to exercise the per-gauge containment branch; the
// OfflineHosts callback still succeeds so the test can also assert the rest of the cycle proceeds.
type failingGauges struct {
	offline int
}

func (g failingGauges) EnrolledHosts(context.Context) (int, error) {
	return 0, assert.AnError
}

func (g failingGauges) OfflineHosts(context.Context, time.Duration) (int, error) {
	return g.offline, nil
}

// spec:observability-instrumentation/http-server-request-duration/inbound-requests-are-timed-by-route-method-and-status
// spec:observability-instrumentation/aggregate-latency-and-alerting-derive-from-metrics-not-sampled-spans/latency-percentiles-are-unaffected-by-the-sample-ratio
//
// The duration histogram records every request with no reference to the trace sampler, so latency percentiles reflect the full
// request population regardless of the trace sample ratio.
//
// ObserveHTTPRequest records on the OTel-semantic-convention http.server.request.duration histogram. The test pins: (a) two
// requests sharing method+route+status collapse into one series with count 2, (b) a distinct status is its own series, and
// (c) the cardinality guards fire: an unknown method collapses to "_OTHER" and an empty route to "unmatched".
func TestObserveHTTPRequest(t *testing.T) {
	t.Parallel()
	r, collect := newTestRecorder(t, nil, Options{})
	ctx := context.Background()
	r.ObserveHTTPRequest(ctx, "POST", "/api/events", 200, 50*time.Millisecond)
	r.ObserveHTTPRequest(ctx, "POST", "/api/events", 200, 70*time.Millisecond)
	r.ObserveHTTPRequest(ctx, "GET", "/api/hosts/{host_id}/tree", 500, 5*time.Millisecond)
	r.ObserveHTTPRequest(ctx, "BREW", "", 418, time.Millisecond)

	rm := collect()
	const name = "http.server.request.duration"
	assert.Equal(t, uint64(2), findHistogramCount(t, rm, name, map[string]any{
		"http.request.method": "POST", "http.route": "/api/events", "http.response.status_code": int64(200),
	}), "two POST /api/events 200s share one series")
	assert.Equal(t, uint64(1), findHistogramCount(t, rm, name, map[string]any{
		"http.request.method": "GET", "http.route": "/api/hosts/{host_id}/tree", "http.response.status_code": int64(500),
	}))
	assert.Equal(t, uint64(1), findHistogramCount(t, rm, name, map[string]any{
		"http.request.method": "_OTHER", "http.route": "unmatched", "http.response.status_code": int64(418),
	}), "unknown method -> _OTHER and empty route -> unmatched (cardinality guard)")
}
