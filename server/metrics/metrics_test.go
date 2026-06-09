package metrics

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
// spec:observability-instrumentation/db-query-latency-histogram/a-store-operation-records-its-latency
// spec:observability-instrumentation/observable-host-fleet-gauges/gauges-evaluate-on-the-reader-cadence
//
// Five scenarios share this test because they describe the same observation from different angles: every
// counter / histogram / gauge that the spec names is fired once by Recorder methods and then collected
// via the ManualReader. The asserts pin (a) host_id attr on edr.events.ingested, (b) rule_id+severity
// attrs on edr.alerts.created, (c) the lossy=true vs lossy=false distinction on edr.agent.queue.dropped
// (server-side mirror of the agent-side TestRecorder_QueueDropped), (d) the op attr on the
// edr.db.query.duration histogram, and (e) that collect() drives the gauge callbacks and observes their
// values (stubGauges feeds enrolled=3, offline=1; the gauge assertions see them).
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

// spec:observability-instrumentation/instrumentation-is-safe-on-a-nil-receiver/call-sites-do-not-guard-the-recorder
//
// Methods short-circuit on nil so call sites can tolerate "no metrics configured" without defensive
// checks. Companion agent-side coverage in TestNilRecorder_QueueDropped_Safe.
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
// break compilation here before the consumer packages - catches signature drift
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

// spec:observability-instrumentation/db-query-latency-histogram/operation-names-are-bounded
//
// Walks every .go file under ../../ (the server module root) via go/ast and asserts that every literal string passed
// as the second positional argument to a `.ObserveDBQuery(` call is in BoundedDBOps(). The bounded-cardinality
// contract the spec scenario describes is what keeps the `op` attribute from inflating SigNoz's time-series space
// without limit when a contributor accidentally passes a dynamic value (host id, table row, error message). A failure
// here means either (a) a new call site needs to be added to boundedDBOps, or (b) someone passed a non-literal
// expression and the `op` attribute is no longer statically bounded - both block merge.
//
// Test files are intentionally excluded from the walk: metrics_test.go itself passes synthetic ops like "op" and
// "insert_event" to exercise the recorder, and policing those would couple test scaffolding to the production
// allowlist for no operational gain.
//
// The AST walk + violation collection is split into a helper (scanObserveDBQueryCallSites) to keep this test under
// Sonar's cognitive-complexity threshold (go:S3776).
func TestObserveDBQuery_OperationNamesAreBounded(t *testing.T) {
	t.Parallel()

	allowed := make(map[string]struct{}, len(boundedDBOps))
	for _, op := range BoundedDBOps() {
		allowed[op] = struct{}{}
	}

	// Walk from the server root only. The metrics package lives at server/metrics/, so one dot up reaches server/. Scoping to
	// server/ keeps the test from scanning unrelated packages (agent/, tools/, etc.) that don't carry ObserveDBQuery call sites
	// and would inflate the walk time + reach files that may legitimately use the literal "ObserveDBQuery" string elsewhere.
	root, err := filepath.Abs("..")
	require.NoError(t, err, "resolve server root")

	bads, walkErr := scanObserveDBQueryCallSites(root, allowed)
	require.NoError(t, walkErr)

	if len(bads) == 0 {
		return
	}
	var msg strings.Builder
	msg.WriteString("ObserveDBQuery op argument violations (BoundedDBOps in metrics.go is the canonical set):\n")
	for _, b := range bads {
		rel, _ := filepath.Rel(root, b.path)
		if b.value == "" {
			fmt.Fprintf(&msg, "  %s:%d: non-literal `op` argument - the static-analyzer cannot prove bounded cardinality\n", rel, b.line)
			continue
		}
		fmt.Fprintf(&msg, "  %s:%d: literal %q not in BoundedDBOps\n", rel, b.line, b.value)
	}
	t.Fatal(msg.String())
}

// observeDBQueryViolation records a single ObserveDBQuery call site where the `op` argument is either non-literal or outside
// the boundedDBOps allowlist. Carried as a struct rather than a string so the report formatter can distinguish the two
// failure shapes ("non-literal expression" vs "literal X not in allowlist") and point the contributor at the right fix.
type observeDBQueryViolation struct {
	path  string
	line  int
	value string // empty when the arg is a non-literal expression
}

// scanObserveDBQueryCallSites walks rootDir for .go files (skipping vendor + test files) and returns every
// ObserveDBQuery call site whose `op` argument is not in `allowed`. Split out of TestObserveDBQuery_OperationNamesAreBounded
// to keep that test under Sonar's go:S3776 cognitive-complexity threshold.
func scanObserveDBQueryCallSites(rootDir string, allowed map[string]struct{}) ([]observeDBQueryViolation, error) {
	var bads []observeDBQueryViolation
	walkErr := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", "tmp", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			// Fail with the path so a parse error in a future contributor's commit doesn't silently disable the analyzer for
			// that file. `go build` would surface the same error in CI, but this test fires earlier in the gate sequence and
			// surfaces a clearer "operation-names bound test couldn't parse X" message.
			return fmt.Errorf("parse %s: %w", path, err)
		}
		bads = appendObserveDBQueryViolations(bads, file, fset, allowed)
		return nil
	})
	return bads, walkErr
}

// appendObserveDBQueryViolations walks a single parsed file's AST and appends any ObserveDBQuery call sites whose `op` argument
// violates the bounded-cardinality contract. Extracted from scanObserveDBQueryCallSites for the same Sonar S3776 budget reason
// that drove the outer helper extraction.
func appendObserveDBQueryViolations(bads []observeDBQueryViolation, file *ast.File, fset *token.FileSet,
	allowed map[string]struct{},
) []observeDBQueryViolation {
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ObserveDBQuery" {
			return true
		}
		// Signature is (ctx, op string, d time.Duration); the op argument is positional index 1.
		if len(call.Args) < 2 {
			return true
		}
		pos := fset.Position(call.Args[1].Pos())
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			bads = append(bads, observeDBQueryViolation{path: pos.Filename, line: pos.Line})
			return true
		}
		// strconv.Unquote correctly handles both interpreted (`"foo"`) and raw (`` `foo` ``) string literals plus any
		// escape sequences in the interpreted form. A previous version of this test used strings.Trim(lit.Value, `"`)
		// which silently mis-decoded raw string literals (the backticks would survive into `value` and the allowlist
		// lookup would always fail) and any escape sequences would leak literal `\x` bytes into the comparison.
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			bads = append(bads, observeDBQueryViolation{path: pos.Filename, line: pos.Line})
			return true
		}
		if _, ok := allowed[value]; !ok {
			bads = append(bads, observeDBQueryViolation{path: pos.Filename, line: pos.Line, value: value})
		}
		return true
	})
	return bads
}
