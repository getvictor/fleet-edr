// Package metrics owns the OTel metric surface. Every counter, histogram, and
// observable gauge is registered against the global OTel meter so values flow through
// the same OTLP pipeline `observability.Init` already configured. There is no Prometheus
// scrape endpoint and no secondary registry: SigNoz (or any OTLP receiver) sees these
// alongside traces and logs.
//
// Call sites instrument via typed methods (EventsIngested, AlertCreated, etc.) rather
// than touching the meter directly, which keeps metric names + attribute keys in one
// place and prevents surprise label values at call sites.
package metrics

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	meterName = "github.com/fleetdm/edr/server/metrics"

	// defaultOfflineThreshold is the gauge cutoff used when Options.OfflineThreshold is zero. Mirrored as the UI offline cutoff so SigNoz
	// numbers match what operators see on the host page.
	defaultOfflineThreshold = 5 * time.Minute
)

// httpDurationBuckets is the OTel HTTP semantic-convention default bucket set for http.server.request.duration, in seconds.
// Using the conventional boundaries keeps p50/p95/p99 readings comparable with any other OTel-instrumented service and with
// SigNoz's built-in expectations for this metric.
var httpDurationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}

// knownHTTPMethods bounds the http.request.method label. An unrecognized method (a scanner sending garbage verbs) collapses to
// "_OTHER" per the OTel HTTP semantic conventions, so a flood of junk methods cannot inflate the metric's cardinality.
var knownHTTPMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true,
	http.MethodDelete: true, http.MethodConnect: true, http.MethodOptions: true, http.MethodTrace: true,
}

// GaugeSource is the read-only contract used by the observable gauges. The OTel reader invokes the callbacks on its collection
// cadence; the callback issues a live DB query each time. Interface not concrete struct so tests can swap in fakes without pulling in
// a MySQL dependency.
type GaugeSource interface {
	EnrolledHosts(ctx context.Context) (int, error)
	OfflineHosts(ctx context.Context, threshold time.Duration) (int, error)
}

// Recorder is the write surface instrumentation code uses. Every method is safe to call from any goroutine and safe on a nil receiver
// (methods short-circuit) so call sites don't need defensive `if r != nil` blocks.
type Recorder struct {
	eventsIngested       metric.Int64Counter
	alertsCreated        metric.Int64Counter
	retentionRowsDeleted metric.Int64Counter
	processesReconciled  metric.Int64Counter
	queueDropped         metric.Int64Counter
	httpRequestDuration  metric.Float64Histogram
	// observable gauges retained only so the GC can't collect them; the callbacks run
	// against the global meter provider.
	enrolledGauge metric.Int64ObservableGauge
	offlineGauge  metric.Int64ObservableGauge
}

// Options tune the Recorder. All fields are optional.
type Options struct {
	// OfflineThreshold is the "how old is too old" for the offline-hosts gauge. Zero uses 5 minutes to match the UI's threshold so what
	// operators see in SigNoz matches what they see on the host page.
	OfflineThreshold time.Duration
	// Meter, optional. Defaults to otel.Meter(meterName). Tests pass a meter backed by
	// a ManualReader so they can collect metrics synchronously.
	Meter metric.Meter
}

// New builds a Recorder and registers every metric against the OTel meter. When OTEL_EXPORTER_OTLP_ENDPOINT is unset
// `observability.Init` leaves the SDK in its no-op state; in that case every `Add`/`Record`/`Observe` call is a no-op and this
// constructor still succeeds, so unit tests and offline dev don't need a collector. Passing nil for `gauges` skips observable gauge
// registration (unit tests).
func New(gauges GaugeSource, opts Options) *Recorder {
	if opts.OfflineThreshold <= 0 {
		opts.OfflineThreshold = defaultOfflineThreshold
	}
	meter := opts.Meter
	if meter == nil {
		meter = otel.Meter(meterName)
	}

	r := &Recorder{}
	// Counters and histograms are synchronous instruments; creation is cheap and errors only surface for truly pathological inputs
	// (duplicate name with conflicting type, etc.). If any instrument fails to register we leave the field nil and let the nil-safe method
	// paths below no-op, so a Recorder from New is always usable.
	r.eventsIngested, _ = meter.Int64Counter(
		"edr.events.ingested",
		metric.WithDescription("Events accepted by POST /api/events, by host_id."),
		metric.WithUnit("{event}"),
	)
	r.alertsCreated, _ = meter.Int64Counter(
		"edr.alerts.created",
		metric.WithDescription("Detection alerts created (dedup-skipped alerts not counted), by rule + severity."),
		metric.WithUnit("{alert}"),
	)
	r.retentionRowsDeleted, _ = meter.Int64Counter(
		"edr.retention.rows_deleted",
		metric.WithDescription("Total rows deleted by the event retention job since server start."),
		metric.WithUnit("{row}"),
	)
	r.processesReconciled, _ = meter.Int64Counter(
		"edr.processes.ttl_reconciled",
		metric.WithDescription("Processes whose exit_time_ns was synthesized by the freshness-TTL reconciler (missed-exit-event fallback)."),
		metric.WithUnit("{process}"),
	)
	r.queueDropped, _ = meter.Int64Counter(
		"edr.agent.queue.dropped",
		metric.WithDescription("Events dropped by agent queue cap. Attribute `lossy=true` means data loss; `lossy=false` means already-delivered rows trimmed for space."),
		metric.WithUnit("{event}"),
	)
	// Deliberately the OTel HTTP semantic-convention name (not the edr.* prefix the metrics above use): tooling, including SigNoz,
	// recognizes http.server.request.duration and its standard attributes. The histogram's count gives request rate, a status-code
	// filter gives the error rate, and the buckets give latency quantiles, so this one instrument covers the full RED picture.
	r.httpRequestDuration, _ = meter.Float64Histogram(
		"http.server.request.duration",
		metric.WithDescription("Duration of inbound HTTP requests, by route + method + status. The per-request access log only fires for 4xx/5xx/slow; this metric is the volume + latency signal."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(httpDurationBuckets...),
	)

	if gauges != nil {
		threshold := opts.OfflineThreshold
		r.enrolledGauge, _ = meter.Int64ObservableGauge(
			"edr.enrolled.hosts",
			metric.WithDescription("Number of non-revoked host enrollments, counted each collection."),
			metric.WithInt64Callback(func(ctx context.Context, obs metric.Int64Observer) error {
				gaugeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				n, err := gauges.EnrolledHosts(gaugeCtx)
				if err != nil {
					// A slow or failing DB must not drop every collection cycle; log so an
					// operator staring at a flat/absent `edr.enrolled.hosts` has a breadcrumb.
					slog.Default().WarnContext(ctx, "edr.enrolled.hosts gauge callback failed", "err", err)
					return nil
				}
				obs.Observe(int64(n))
				return nil
			}),
		)
		r.offlineGauge, _ = meter.Int64ObservableGauge(
			"edr.offline.hosts",
			metric.WithDescription("Hosts whose last_seen_ns is older than the offline threshold."),
			metric.WithInt64Callback(func(ctx context.Context, obs metric.Int64Observer) error {
				gaugeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				n, err := gauges.OfflineHosts(gaugeCtx, threshold)
				if err != nil {
					slog.Default().WarnContext(ctx, "edr.offline.hosts gauge callback failed",
						"err", err, "threshold", threshold)
					return nil
				}
				obs.Observe(int64(n))
				return nil
			}),
		)
	}
	return r
}

// EventsIngested increments the ingest counter by n for a host. Called per-batch by
// the ingest handler after a successful InsertEvents.
func (r *Recorder) EventsIngested(ctx context.Context, hostID string, n int) {
	if r == nil || r.eventsIngested == nil || n <= 0 {
		return
	}
	r.eventsIngested.Add(ctx, int64(n), metric.WithAttributes(attribute.String("host_id", hostID)))
}

// AlertCreated increments the alert counter. Called by the detection engine ONLY on
// `created=true` so the rate reflects new alerts, not evaluator noise.
func (r *Recorder) AlertCreated(ctx context.Context, ruleID, severity string) {
	if r == nil || r.alertsCreated == nil {
		return
	}
	r.alertsCreated.Add(ctx, 1, metric.WithAttributes(
		attribute.String("rule_id", ruleID),
		attribute.String("severity", severity),
	))
}

// ObserveHTTPRequest records one inbound HTTP request's latency on the http.server.request.duration histogram. `route` must be
// the matched route TEMPLATE (e.g. "/api/hosts/{host_id}/tree"), never the raw path: a raw path carrying ids would make every
// host its own time series. The caller passes "unmatched" for requests that hit no route. `method` is normalized against the
// known-verb set so a garbage method collapses to "_OTHER". Status code is bounded by construction.
func (r *Recorder) ObserveHTTPRequest(ctx context.Context, method, route string, statusCode int, d time.Duration) {
	if r == nil || r.httpRequestDuration == nil {
		return
	}
	if !knownHTTPMethods[method] {
		method = "_OTHER"
	}
	if route == "" {
		route = "unmatched"
	}
	r.httpRequestDuration.Record(ctx, d.Seconds(), metric.WithAttributes(
		attribute.String("http.request.method", method),
		attribute.String("http.route", route),
		attribute.Int("http.response.status_code", statusCode),
	))
}

// RetentionRowsDeleted satisfies retention.MetricsRecorder.
func (r *Recorder) RetentionRowsDeleted(ctx context.Context, n int64) {
	if r == nil || r.retentionRowsDeleted == nil || n <= 0 {
		return
	}
	r.retentionRowsDeleted.Add(ctx, n)
}

// ProcessesTTLReconciled satisfies processttl.MetricsRecorder. A non-zero rate of this indicates the fleet is losing exit events
// (agent drops, kernel back-pressure, queue pruning): investigate the affected hosts.
func (r *Recorder) ProcessesTTLReconciled(ctx context.Context, n int64) {
	if r == nil || r.processesReconciled == nil || n <= 0 {
		return
	}
	r.processesReconciled.Add(ctx, n)
}

// QueueDropped satisfies queue.MetricsRecorder. A single counter with a `lossy` attribute lets operators alert on lossy drops (real
// data loss) independently of lossless drops (already-delivered events pruned for space) without maintaining two metric families.
func (r *Recorder) QueueDropped(ctx context.Context, n int64, lossy bool) {
	if r == nil || r.queueDropped == nil || n <= 0 {
		return
	}
	r.queueDropped.Add(ctx, n, metric.WithAttributes(attribute.Bool("lossy", lossy)))
}
