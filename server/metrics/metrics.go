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

	// unitEvent is the OTel unit annotation (UCUM "{event}") shared by the event-counting instruments.
	unitEvent = "{event}"
)

// httpDurationBuckets is the OTel HTTP semantic-convention default bucket set for http.server.request.duration, in seconds.
// Using the conventional boundaries keeps p50/p95/p99 readings comparable with any other OTel-instrumented service and with
// SigNoz's built-in expectations for this metric.
// ruleEvalDurationBuckets covers the measured range of a rule's evaluation: the mean on the dev server was 0.094ms and the
// slowest rule doing legitimate work 17.8ms, so the interesting span is tens of microseconds to tens of milliseconds. The top
// boundaries sit above the 100ms evaluation budget (issue #767) so a rule approaching its skip is visible here first, which is
// while an operator can still act on it.
var ruleEvalDurationBuckets = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1}

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
	eventsIngested                  metric.Int64Counter
	heartbeatsDropped               metric.Int64Counter
	alertsCreated                   metric.Int64Counter
	monitorMatches                  metric.Int64Counter
	processRetentionRowsDeleted     metric.Int64Counter
	queueRowsPruned                 metric.Int64Counter
	processesReconciled             metric.Int64Counter
	queueDropped                    metric.Int64Counter
	detectionMaterializationRetries metric.Int64Counter
	eventsSetAside                  metric.Int64Counter
	ruleEvalSkipped                 metric.Int64Counter
	httpRequestDuration             metric.Float64Histogram
	ruleEvaluationDuration          metric.Float64Histogram
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
		metric.WithUnit(unitEvent),
	)
	r.heartbeatsDropped, _ = meter.Int64Counter(
		"edr.ingest.heartbeats_dropped",
		metric.WithDescription("snapshot_heartbeat events accepted but not persisted as event rows (their freshness side effect is applied at ingest), by host_id."),
		metric.WithUnit(unitEvent),
	)
	r.alertsCreated, _ = meter.Int64Counter(
		"edr.alerts.created",
		metric.WithDescription("Detection alerts created (dedup-skipped alerts not counted), by rule + severity."),
		metric.WithUnit("{alert}"),
	)
	r.monitorMatches, _ = meter.Int64Counter(
		"edr.detection.monitor_matches",
		metric.WithDescription("Rule matches suppressed because the resolved mode was monitor, by rule + severity. "+
			"Counts MATCHES, not would-be alerts: edr.alerts.created counts newly created alerts, which deduplicate on "+
			"(host, rule, subject) forever, so a rule that keeps matching one subject raises this series repeatedly and would "+
			"raise exactly one alert. Read it as volume and reach: it is biased upward by repeated subjects and downward by the "+
			"losses below, so it is an approximation of what promotion produces rather than a bound in either direction. "+
			"Recorded once the batch is acknowledged, so a nacked and replayed batch counts once rather than once per attempt; "+
			"the residual inaccuracies are a crash between the acknowledgement and the record, which loses counts and so can "+
			"make a noisy rule look safe to promote, and an evaluation outliving its claim lease, which can let a reclaimer "+
			"count the same batch again."),
		metric.WithUnit("{match}"),
	)
	r.processRetentionRowsDeleted, _ = meter.Int64Counter(
		"edr.retention.processes.rows_deleted",
		metric.WithDescription("Total completed process rows deleted by the retention job since server start."),
		metric.WithUnit("{row}"),
	)
	r.queueRowsPruned, _ = meter.Int64Counter(
		"edr.event_queue.rows_pruned",
		metric.WithDescription("Total acked rows pruned from the event work queue since server start."),
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
		metric.WithUnit(unitEvent),
	)
	r.detectionMaterializationRetries, _ = meter.Int64Counter(
		"edr.detection.materialization_retries",
		metric.WithDescription("Detection batches re-queued because an event's subject or flow process was not materialized yet (a transient ordering race). A sustained non-zero rate means a replica is behind on graph materialization or agents are dropping fork/exec."),
		metric.WithUnit("{retry}"),
	)
	// The description stays short because it renders as dashboard metadata beside the counter, where it competes with the chart for
	// the reader's attention; the reasoning a maintainer needs lives here instead. Setting events aside is NOT data loss: ingest
	// writes the archive before the work queue and retains it on its own window (ADR-0015), so the events stay available to hunting
	// queries and alert evidence. What is given up is their contribution to the process graph and their evaluation by whichever
	// rules had not already finished when the batch failed, which for a batch withdrawn at the builder stage is all of them.
	r.eventsSetAside, _ = meter.Int64Counter(
		"edr.events.set_aside",
		metric.WithDescription("Queued events withdrawn from processing after their batch failed repeatedly (issue #836). The host in `host_id` "+
			"has a gap in its process graph. Alert on a non-zero increase, per host: the counter is cumulative, so an absolute-value "+
			"condition never clears once it fires."),
		metric.WithUnit(unitEvent),
	)
	// One increment per rule per replica when the budget is exhausted, not per skipped batch: see the interface comment on
	// RuleEvaluationSkipped. An operator reads this to find the rule to fix; a rule appearing here has stopped contributing
	// detections on that replica, which no alert-volume signal can show because the absence looks like quiet.
	r.ruleEvalSkipped, _ = meter.Int64Counter(
		"edr.detection.rule_evaluation_skipped",
		metric.WithDescription("Rules a replica stopped evaluating after they exceeded their evaluation budget repeatedly (issue #767). "+
			"The rule in `rule_id` is no longer contributing detections on that replica and needs its patterns looked at. Cleared by a "+
			"restart, so alert on an increase rather than an absolute value."),
		metric.WithUnit("{rule}"),
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

	// Buckets chosen against the measured distribution rather than the default: on the dev server the mean rule evaluation was
	// 0.094ms and the slowest doing legitimate work 17.8ms, so the interesting range is tens of microseconds to tens of
	// milliseconds. The top bucket sits above the 100ms evaluation budget (issue #767) so a rule approaching its skip is visible
	// here before it is skipped, which is the point at which an operator can still act.
	r.ruleEvaluationDuration, _ = meter.Float64Histogram(
		"edr.detection.rule_evaluation.duration",
		metric.WithDescription("Duration of one detection rule's evaluation of one event batch, by rule."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(ruleEvalDurationBuckets...),
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

// EventsSetAside increments the set-aside counter by n for a host. Called by the processor when a nack withdraws events from
// processing rather than returning them, which happens only once a batch has passed both retry bounds.
//
// Attributed per host deliberately: the question this answers is which host stopped contributing to the graph, and a fleet-wide
// total cannot answer it.
func (r *Recorder) EventsSetAside(ctx context.Context, hostID string, n int64) {
	if r == nil || r.eventsSetAside == nil || n <= 0 {
		return
	}
	r.eventsSetAside.Add(ctx, n, metric.WithAttributes(attribute.String("host_id", hostID)))
}

// RuleEvaluationDuration records how long one rule took to evaluate one batch (issue #837).
//
// This is the tier that answers "which rule is slow" with percentiles. The nil check matches the recorder's other methods: a
// Recorder built without a meter records nothing rather than panicking.
func (r *Recorder) RuleEvaluationDuration(ctx context.Context, ruleID string, d time.Duration) {
	if r == nil || r.ruleEvaluationDuration == nil {
		return
	}
	r.ruleEvaluationDuration.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("rule_id", ruleID)))
}

// RuleEvaluationSkipped records that this replica has stopped evaluating a rule for exceeding its evaluation budget (issue #767).
func (r *Recorder) RuleEvaluationSkipped(ctx context.Context, ruleID string) {
	if r == nil || r.ruleEvalSkipped == nil {
		return
	}
	r.ruleEvalSkipped.Add(ctx, 1, metric.WithAttributes(attribute.String("rule_id", ruleID)))
}

// EventsHeartbeatDropped increments the heartbeat-dropped counter by n for a host. Called per-batch by the ingest handler with the
// number of snapshot_heartbeat events accepted but not persisted as event rows (issue #408): every heartbeat in the batch, whether
// or not it produced a freshness bump (a malformed or zero-pid heartbeat is still dropped, not persisted). edr.events.ingested
// still counts the full accepted batch (heartbeats included) per the stable-counter contract; this is the not-persisted subset.
func (r *Recorder) EventsHeartbeatDropped(ctx context.Context, hostID string, n int) {
	if r == nil || r.heartbeatsDropped == nil || n <= 0 {
		return
	}
	r.heartbeatsDropped.Add(ctx, int64(n), metric.WithAttributes(attribute.String("host_id", hostID)))
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

// MonitorMatched adds n to the monitor-match counter: a rule matched n times, and its resolved mode suppressed the alerts. Same
// attribute shape as AlertCreated so the two can be compared per rule, which is exactly the comparison promoting a rule turns on.
//
// n rather than one call per match, because the caller aggregates a batch and records it only once the batch is acknowledged. See
// api.MetricsRecorder for why that timing is what makes the series survive a retry.
func (r *Recorder) MonitorMatched(ctx context.Context, ruleID, severity string, n int) {
	if r == nil || r.monitorMatches == nil || n <= 0 {
		return
	}
	r.monitorMatches.Add(ctx, int64(n), metric.WithAttributes(
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

// ProcessRetentionRowsDeleted satisfies api.MetricsRecorder. Counts completed process rows pruned past the retention window. (The
// events table left MySQL for ClickHouse native TTL in ADR-0015, so there is no longer an event-row deletion counter here.)
func (r *Recorder) ProcessRetentionRowsDeleted(ctx context.Context, n int64) {
	if r == nil || r.processRetentionRowsDeleted == nil || n <= 0 {
		return
	}
	r.processRetentionRowsDeleted.Add(ctx, n)
}

// QueueRowsPruned satisfies api.MetricsRecorder. Counts acked rows the queue-prune sweep removed from the event work queue, so a
// dashboard can compare prune throughput against ingest and catch a sweep falling behind.
func (r *Recorder) QueueRowsPruned(ctx context.Context, n int64) {
	if r == nil || r.queueRowsPruned == nil || n <= 0 {
		return
	}
	r.queueRowsPruned.Add(ctx, n)
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

// DetectionMaterializationRetry satisfies detection api.MetricsRecorder. The processor calls it once per batch whose rule evaluation
// reported a not-yet-materialized subject or flow process (issue #631). This counter is the observable signal for a sustained
// materialization-miss backlog: the processor logs each such retry at DEBUG rather than WARN, so operators alert on a sustained
// non-zero rate here instead of scraping a flood of retry log lines. Kept attribute-free to bound cardinality.
func (r *Recorder) DetectionMaterializationRetry(ctx context.Context) {
	if r == nil || r.detectionMaterializationRetries == nil {
		return
	}
	r.detectionMaterializationRetries.Add(ctx, 1)
}
