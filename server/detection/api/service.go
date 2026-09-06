package api

import (
	"context"
	"net/http"
	"time"
)

// Service is the operator-facing surface of the detection bounded
// context. Consumed by:
//   - response/internal/service via the Heartbeat closure (cmd/main
//     wires response.Heartbeat = detectionCtx.Service().RecordHostSeen);
//   - cmd/main metrics adapter (CountOfflineHosts, CountUnprocessed);
//   - the operator HTTP handlers inside detection/internal/operator.
//
// The agent-facing ingest path does NOT go through this Service; the
// dedicated IngestHandler (returned by IngestHandler()) gets mounted
// under endpoint.HostToken middleware in cmd/main, separate from the
// operator's session-gated mount.
type Service interface {
	// Operator reads.
	ListHosts(ctx context.Context) ([]HostSummary, error)
	// BuildTree returns the per-host process forest for the window, plus the metadata describing what the limit left out (issue
	// #423). Unless flatten is set, repeated identical-path leaf siblings are collapsed into aggregated `×N` nodes (issue #416);
	// flatten returns the raw forest. pinnedID (0 = none) keeps that one process a first-class node, never folded into an aggregate,
	// so the alert view can always locate the alerted process by its real id.
	BuildTree(ctx context.Context, hostID string, tr TimeRange, limit int, flatten bool, pinnedID int64) (ProcessTreeResult, error)
	// GetProcessDetail returns one process generation with its flows and re-exec chain. pidVersion is optional: when set it names the
	// exact generation, which is the only way to address any but the newest member of a re-exec chain (all of whose generations share
	// one fork_time_ns, so the as-of read cannot separate them). nil keeps the as-of resolution the tree and timeline pass.
	GetProcessDetail(ctx context.Context, hostID string, pid int, atTimeNs int64, pidVersion *uint32) (*ProcessDetail, error)
	ListAlerts(ctx context.Context, filter AlertFilter) ([]Alert, error)
	GetAlert(ctx context.Context, id int64) (Alert, []string, error) // alert + correlated event IDs
	// GetAlertEvidence returns the self-contained triggering-event envelopes captured for an alert at creation time (ADR-0015), so the
	// detail view resolves them even after the raw events age out of the event store. Best-effort: an alert may carry fewer payloads
	// than event IDs (alerts created before capture landed, or events already aged out at creation).
	GetAlertEvidence(ctx context.Context, id int64) ([]Event, error)
	UpdateAlertStatus(ctx context.Context, id int64, status AlertStatus, actorID string) (Alert, error)

	// RecordHostSeen advances hosts.last_seen_ns. Called by response
	// on every /api/commands poll; replaces store.UpdateHostLastSeen.
	RecordHostSeen(ctx context.Context, hostID string, at time.Time) error

	// CountOfflineHosts counts hosts whose last_seen_ns is older than
	// the threshold. Used by the OTel offline-hosts gauge.
	CountOfflineHosts(ctx context.Context, threshold time.Duration) (int, error)

	// CountUnprocessed counts events still waiting to be processed or in flight (queue states pending and claimed). Used by the OTel
	// unprocessed-events gauge so SOC dashboards can alert on stuck-processor fleets. Events SET ASIDE after repeated failure are
	// excluded: they are not waiting for anything, so counting them would hold the gauge up by a number that never drains (#836).
	CountUnprocessed(ctx context.Context) (int64, error)

	// IngestHandler returns the POST /api/events handler. Returned as an http.Handler rather than registered via a separate route method
	// so the cmd/main split between fleet-edr-server and fleet-edr-ingest can mount the same handler under different middleware chains.
	IngestHandler() http.Handler
}

// GraphReader is the narrow read surface rules consume during
// evaluation. *detection/internal/mysql.Store satisfies this
// interface directly so rule.Evaluate gets non-allocating method
// dispatch.
//
// The canonical definition lives here; rules/internal/catalog imports
// it directly via detection.api.
type GraphReader interface {
	// GetProcessByPID returns the generation of (host, pid) whose IMAGE was running at atTimeNs.
	//
	// The lifetime bracket selects the candidates (fork_time_ns <= atTimeNs, and either no exit or an exit at or after it); which
	// candidate is returned is decided by the image's own start instant, not by the fork (issue #799). Every generation of a
	// re-exec chain carries the same fork time, so ordering on the fork returns whichever generation was recorded last, which for
	// a parent asked about at its child's fork is an image that had not run yet.
	//
	// A generation between its fork and its first exec is still returned. Its image start lies in the future, and excluding it
	// would answer "no such process" for a parent that forked a child before executing anything itself.
	GetProcessByPID(ctx context.Context, hostID string, pid int, atTimeNs int64) (*Process, error)

	// GetProcessByPIDVersion returns the process generation matching the exact (host, pid, pidversion) identity at the event time
	// atNs, or nil when none matches. The kernel PID generation pins the lifetime, so the lookup is immune to PID reuse without
	// clock-drift padding. execve increments the generation, so each generation of a same-PID re-exec chain has its own pidversion and
	// the identity normally matches one row; it can still match several for rows written before that was fixed, and atNs then selects
	// the one that was the running image at the event time. A single identity match is returned regardless of atNs (identity beats
	// clock skew). Correlation rules prefer this when a flow event carries a pidversion and fall back to GetProcessByPID otherwise
	// (issue #403).
	GetProcessByPIDVersion(ctx context.Context, hostID string, pid int, pidversion uint32, atNs int64) (*Process, error)

	// GetChildProcesses returns all rows whose ppid matches the given
	// parent PID and whose fork_time_ns falls inside the time range.
	GetChildProcesses(ctx context.Context, hostID string, ppid int, tr TimeRange) ([]Process, error)

	// GetExecChain walks PreviousExecID backwards from the given row to its chain root. Returns at least one element (the input row) and
	// at most the chain length.
	GetExecChain(ctx context.Context, current Process) ([]Process, error)

	// GetNetworkEventsForProcess returns the network_connect and dns_query events attributed to (hostID, pid), filtered to the
	// ingested-time range tr and ordered by timestamp_ns. Used by cross-stream correlation rules (e.g. dns_c2_beacon) to join a
	// process's DNS resolutions with its outbound connections. Pass a wide tr to retrieve all of a pid's network/DNS events; the
	// caller bounds the correlation in-memory on timestamp_ns (network_connect and dns_query share the network-extension clock).
	GetNetworkEventsForProcess(ctx context.Context, hostID string, pid int, tr TimeRange) ([]Event, error)

	// GetHostEventsByType returns one host's events of a single type whose EVENT time falls inside tr, oldest first. Used by rules
	// whose signal is the RELATION between two events from one producer rather than a single event: sensor_tamper asks whether a
	// stopped capture provider came back within a few seconds, which is what separates a routine upgrade cutover from somebody
	// switching the sensor off (issue #684).
	//
	// Event time rather than ingest time: both events come from the same agent on the same host, so they share a clock, and the
	// gap between them is the thing being measured. The window a caller passes must be narrow; this is a correlation read, not a
	// history scan.
	GetHostEventsByType(ctx context.Context, hostID, eventType string, tr TimeRange) ([]Event, error)
}

// MetricsRecorder is the optional OTel hook the engine + intake + pipeline goroutines write to. Nil-safe: cmd/main wires the
// metrics.Recorder; tests pass nil.
type MetricsRecorder interface {
	EventsIngested(ctx context.Context, hostID string, n int)
	// EventsSetAside counts events the queue withdrew from processing after a batch failed repeatedly. Per host, because the
	// question is which host lost something (issue #836). WHAT it lost depends on the stage the withdrawal happened at, which
	// the accompanying log line carries on a consequence attribute: at the detection stage an intact graph with detection
	// unfinished, so alerts those events would have raised may be missing, and at the graph-building stage a POSSIBLE gap in that
	// graph, since an earlier attempt may have folded the batch before a later one failed.
	EventsSetAside(ctx context.Context, hostID string, n int64)
	// EventsHeartbeatDropped is called per-batch by the ingest handler with the number of snapshot_heartbeat events that were
	// processed for their freshness side effect and then dropped instead of persisted as retained event rows (issue #408).
	EventsHeartbeatDropped(ctx context.Context, hostID string, n int)
	AlertCreated(ctx context.Context, ruleID, severity string)
	// MonitorMatched is called with the number of matches a rule made in monitor mode, so no alert was persisted. It is the
	// counted form of what used to be only a log line, and it exists because issue #764 made monitor the default for most of the
	// catalog: a per-match log entry was reasonable when monitor was a state an operator deliberately set on one noisy rule, and
	// is not when sixty-six rules match commonplace commands on every host. The counter is also what an operator needs in order to
	// decide whether promoting a rule is worth it.
	//
	// It takes a count rather than being called per match because the caller aggregates a whole batch before recording it, and it
	// does that because of WHEN it records: on the transition that ends the batch's life, not while evaluating. A nacked batch is
	// replayed whole, so a counter incremented during evaluation counts a retried batch twice.
	//
	// Two transitions end a batch. Usually the acknowledgement, after which a replayed batch is counted once. The other is the
	// batch being withdrawn from processing for good once its retry bounds are passed: there is no later attempt to count it, so
	// the withdrawn attempt's matches are recorded then instead (#843). Recorded only when the WHOLE batch was withdrawn, since a
	// partial withdrawal leaves rows that are re-claimed and evaluated again.
	//
	// Five inaccuracies remain and a consumer has to know all of them, because every one of them loses counts and none inflates.
	//
	// A crash between the transition and the record loses those counts, and so does a failure of the durable write, which is
	// logged and dropped rather than allowed to fail a batch that is already finished with the queue.
	//
	// Which sink is left ahead depends on WHERE in that window it happens, and an earlier version of this comment got it wrong by
	// claiming this counter always survives. The increment happens after the queue transition and before the durable write, so a
	// crash before the increment loses both; only a crash after it, or a failure of the write itself, leaves this counter ahead.
	//
	// A batch withdrawn on an attempt that had not evaluated it records nothing: that attempt resolved no matches, and an earlier
	// attempt's were discarded when it was retried rather than carried forward (#893).
	//
	// A batch only PARTLY withdrawn drops the whole attempt's matches. The survivors are evaluated again and counted then, but
	// whatever the withdrawn events alone had matched has no later attempt to produce it. Recording the survivors' share instead
	// would need this figure to say which event each match came from, and it is aggregated per rule and host for the batch.
	//
	// A withdrawal reported to an attempt that no longer owns the events loses them from both sides. An attempt whose processing
	// outran its claim lease can withdraw rows a replacement has since claimed; the count it gets back describes its own view, so
	// it can fall short of that attempt's batch and be rejected, while the replacement's later nack reports nothing because the
	// rows are already withdrawn. That needs the queue's nack to be conditional on the claim it was issued for, as its ack already
	// is since #817. Tracked as #840.
	//
	// Losing counts is the direction that carries risk rather than the one that avoids it: a rule that looks quieter than it is
	// gets promoted, and promoting a noisy rule is the outcome monitor mode exists to prevent. It is accepted only because every
	// alternative here over-counts systematically rather than losing rarely.
	//
	// A third once stood here and is gone: an evaluation outliving its claim lease could be re-offered while the first was still
	// running, and Ack ignored claim ownership so both attempts recorded. Issue #817 made Ack conditional on still holding the
	// claim and the caller skips this write when it has lost.
	//
	// Most importantly this counts MATCHES, not would-be alerts. AlertCreated fires only for a newly INSERTED alert, and alerts
	// deduplicate on (host, rule, subject) permanently, so a rule that keeps matching one subject increments this series every
	// time and would have raised exactly one alert.
	//
	// That biases it UPWARD against what promotion produces, and the losses above bias it DOWNWARD, so it is an approximation
	// rather than a bound in either direction. Calling it an upper bound, as an earlier version of this comment did, contradicts
	// the losses documented two paragraphs up: a series that can drop counts cannot promise to be above anything. The upward bias
	// is the systematic one and the downward bias is the rare one, which is worth knowing when reading a number, but it is not a
	// guarantee to design against.
	MonitorMatched(ctx context.Context, ruleID, severity string, n int)
	// ProcessesTTLReconciled is called by the pipeline's
	// stale-process janitor on every reconciliation pass.
	ProcessesTTLReconciled(ctx context.Context, n int64)
	// ProcessRetentionRowsDeleted is called by the pipeline's retention runner on every pass with the count of completed process rows
	// pruned past the retention window. (Raw events left MySQL for ClickHouse native TTL in ADR-0015, so there is no event-row counter.)
	ProcessRetentionRowsDeleted(ctx context.Context, n int64)
	// QueueRowsPruned is called by the pipeline's queue-prune sweep on every pass with the number of acked rows removed from the event
	// work queue (the visibility EventLog), so operators can watch the sweep keep pace with ingest (ADR-0015).
	QueueRowsPruned(ctx context.Context, n int64)
	// DetectionMaterializationRetry is called by the processor each time rule evaluation defers a batch because an event's subject or
	// flow process was not materialized yet (a transient ordering race; issue #631). It counts the miss condition itself, not the nack
	// that follows: a deferred batch is always retried (an immediate nack, or a claim-lease-expiry re-offer if that nack fails), so the
	// count is taken at detection and does not depend on the nack succeeding. It is the bounded, observable replacement for
	// warn-logging every retry: the processor logs the retry at DEBUG and increments this counter, so a sustained materialization-miss
	// backlog stays detectable without flooding the logs or the OTLP export.
	DetectionMaterializationRetry(ctx context.Context)
	// RuleEvaluationSkipped is called ONCE, when a rule exceeds its evaluation budget often enough that this replica stops
	// evaluating it (issue #767). Not per skipped batch: the condition is a transition, and counting it per batch afterwards
	// would report a rule that costs nothing as the busiest thing in the fleet.
	//
	// A skipped rule raises no alerts, which looks exactly like a rule that matches nothing, so this counter is the only thing
	// that separates the two. Per rule, because the answer an operator needs is which rule to fix.
	RuleEvaluationSkipped(ctx context.Context, ruleID string)
	// RuleEvaluationDuration is called once per rule per batch with how long that rule's evaluation took, and is where "which
	// rule is slow" is properly answered (issue #837).
	//
	// A histogram rather than the durable per-rule table alone, because the two answer different questions and only one of them
	// belongs on the drain path. The table exists so a noisy rule is identifiable from the UI without querying a metrics
	// backend, which is #774's acceptance criterion, and it now writes on a periodic flush. This gives real percentiles, at the
	// cost of an in-process aggregation the OTel SDK exports on its own interval, which is the standard mechanism for hot-path
	// telemetry and what the per-batch write bypassed.
	//
	// Cardinality is rule count times buckets: bounded and low-thousands with today's corpus, and worth watching as it grows.
	RuleEvaluationDuration(ctx context.Context, ruleID string, d time.Duration)
}
