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

	// CountUnprocessed counts events with processed != 1. Used by the OTel unprocessed-events gauge so SOC dashboards can alert on
	// stuck-processor fleets.
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
	// GetProcessByPID returns the row whose (host, pid) bracket atTimeNs (i.e. fork_time_ns <= atTimeNs <= exit_time_ns or exit_time_ns IS
	// NULL).
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
	// question is which host has a gap in its process graph (issue #836).
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
	// does that because of WHEN it records: after the batch is acknowledged, not while evaluating. A nacked batch is replayed
	// whole, so a counter incremented during evaluation counts a retried batch twice. Called after the acknowledgement, a replayed
	// batch is counted once.
	//
	// Three inaccuracies remain and a consumer has to know all of them. A crash between the acknowledgement and the durable record
	// loses those counts, and so does a failure of that record, which is logged and dropped rather than allowed to fail a batch
	// that is already acknowledged. Both leave THIS counter ahead of the durable table, since it is incremented first. Losing
	// counts is the direction that carries risk rather than the one that avoids it: a rule that looks quieter than it is gets
	// promoted, and promoting a noisy rule is the outcome monitor mode exists to prevent. Third, an evaluation that outlives its
	// claim lease can be re-offered to another worker while the first is still running; Ack does not verify claim ownership, so
	// both attempts can succeed and both can record.
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
}
