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
	BuildTree(ctx context.Context, hostID string, tr TimeRange, limit int) ([]ProcessNode, error)
	GetProcessDetail(ctx context.Context, hostID string, pid int, atTimeNs int64) (*ProcessDetail, error)
	ListAlerts(ctx context.Context, filter AlertFilter) ([]Alert, error)
	GetAlert(ctx context.Context, id int64) (Alert, []string, error) // alert + correlated event IDs
	// GetAlertEvidence returns the self-contained triggering-event envelopes captured for an alert at creation time (ADR-0015), so the
	// detail view resolves them even after the raw events age out of the event store. Best-effort: an alert may carry fewer payloads
	// than event IDs (alerts created before capture landed, or events already aged out at creation).
	GetAlertEvidence(ctx context.Context, id int64) ([]Event, error)
	UpdateAlertStatus(ctx context.Context, id int64, status AlertStatus, userID int64) (Alert, error)

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
	// clock-drift padding. A same-PID re-exec chain shares one pidversion, so the identity can match several generations; atNs then
	// selects the one that was the running image at the event time. A single identity match is returned regardless of atNs (identity
	// beats clock skew). Correlation rules prefer this when a flow event carries a pidversion and fall back to GetProcessByPID
	// otherwise (issue #403).
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
}

// MetricsRecorder is the optional OTel hook the engine + intake + pipeline goroutines write to. Nil-safe: cmd/main wires the
// metrics.Recorder; tests pass nil.
type MetricsRecorder interface {
	EventsIngested(ctx context.Context, hostID string, n int)
	// EventsHeartbeatDropped is called per-batch by the ingest handler with the number of snapshot_heartbeat events that were
	// processed for their freshness side effect and then dropped instead of persisted as retained event rows (issue #408).
	EventsHeartbeatDropped(ctx context.Context, hostID string, n int)
	AlertCreated(ctx context.Context, ruleID, severity string)
	// ProcessesTTLReconciled is called by the pipeline's
	// stale-process janitor on every reconciliation pass.
	ProcessesTTLReconciled(ctx context.Context, n int64)
	// RetentionRowsDeleted is called by the pipeline's retention
	// runner on every retention pass, reporting event rows deleted.
	RetentionRowsDeleted(ctx context.Context, n int64)
	// ProcessRetentionRowsDeleted is called by the pipeline's retention runner on every pass with the count of completed process rows
	// pruned past the retention window (counted separately from event rows).
	ProcessRetentionRowsDeleted(ctx context.Context, n int64)
}
