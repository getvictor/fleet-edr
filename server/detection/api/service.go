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
	UpdateAlertStatus(ctx context.Context, id int64, status AlertStatus, userID int64) (Alert, error)

	// RecordHostSeen advances hosts.last_seen_ns. Called by response
	// on every /api/commands poll; replaces store.UpdateHostLastSeen.
	RecordHostSeen(ctx context.Context, hostID string, at time.Time) error

	// CountOfflineHosts counts hosts whose last_seen_ns is older than
	// the threshold. Used by the OTel offline-hosts gauge.
	CountOfflineHosts(ctx context.Context, threshold time.Duration) (int, error)

	// CountUnprocessed counts events with processed != 1. Used by the
	// OTel unprocessed-events gauge so SOC dashboards can alert on
	// stuck-processor fleets.
	CountUnprocessed(ctx context.Context) (int64, error)

	// IngestHandler returns the POST /api/events handler. Returned
	// as an http.Handler rather than registered via a separate route
	// method so the cmd/main split between fleet-edr-server and
	// fleet-edr-ingest can mount the same handler under different
	// middleware chains.
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
	// GetProcessByPID returns the row whose (host, pid) bracket
	// atTimeNs (i.e. fork_time_ns <= atTimeNs <= exit_time_ns or
	// exit_time_ns IS NULL).
	GetProcessByPID(ctx context.Context, hostID string, pid int, atTimeNs int64) (*Process, error)

	// GetChildProcesses returns all rows whose ppid matches the given
	// parent PID and whose fork_time_ns falls inside the time range.
	GetChildProcesses(ctx context.Context, hostID string, ppid int, tr TimeRange) ([]Process, error)

	// GetExecChain walks PreviousExecID backwards from the given row
	// to its chain root. Returns at least one element (the input
	// row) and at most the chain length.
	GetExecChain(ctx context.Context, current Process) ([]Process, error)
}

// MetricsRecorder is the optional OTel hook the engine + intake +
// pipeline goroutines write to. Nil-safe: cmd/main wires the
// metrics.Recorder; tests pass nil.
type MetricsRecorder interface {
	EventsIngested(ctx context.Context, hostID string, n int)
	ObserveDBQuery(ctx context.Context, op string, d time.Duration)
	AlertCreated(ctx context.Context, ruleID, severity string)
	// ProcessesTTLReconciled is called by the pipeline's
	// stale-process janitor on every reconciliation pass.
	ProcessesTTLReconciled(ctx context.Context, n int64)
	// RetentionRowsDeleted is called by the pipeline's retention
	// runner on every retention pass.
	RetentionRowsDeleted(ctx context.Context, n int64)
}
