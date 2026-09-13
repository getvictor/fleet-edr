package pipeline

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/detection/api"
)

// retentionDeleter is the minimal DB surface the retention runner needs. *sqlx.DB satisfies it. BeginTxx is there for the alert
// prune, which has to remove an alert's event links and the alert itself atomically (see pruneAlertBatch).
type retentionDeleter interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	BeginTxx(ctx context.Context, opts *sql.TxOptions) (*sqlx.Tx, error)
}

// RetentionOptions tune the retention runner.
type RetentionOptions struct {
	// RetentionDays is how long process records are kept. 0 disables retention. Event retention is ClickHouse-native TTL (ADR-0015).
	RetentionDays int
	// AlertRetentionDays is how long an alert is kept after its last triage activity (issue #995). 0 disables the alert prune. Independent
	// of RetentionDays in both directions: either can be 0 while the other runs.
	AlertRetentionDays int
	// MonitorRecordRetentionDays is how long a monitor record is kept (issue #994). 0 disables the monitor-record prune. Independent of
	// both other windows: the alert prune never deletes a monitor record and this one never deletes an alert.
	MonitorRecordRetentionDays int
	// Interval between runs. Default 1h.
	Interval time.Duration
	// BatchSize is the per-iteration DELETE cap. Default 10_000.
	BatchSize int
	// Logger for audit lines. Nil uses slog.Default().
	Logger *slog.Logger
	// Metrics, optional.
	Metrics api.MetricsRecorder
	// Now is the clock source. Nil uses time.Now.UTC.
	Now func() time.Time
}

const (
	attrRetentionDays              = "edr.retention.days"
	attrAlertRetentionDays         = "edr.retention.alerts.days"
	attrAlertRowsDeleted           = "edr.retention.alerts.rows_deleted"
	attrMonitorRecordRetentionDays = "edr.retention.monitor_records.days"
	attrMonitorRecordRowsDeleted   = "edr.retention.monitor_records.rows_deleted"
)

// RetentionRunner executes retention passes on a cadence. Each pass runs three prunes, on three independent windows, in this order:
//   - alerts whose last triage activity (updated_at) is older than AlertRetentionDays, with their event links (issue #995);
//   - monitor records last written (updated_at) longer ago than MonitorRecordRetentionDays, with their event links (issue #994);
//   - completed `processes` whose exit_time_ns is older than RetentionDays, skipping any process an alert or monitor record references.
//
// The alerts table holds both alerts and monitor records, and each of the first two prunes selects only its own disposition. Both go
// before the process prune so a process record either was holding is collected in the same pass. Any window may be 0 while the others
// run. Event retention is handled by the ClickHouse archive's native TTL (ADR-0015), not here.
//
// The process prune keys on exit_time_ns, never fork_time_ns: a still-running record (exit_time_ns IS NULL, which includes the live
// snapshot working set) is therefore never deleted, and a long-running process that only recently exited is retained for the full
// window measured from its exit. Stale records whose exit event went missing are first force-closed by the freshness-TTL reconciler
// (ProcessTTLRunner, issue #6) and become prunable here once their synthesized exit ages past the window; that two-job split is why this
// prune can safely ignore NULL-exit rows. Per-batch DELETE bounds InnoDB row-lock footprint.
type RetentionRunner struct {
	db                         retentionDeleter
	retentionDays              int
	alertRetentionDays         int
	monitorRecordRetentionDays int
	interval                   time.Duration
	batchSize                  int
	logger                     *slog.Logger
	metrics                    api.MetricsRecorder
	now                        func() time.Time
}

// NewRetention builds a RetentionRunner. Panics if db is nil.
func NewRetention(db retentionDeleter, opts RetentionOptions) *RetentionRunner {
	if db == nil {
		panic("pipeline.NewRetention: db must not be nil")
	}
	if opts.RetentionDays < 0 {
		opts.RetentionDays = 0
	}
	if opts.AlertRetentionDays < 0 {
		opts.AlertRetentionDays = 0
	}
	if opts.MonitorRecordRetentionDays < 0 {
		opts.MonitorRecordRetentionDays = 0
	}
	if opts.Interval <= 0 {
		opts.Interval = time.Hour
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 10_000
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	return &RetentionRunner{
		db:                         db,
		retentionDays:              opts.RetentionDays,
		alertRetentionDays:         opts.AlertRetentionDays,
		monitorRecordRetentionDays: opts.MonitorRecordRetentionDays,
		interval:                   opts.Interval,
		batchSize:                  opts.BatchSize,
		logger:                     opts.Logger,
		metrics:                    opts.Metrics,
		now:                        opts.Now,
	}
}

// SetMetrics installs the metrics recorder after construction. See ProcessTTLRunner.SetMetrics for the cmd/main two-phase setup
// rationale.
func (r *RetentionRunner) SetMetrics(m api.MetricsRecorder) { r.metrics = m }

// Loop runs retention passes until ctx is done.
//
// It stops only when EVERY window is disabled. It used to stop whenever the process window was 0, which was right while that was the
// runner's only job; with alerts and monitor records on their own knobs, that early return would have silently disabled their pruning for
// every operator who turned process pruning off for a forensic hold, which is the opposite of what any of the settings says.
func (r *RetentionRunner) Loop(ctx context.Context) {
	if r.retentionDays == 0 && r.alertRetentionDays == 0 && r.monitorRecordRetentionDays == 0 {
		r.logger.InfoContext(ctx, "retention disabled",
			attrRetentionDays, 0, attrAlertRetentionDays, 0, attrMonitorRecordRetentionDays, 0)
		return
	}
	runPeriodic(ctx, r.interval, r.logger, "retention", r.Run)
}

// Run executes one retention pass: the alert prune, the monitor-record prune, then the process prune. It returns the number of PROCESS
// records pruned, which is what its callers have always read; the other counts are reported through their own span attributes, metrics,
// and log lines instead of being summed into a number that meant one thing for years. Event retention is ClickHouse-native TTL (ADR-0015), not part of this pass.
func (r *RetentionRunner) Run(ctx context.Context) (int64, error) {
	// Alerts BEFORE processes, so a process row an expired alert was holding is collected in this same pass rather than an hour later.
	// The process prune skips any row an alert still references; running it first would see the expiring alert's reference and keep
	// the row until the next pass. Either order converges, but this one does not leave a pass's worth of rows behind for no reason.
	for _, w := range r.alertWindows() {
		if err := r.pruneAlerts(ctx, w); err != nil {
			return 0, err
		}
	}
	if r.retentionDays == 0 {
		return 0, nil
	}
	cutoff := r.now().Add(-time.Duration(r.retentionDays) * 24 * time.Hour).UnixNano()
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.Int(attrRetentionDays, r.retentionDays),
		attribute.Int64("edr.retention.cutoff_ns", cutoff),
	)

	// Completed processes only (exit_time_ns IS NOT NULL): see the type doc for why NULL-exit rows are intentionally left to the
	// freshness-TTL reconciler. The alerts.process_id FK is ON DELETE RESTRICT, so an alert-referenced row must be skipped or the
	// batch DELETE errors; the NOT EXISTS guard does that and is index-backed by InnoDB's implicit FK index on alerts.process_id.
	processes, procErr := r.pruneBatched(ctx, `
		DELETE FROM processes
		WHERE exit_time_ns IS NOT NULL
		  AND exit_time_ns < ?
		  AND NOT EXISTS (
		      SELECT 1 FROM alerts a WHERE a.process_id = processes.id
		  )
		ORDER BY exit_time_ns
		LIMIT ?
	`, cutoff)
	span.SetAttributes(attribute.Int64("edr.retention.processes.rows_deleted", processes))
	if r.metrics != nil {
		r.metrics.ProcessRetentionRowsDeleted(ctx, processes)
	}
	if procErr != nil {
		return processes, fmt.Errorf("retention delete processes batch: %w", procErr)
	}

	r.logger.InfoContext(ctx, "retention run",
		attrRetentionDays, r.retentionDays,
		"edr.retention.cutoff_ns", cutoff,
		"edr.retention.processes.rows_deleted", processes,
	)
	return processes, nil
}

// alertWindow is one disposition's retention window over the alerts table: which rows it prunes, how long they are kept, and where its
// count is reported.
type alertWindow struct {
	disposition api.AlertDisposition
	days        int
	daysAttr    string
	deletedAttr string
	cutoffAttr  string
	logMsg      string
	record      func(ctx context.Context, n int64)
}

// alertWindows lists the two windows over the alerts table. Separate windows rather than one prune with a per-row age, because they answer
// different questions on different scales: an alert is the investigation and compliance record and is kept for months, a monitor record is
// evidence for a promote decision made over a week, and there are several times as many of them (issue #994).
func (r *RetentionRunner) alertWindows() []alertWindow {
	return []alertWindow{
		{
			disposition: api.AlertDispositionAlert, days: r.alertRetentionDays,
			daysAttr: attrAlertRetentionDays, deletedAttr: attrAlertRowsDeleted, cutoffAttr: "edr.retention.alerts.cutoff",
			logMsg: "alert retention run",
			record: func(ctx context.Context, n int64) {
				if r.metrics != nil {
					r.metrics.AlertRetentionRowsDeleted(ctx, n)
				}
			},
		},
		{
			disposition: api.AlertDispositionMonitor, days: r.monitorRecordRetentionDays,
			daysAttr: attrMonitorRecordRetentionDays, deletedAttr: attrMonitorRecordRowsDeleted, cutoffAttr: "edr.retention.monitor_records.cutoff",
			logMsg: "monitor record retention run",
			record: func(ctx context.Context, n int64) {
				if r.metrics != nil {
					r.metrics.MonitorRecordRetentionRowsDeleted(ctx, n)
				}
			},
		},
	}
}

// pruneAlerts deletes the rows of w's disposition whose updated_at is older than w's window, in batches, and reports the count through the
// span, the metric, and the run log. A no-op when the window is disabled.
//
// Keyed on updated_at, the last status change, not on created_at. An alert an analyst acknowledged or reopened inside the window is one
// somebody is working, and deleting it because it was raised long ago would take evidence out from under an open investigation. The
// dedup path deliberately never touches updated_at when a finding re-fires, so a standing condition that nobody triages still ages out,
// and its next re-fire raises a fresh alert rather than being lost. A monitor record is never triaged, so for it updated_at is when it
// was written.
func (r *RetentionRunner) pruneAlerts(ctx context.Context, w alertWindow) error {
	if w.days == 0 {
		return nil
	}
	cutoff := r.now().Add(-time.Duration(w.days) * 24 * time.Hour)
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.Int(w.daysAttr, w.days))

	// A failed batch still reports the batches before it, which committed: those rows are gone whether or not a later batch failed.
	var total int64
	var err error
	for {
		var n int64
		n, err = r.pruneAlertBatch(ctx, w.disposition, cutoff)
		total += n
		if err != nil || n < int64(r.batchSize) {
			break
		}
	}
	span.SetAttributes(attribute.Int64(w.deletedAttr, total))
	w.record(ctx, total)
	if err != nil {
		return fmt.Errorf("retention delete %s batch: %w", w.disposition, err)
	}
	r.logger.InfoContext(ctx, w.logMsg,
		w.daysAttr, w.days,
		w.cutoffAttr, cutoff,
		w.deletedAttr, total,
	)
	return nil
}

// pruneAlertBatch deletes one batch of expired rows of one disposition, alerts or monitor records, and returns how many it removed.
//
// A transaction rather than a single DELETE, because of alert_events. Its foreign key to alerts carries no ON DELETE CASCADE, so an alert
// with linked events cannot be deleted until those links are, and every alert has linked events: a plain DELETE FROM alerts would fail on
// its first row. Deleting the links first then needs the two statements to be atomic, or a batch that failed at the second would leave
// alerts it kept stripped of their evidence.
//
// The FOR UPDATE is about a finding re-firing against an alert this batch is expiring. InsertAlert's dedup statement takes the alert row
// first and links the new evidence after. Locking the selected rows up front orders the two: a re-fire already holding the row finishes
// before this batch reads it, and its new link is deleted with the alert; one arriving later waits, finds no alert, and raises a fresh
// one. Without the lock this batch deletes the links first, taking next-key locks on that alert_events range, then waits on the alert
// row, while the re-fire waits on those gap locks to insert its link. Staged in TestAlertRetention_ARefireDuringThePruneCompletesCleanly,
// InnoDB broke that deadlock by rolling back the detection write on every run.
//
// alert_event_payloads and webhook_delivery both cascade from alerts, so they need no statement of their own.
func (r *RetentionRunner) pruneAlertBatch(ctx context.Context, disposition api.AlertDisposition, cutoff time.Time) (int64, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin alert retention batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var ids []int64
	if err := tx.SelectContext(ctx, &ids, `
		SELECT id FROM alerts
		WHERE disposition = ? AND updated_at < ?
		ORDER BY updated_at
		LIMIT ?
		FOR UPDATE`, string(disposition), cutoff, r.batchSize); err != nil {
		return 0, fmt.Errorf("select expired alerts: %w", err)
	}
	if len(ids) == 0 {
		return 0, tx.Commit()
	}

	// Placeholders built directly: ids is non-empty here, which is the only input sqlx.In would have rejected.
	in := "?" + strings.Repeat(", ?", len(ids)-1)
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM alert_events WHERE alert_id IN (`+in+`)`, args...); err != nil {
		return 0, fmt.Errorf("delete expired alerts' event links: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM alerts WHERE id IN (`+in+`)`, args...)
	if err != nil {
		return 0, fmt.Errorf("delete expired alerts: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("expired alerts rows affected: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit alert retention batch: %w", err)
	}
	return n, nil
}

// pruneBatched runs a batched DELETE until a batch removes fewer than batchSize rows, returning the total deleted. query MUST end in a
// `LIMIT ?` bind; pruneBatched appends batchSize as that final arg (constant across batches, so the args slice is built once). Per-batch
// LIMIT bounds the InnoDB row-lock and undo-log footprint of a single statement on a large backlog.
func (r *RetentionRunner) pruneBatched(ctx context.Context, query string, args ...any) (int64, error) {
	args = append(args, r.batchSize)
	var total int64
	for {
		res, err := r.db.ExecContext(ctx, query, args...)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("retention rows affected: %w", err)
		}
		total += n
		if n < int64(r.batchSize) {
			return total, nil
		}
	}
}
