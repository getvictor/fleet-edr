package pipeline

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
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
	attrRetentionDays      = "edr.retention.days"
	attrAlertRetentionDays = "edr.retention.alerts.days"
)

// RetentionRunner executes retention passes on a cadence. Each pass runs two prunes, on two independent windows, in this order:
//   - alerts whose last triage activity (updated_at) is older than AlertRetentionDays, with their event links (issue #995);
//   - completed `processes` whose exit_time_ns is older than RetentionDays, skipping any process an alert still references.
//
// Alerts go first so a process record an expired alert was holding is collected in the same pass. Either window may be 0 while the other
// runs. Event retention is handled by the ClickHouse archive's native TTL (ADR-0015), not here.
//
// The process prune keys on exit_time_ns, never fork_time_ns: a still-running record (exit_time_ns IS NULL, which includes the live
// snapshot working set) is therefore never deleted, and a long-running process that only recently exited is retained for the full
// window measured from its exit. Stale records whose exit event went missing are first force-closed by the freshness-TTL reconciler
// (ProcessTTLRunner, issue #6) and become prunable here once their synthesized exit ages past the window; that two-job split is why this
// prune can safely ignore NULL-exit rows. Per-batch DELETE bounds InnoDB row-lock footprint.
type RetentionRunner struct {
	db                 retentionDeleter
	retentionDays      int
	alertRetentionDays int
	interval           time.Duration
	batchSize          int
	logger             *slog.Logger
	metrics            api.MetricsRecorder
	now                func() time.Time
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
		db:                 db,
		retentionDays:      opts.RetentionDays,
		alertRetentionDays: opts.AlertRetentionDays,
		interval:           opts.Interval,
		batchSize:          opts.BatchSize,
		logger:             opts.Logger,
		metrics:            opts.Metrics,
		now:                opts.Now,
	}
}

// SetMetrics installs the metrics recorder after construction. See ProcessTTLRunner.SetMetrics for the cmd/main two-phase setup
// rationale.
func (r *RetentionRunner) SetMetrics(m api.MetricsRecorder) { r.metrics = m }

// Loop runs retention passes until ctx is done.
//
// It stops only when BOTH windows are disabled. It used to stop whenever the process window was 0, which was right while that was the
// runner's only job; with alerts on their own knob, that early return would have silently disabled alert pruning for every operator who
// turned process pruning off for a forensic hold, which is the opposite of what either setting says.
func (r *RetentionRunner) Loop(ctx context.Context) {
	if r.retentionDays == 0 && r.alertRetentionDays == 0 {
		r.logger.InfoContext(ctx, "retention disabled", attrRetentionDays, 0, attrAlertRetentionDays, 0)
		return
	}
	runPeriodic(ctx, r.interval, r.logger, "retention", r.Run)
}

// Run executes one retention pass: the alert prune, then the process prune. It returns the number of PROCESS records pruned, which is what
// its callers have always read; the alert count is reported through its own span attribute, metric, and log line instead of being summed
// into a number that meant one thing for years. Event retention is ClickHouse-native TTL (ADR-0015), not part of this pass.
func (r *RetentionRunner) Run(ctx context.Context) (int64, error) {
	// Alerts BEFORE processes, so a process row an expired alert was holding is collected in this same pass rather than an hour later.
	// The process prune skips any row an alert still references; running it first would see the expiring alert's reference and keep
	// the row until the next pass. Either order converges, but this one does not leave a pass's worth of rows behind for no reason.
	if err := r.pruneAlerts(ctx); err != nil {
		return 0, err
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

// pruneAlerts deletes alerts whose last triage activity is older than the alert window, in batches, and reports the count through the
// span, the metric, and the run log. A no-op when the alert window is disabled.
//
// Keyed on updated_at, the last status change, not on created_at. An alert an analyst acknowledged or reopened inside the window is one
// somebody is working, and deleting it because it was raised long ago would take evidence out from under an open investigation. The
// dedup path deliberately never touches updated_at when a finding re-fires, so a standing condition that nobody triages still ages out,
// and its next re-fire raises a fresh alert rather than being lost.
func (r *RetentionRunner) pruneAlerts(ctx context.Context) error {
	if r.alertRetentionDays == 0 {
		return nil
	}
	cutoff := r.now().Add(-time.Duration(r.alertRetentionDays) * 24 * time.Hour)
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.Int(attrAlertRetentionDays, r.alertRetentionDays))

	var total int64
	for {
		n, err := r.pruneAlertBatch(ctx, cutoff)
		total += n
		if err != nil {
			span.SetAttributes(attribute.Int64("edr.retention.alerts.rows_deleted", total))
			if r.metrics != nil {
				r.metrics.AlertRetentionRowsDeleted(ctx, total)
			}
			return fmt.Errorf("retention delete alerts batch: %w", err)
		}
		if n < int64(r.batchSize) {
			break
		}
	}
	span.SetAttributes(attribute.Int64("edr.retention.alerts.rows_deleted", total))
	if r.metrics != nil {
		r.metrics.AlertRetentionRowsDeleted(ctx, total)
	}
	r.logger.InfoContext(ctx, "alert retention run",
		attrAlertRetentionDays, r.alertRetentionDays,
		"edr.retention.alerts.cutoff", cutoff,
		"edr.retention.alerts.rows_deleted", total,
	)
	return nil
}

// pruneAlertBatch deletes one batch of expired alerts and returns how many it removed.
//
// A transaction rather than a single DELETE, for two reasons that are both about alert_events. Its foreign key to alerts carries no ON
// DELETE CASCADE, so an alert with linked events cannot be deleted until those links are, and every alert has linked events: a plain
// DELETE FROM alerts would fail on its first row. And the two deletes must be atomic against a re-fire. InsertAlert's dedup takes a lock
// on the alert row and re-links new events to it; without the FOR UPDATE here, a re-fire landing between the two statements could link
// fresh evidence to an alert whose older links were just removed, and the alert would survive having lost part of its record. Locking the
// selected rows first makes that re-fire wait, then find no alert, and raise a fresh one.
//
// alert_event_payloads and webhook_delivery both cascade from alerts, so they need no statement of their own.
func (r *RetentionRunner) pruneAlertBatch(ctx context.Context, cutoff time.Time) (int64, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin alert retention batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var ids []int64
	if err := tx.SelectContext(ctx, &ids, `
		SELECT id FROM alerts
		WHERE updated_at < ?
		ORDER BY updated_at
		LIMIT ?
		FOR UPDATE`, cutoff, r.batchSize); err != nil {
		return 0, fmt.Errorf("select expired alerts: %w", err)
	}
	if len(ids) == 0 {
		return 0, tx.Commit()
	}

	eventsQuery, eventsArgs, err := sqlx.In(`DELETE FROM alert_events WHERE alert_id IN (?)`, ids)
	if err != nil {
		return 0, fmt.Errorf("build alert_events delete: %w", err)
	}
	if _, err := tx.ExecContext(ctx, eventsQuery, eventsArgs...); err != nil {
		return 0, fmt.Errorf("delete expired alerts' event links: %w", err)
	}
	alertsQuery, alertsArgs, err := sqlx.In(`DELETE FROM alerts WHERE id IN (?)`, ids)
	if err != nil {
		return 0, fmt.Errorf("build alerts delete: %w", err)
	}
	res, err := tx.ExecContext(ctx, alertsQuery, alertsArgs...)
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
