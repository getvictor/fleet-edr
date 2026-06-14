package pipeline

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/detection/api"
)

// retentionDeleter is the minimal DB surface the retention runner
// needs. Matches *sql.DB / *sqlx.DB so a caller can pass either.
type retentionDeleter interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// RetentionOptions tune the retention runner.
type RetentionOptions struct {
	// RetentionDays is how long events are kept. 0 disables retention.
	RetentionDays int
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

const attrRetentionDays = "edr.retention.days"

// RetentionRunner executes retention passes on a cadence. Each pass deletes two row families older than RetentionDays, each preserving
// rows still referenced by an alert so alert detail views keep rendering:
//   - `events` older than the cutoff (by timestamp_ns), skipping any event referenced by an alert_events row.
//   - completed `processes` whose exit_time_ns is older than the cutoff, skipping any process referenced by an alerts.process_id row.
//
// The process prune keys on exit_time_ns, never fork_time_ns: a still-running record (exit_time_ns IS NULL, which includes the live
// snapshot working set) is therefore never deleted, and a long-running process that only recently exited is retained for the full
// window measured from its exit. Stale records whose exit event went missing are first force-closed by the freshness-TTL reconciler
// (ProcessTTLRunner, issue #6) and become prunable here once their synthesized exit ages past the window; that two-job split is why this
// prune can safely ignore NULL-exit rows. Per-batch DELETE bounds InnoDB row-lock footprint.
type RetentionRunner struct {
	db            retentionDeleter
	retentionDays int
	interval      time.Duration
	batchSize     int
	logger        *slog.Logger
	metrics       api.MetricsRecorder
	now           func() time.Time
}

// NewRetention builds a RetentionRunner. Panics if db is nil.
func NewRetention(db retentionDeleter, opts RetentionOptions) *RetentionRunner {
	if db == nil {
		panic("pipeline.NewRetention: db must not be nil")
	}
	if opts.RetentionDays < 0 {
		opts.RetentionDays = 0
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
		db:            db,
		retentionDays: opts.RetentionDays,
		interval:      opts.Interval,
		batchSize:     opts.BatchSize,
		logger:        opts.Logger,
		metrics:       opts.Metrics,
		now:           opts.Now,
	}
}

// SetMetrics installs the metrics recorder after construction. See ProcessTTLRunner.SetMetrics for the cmd/main two-phase setup
// rationale.
func (r *RetentionRunner) SetMetrics(m api.MetricsRecorder) { r.metrics = m }

// Loop runs retention passes until ctx is done.
func (r *RetentionRunner) Loop(ctx context.Context) {
	if r.retentionDays == 0 {
		r.logger.InfoContext(ctx, "retention disabled", attrRetentionDays, 0)
		return
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	if _, err := r.Run(ctx); err != nil {
		r.logger.WarnContext(ctx, "retention initial run failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.Run(ctx); err != nil {
				r.logger.WarnContext(ctx, "retention run failed", "err", err)
			}
		}
	}
}

// Run executes one retention pass and returns total rows deleted across events + processes.
func (r *RetentionRunner) Run(ctx context.Context) (int64, error) {
	if r.retentionDays == 0 {
		return 0, nil
	}
	cutoff := r.now().Add(-time.Duration(r.retentionDays) * 24 * time.Hour).UnixNano()
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.Int(attrRetentionDays, r.retentionDays),
		attribute.Int64("edr.retention.cutoff_ns", cutoff),
	)

	// Emit each delete's count as soon as that delete returns, before checking its error. pruneBatched reports rows actually deleted even
	// on a mid-batch failure, and a failure in the second (processes) delete must not suppress the telemetry for the first (events) one,
	// else a partial-failure run reports zero events pruned when rows were in fact removed.
	events, eventsErr := r.pruneBatched(ctx, `
		DELETE FROM events
		WHERE timestamp_ns < ?
		  AND NOT EXISTS (
		      SELECT 1 FROM alert_events ae WHERE ae.event_id = events.event_id
		  )
		ORDER BY timestamp_ns
		LIMIT ?
	`, cutoff)
	span.SetAttributes(attribute.Int64("edr.retention.rows_deleted", events))
	if r.metrics != nil {
		r.metrics.RetentionRowsDeleted(ctx, events)
	}
	if eventsErr != nil {
		return events, fmt.Errorf("retention delete events batch: %w", eventsErr)
	}

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
		return events + processes, fmt.Errorf("retention delete processes batch: %w", procErr)
	}

	r.logger.InfoContext(ctx, "retention run",
		attrRetentionDays, r.retentionDays,
		"edr.retention.cutoff_ns", cutoff,
		"edr.retention.rows_deleted", events,
		"edr.retention.processes.rows_deleted", processes,
	)
	return events + processes, nil
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
