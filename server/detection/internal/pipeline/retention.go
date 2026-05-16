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

// RetentionRunner executes retention passes on a cadence. Deletes rows from `events` older than RetentionDays, preserving any event
// referenced by an alert_events row so alert detail views still render. Per-batch DELETE bounds InnoDB row-lock footprint.
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

// Run executes one retention pass and returns total rows deleted.
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

	var total int64
	for {
		res, err := r.db.ExecContext(ctx, `
			DELETE FROM events
			WHERE timestamp_ns < ?
			  AND NOT EXISTS (
			      SELECT 1 FROM alert_events ae WHERE ae.event_id = events.event_id
			  )
			ORDER BY timestamp_ns
			LIMIT ?
		`, cutoff, r.batchSize)
		if err != nil {
			return total, fmt.Errorf("retention delete batch: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("retention rows affected: %w", err)
		}
		total += n
		if n < int64(r.batchSize) {
			break
		}
	}

	span.SetAttributes(attribute.Int64("edr.retention.rows_deleted", total))
	if r.metrics != nil {
		r.metrics.RetentionRowsDeleted(ctx, total)
	}
	r.logger.InfoContext(ctx, "retention run",
		attrRetentionDays, r.retentionDays,
		"edr.retention.cutoff_ns", cutoff,
		"edr.retention.rows_deleted", total,
	)
	return total, nil
}
