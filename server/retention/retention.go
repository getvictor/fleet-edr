// Package retention implements the Phase 4 event-retention job. On a schedule it deletes
// rows from the `events` table older than a configurable window, preserving any event
// that is referenced by an `alert_events` row so alert detail views can still render.
//
// Deletes run in batches (default 10k rows) so a backlogged fleet that accumulated
// months of events doesn't hold InnoDB row locks for the entire table during a single
// multi-gigabyte DELETE. Each batch is a separate transaction; the loop stops once a
// batch deletes fewer rows than the configured batch size.
package retention

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Deleter is the minimal DB surface the runner needs. Matches *sql.DB / *sqlx.DB so a
// caller can pass either. Kept narrow so tests can substitute a recorder.
type Deleter interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// MetricsRecorder is the optional OTel hook. Nil is fine — retention runs without
// metrics. The hook receives the total rows deleted in a single retention pass.
type MetricsRecorder interface {
	RetentionRowsDeleted(ctx context.Context, n int64)
}

// Options tune the runner. Zero values fall back to documented defaults.
type Options struct {
	// RetentionDays is how long events are kept. 0 disables retention entirely (the
	// runner becomes a no-op). There is no default at this layer — config.Load
	// applies 30 when EDR_RETENTION_DAYS is unset; New preserves whatever value
	// arrives here so operators who explicitly pass 0 get retention off.
	RetentionDays int
	// Interval between runs. Default 1h. In tests pass something short so the loop
	// loop doesn't take a real hour.
	Interval time.Duration
	// BatchSize is the per-iteration DELETE cap. Default 10 000 — tuned for InnoDB
	// row-lock budgets on a single-node MySQL.
	BatchSize int
	// Logger for audit lines. Nil uses slog.Default().
	Logger *slog.Logger
	// Metrics, optional.
	Metrics MetricsRecorder
	// Now is the clock source. Nil uses time.Now.UTC. Tests can freeze.
	Now func() time.Time
}

// attrRetentionDays is the slog/OTel attribute key for the configured retention window.
const attrRetentionDays = "edr.retention.days"

// Runner executes retention passes on a cadence.
type Runner struct {
	db            Deleter
	retentionDays int
	interval      time.Duration
	batchSize     int
	logger        *slog.Logger
	metrics       MetricsRecorder
	now           func() time.Time
}

// New builds a Runner. Panics if db is nil. Never errors; config problems are
// caught at config.Load time.
func New(db Deleter, opts Options) *Runner {
	if db == nil {
		panic("retention.New: db must not be nil")
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
	return &Runner{
		db:            db,
		retentionDays: opts.RetentionDays,
		interval:      opts.Interval,
		batchSize:     opts.BatchSize,
		logger:        opts.Logger,
		metrics:       opts.Metrics,
		now:           opts.Now,
	}
}

// Loop runs retention passes until ctx is done. Blocks. Intended to be started in its
// own goroutine by main.go. The first run happens immediately so a just-started server
// doesn't wait a full interval to purge old rows from a pre-existing DB.
func (r *Runner) Loop(ctx context.Context) {
	if r.retentionDays == 0 {
		r.logger.InfoContext(ctx, "retention disabled", attrRetentionDays, 0)
		return
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	// Fire once up front, then on each tick.
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

// Run executes one retention pass and returns total rows deleted. Safe to call
// concurrently with itself only in the sense that it won't corrupt data — the
// per-batch DELETE is atomic — but running in parallel yields redundant work. Caller
// arranges single-writer semantics; Loop() is the normal entry point.
func (r *Runner) Run(ctx context.Context) (int64, error) {
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
		// MySQL does not allow `DELETE ... JOIN ... LIMIT` in a single statement, so
		// the join-based variant of this query gets rewritten as a single-table DELETE
		// with a correlated NOT EXISTS predicate against alert_events.event_id. NOT
		// EXISTS is optimiser-safer than NOT IN (no anti-semi-join rewrite gotchas) and
		// runs against the UNIQUE/PK index on alert_events.event_id.
		//
		// ORDER BY timestamp_ns makes per-batch deletion deterministic (oldest-first)
		// and keeps statement-based replication happy — MySQL warns on
		// `DELETE ... LIMIT` without ORDER BY because different replicas could pick
		// different rows. The existing idx_events_host_ts covers the ordering.
		//
		// LIMIT bounds the lock footprint: retention on a DB with years of history
		// would otherwise DELETE millions of rows in a single statement and block
		// concurrent ingest.
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
