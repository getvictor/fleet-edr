package pipeline

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/detection/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// QueuePruneRunner periodically removes acked rows from the visibility event work queue (ADR-0015). Ack only marks a row processed (a
// cheap index UPDATE on the per-replica hot path); this leader-gated sweep does the batched DELETEs off that path so the queue keeps to
// its in-flight working set rather than accumulating every processed event. Independent of event/process retention: the queue must be
// swept even when age-based retention is disabled, and on a shorter cadence (the queue grows at the ingest rate, not the retention
// window), so it is its own runner rather than folded into RetentionRunner. The durable history lives in the archive, so a pruned row
// is never needed again.
//
// It also sweeps SET-ASIDE rows (processed = 3, issue #836), and those DO age on the retention window, which is the one place this
// runner is not retention-independent. The distinction is deliberate. An acked row is finished and worth nothing, so it goes
// whatever retention says. A set-aside row is the only record of which events a host stopped contributing to its process graph, so
// it is kept for as long as the deployment keeps anything, and kept indefinitely when retention is disabled, which is what
// disabling retention means everywhere else.
type QueuePruneRunner struct {
	eventLog      visibilityapi.EventLog
	interval      time.Duration
	batchSize     int
	retentionDays int
	logger        *slog.Logger
	metrics       api.MetricsRecorder
}

// QueuePruneOptions tune the queue-prune sweep.
type QueuePruneOptions struct {
	// Interval between sweeps. Default 1 minute: frequent enough to keep the queue small at a high ingest rate, cheap because the
	// DELETE is index-driven (the claim index leads with processed) and a no-op when nothing is acked.
	Interval time.Duration
	// BatchSize is the per-statement DELETE cap. Zero lets the EventLog apply its own default, keeping that default in one place
	// (eventlog.Store owns it) rather than restating it here where the two could drift.
	BatchSize int
	// RetentionDays bounds how long a SET-ASIDE row is kept. Zero or negative keeps them indefinitely, matching what a disabled
	// retention window means for every other store. It does not affect the acked-row sweep, which runs regardless.
	RetentionDays int
	Logger        *slog.Logger
	Metrics       api.MetricsRecorder
}

// NewQueuePrune builds a QueuePruneRunner over the given EventLog.
func NewQueuePrune(eventLog visibilityapi.EventLog, opts QueuePruneOptions) *QueuePruneRunner {
	if opts.Interval <= 0 {
		opts.Interval = time.Minute
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &QueuePruneRunner{
		eventLog:      eventLog,
		interval:      opts.Interval,
		batchSize:     opts.BatchSize,
		retentionDays: opts.RetentionDays,
		logger:        opts.Logger,
		metrics:       opts.Metrics,
	}
}

// SetMetrics installs the metrics recorder after construction (cmd/main two-phase setup, see RetentionRunner.SetMetrics).
func (r *QueuePruneRunner) SetMetrics(m api.MetricsRecorder) { r.metrics = m }

// Loop runs a sweep immediately and then every interval until ctx is cancelled. A failed sweep logs and is retried on the next tick;
// nothing is lost because the rows stay acked (processed = 1) until a later sweep removes them.
func (r *QueuePruneRunner) Loop(ctx context.Context) {
	runPeriodic(ctx, r.interval, r.logger, "queue-prune", r.Run)
}

// Run executes one sweep and returns the number of rows pruned. PruneProcessed batches the DELETEs internally; this records the total.
func (r *QueuePruneRunner) Run(ctx context.Context) (int64, error) {
	pruned, err := r.eventLog.PruneProcessed(ctx, r.batchSize)
	// Record what was removed before checking the error: a mid-batch failure still removed `pruned` rows, and reporting them keeps the
	// rows_pruned counter honest (the same emit-then-check discipline the retention sweep uses).
	trace.SpanFromContext(ctx).SetAttributes(attribute.Int64("edr.event_queue.rows_pruned", pruned))
	if r.metrics != nil {
		r.metrics.QueueRowsPruned(ctx, pruned)
	}
	if err != nil {
		return pruned, err
	}
	// Swept after the acked rows and reported separately, because the two mean different things: acked rows draining is routine,
	// and set-aside rows draining means the window to inspect a host's gap has closed.
	if setAside, sErr := r.eventLog.PruneSetAside(ctx, r.retentionDays, r.batchSize); sErr != nil {
		r.logger.WarnContext(ctx, "prune set-aside events from the queue", "err", sErr)
	} else if setAside > 0 {
		r.logger.InfoContext(ctx, "pruned set-aside events past the retention window", "rows", setAside,
			"retention_days", r.retentionDays)
	}
	if pruned > 0 {
		r.logger.InfoContext(ctx, "pruned acked events from the queue", "rows", pruned)
	}
	return pruned, nil
}
