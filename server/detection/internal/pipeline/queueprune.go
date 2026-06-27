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
type QueuePruneRunner struct {
	eventLog  visibilityapi.EventLog
	interval  time.Duration
	batchSize int
	logger    *slog.Logger
	metrics   api.MetricsRecorder
}

// QueuePruneOptions tune the queue-prune sweep.
type QueuePruneOptions struct {
	// Interval between sweeps. Default 1 minute: frequent enough to keep the queue small at a high ingest rate, cheap because the
	// DELETE is index-driven (the claim index leads with processed) and a no-op when nothing is acked.
	Interval time.Duration
	// BatchSize is the per-statement DELETE cap. Default 10_000, matching the process-retention sweep.
	BatchSize int
	Logger    *slog.Logger
	Metrics   api.MetricsRecorder
}

// NewQueuePrune builds a QueuePruneRunner over the given EventLog.
func NewQueuePrune(eventLog visibilityapi.EventLog, opts QueuePruneOptions) *QueuePruneRunner {
	if opts.Interval <= 0 {
		opts.Interval = time.Minute
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 10_000
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &QueuePruneRunner{
		eventLog:  eventLog,
		interval:  opts.Interval,
		batchSize: opts.BatchSize,
		logger:    opts.Logger,
		metrics:   opts.Metrics,
	}
}

// SetMetrics installs the metrics recorder after construction (cmd/main two-phase setup, see RetentionRunner.SetMetrics).
func (r *QueuePruneRunner) SetMetrics(m api.MetricsRecorder) { r.metrics = m }

// Loop runs a sweep immediately and then every interval until ctx is cancelled. A failed sweep logs and is retried on the next tick;
// nothing is lost because the rows stay acked (processed = 1) until a later sweep removes them.
func (r *QueuePruneRunner) Loop(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	if _, err := r.Run(ctx); err != nil {
		r.logger.WarnContext(ctx, "queue-prune initial run failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.Run(ctx); err != nil {
				r.logger.WarnContext(ctx, "queue-prune run failed", "err", err)
			}
		}
	}
}

// Run executes one sweep and returns the number of rows pruned. PruneProcessed batches the DELETEs internally; this records the total.
func (r *QueuePruneRunner) Run(ctx context.Context) (int64, error) {
	pruned, err := r.eventLog.PruneProcessed(ctx, r.batchSize)
	// Record what was removed before checking the error: a mid-batch failure still removed `pruned` rows, and reporting them keeps the
	// gauge honest (the same emit-then-check discipline the retention sweep uses).
	trace.SpanFromContext(ctx).SetAttributes(attribute.Int64("edr.event_queue.rows_pruned", pruned))
	if r.metrics != nil {
		r.metrics.QueueRowsPruned(ctx, pruned)
	}
	if err != nil {
		return pruned, err
	}
	if pruned > 0 {
		r.logger.InfoContext(ctx, "pruned acked events from the queue", "rows", pruned)
	}
	return pruned, nil
}
