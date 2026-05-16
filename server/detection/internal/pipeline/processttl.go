package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/detection/api"
)

// processTTLReconciler is the narrow store-surface needed by the
// runner. Implemented by *mysql.Store.
type processTTLReconciler interface {
	ReconcileStaleProcesses(ctx context.Context, cutoffNs, maxAgeNs int64) (int64, error)
}

// SetMetrics installs the metrics recorder after construction. Used by Detection.SetMetrics to break the cmd/main circular-dependency
// (metrics recorder needs detectionCtx for the OfflineHosts gauge, detectionCtx's TTL runner needs the recorder).
func (r *ProcessTTLRunner) SetMetrics(m api.MetricsRecorder) { r.metrics = m }

// ProcessTTLOptions tune the runner. Zero values fall back to defaults.
type ProcessTTLOptions struct {
	// MaxAge is the fork-time age past which a still-running process is
	// considered stale and force-exited. 0 disables the runner entirely.
	MaxAge time.Duration
	// Interval between reconciliation passes. Default 10 minutes.
	Interval time.Duration
	// Logger for audit lines. Nil uses slog.Default().
	Logger *slog.Logger
	// Metrics, optional.
	Metrics api.MetricsRecorder
	// Now is the clock source. Nil uses time.Now.
	Now func() time.Time
}

// ProcessTTLRunner executes the issue #6 freshness-TTL reconciliation
// passes on a cadence. ESF is a best-effort event stream; exit events
// go missing under back-pressure / agent crashes / SQLite-queue
// pruning. When that happens the processes row stays green forever
// and the UI tree turns into a wall of stale greens.
//
// This runner periodically forces a synthesized exit on processes
// running past a configurable TTL. The synthesized exit is tagged
// exit_reason = "ttl_reconciliation" so the UI can render a
// distinct "forced gray" indicator rather than pretending it was a
// clean observed exit.
type ProcessTTLRunner struct {
	store    processTTLReconciler
	maxAge   time.Duration
	interval time.Duration
	logger   *slog.Logger
	metrics  api.MetricsRecorder
	now      func() time.Time
}

// NewProcessTTL builds a ProcessTTLRunner. Panics if store is nil.
func NewProcessTTL(s processTTLReconciler, opts ProcessTTLOptions) *ProcessTTLRunner {
	if s == nil {
		panic("pipeline.NewProcessTTL: store must not be nil")
	}
	if opts.MaxAge < 0 {
		opts.MaxAge = 0
	}
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Minute
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &ProcessTTLRunner{
		store:    s,
		maxAge:   opts.MaxAge,
		interval: opts.Interval,
		logger:   opts.Logger,
		metrics:  opts.Metrics,
		now:      opts.Now,
	}
}

// Loop runs reconciliation passes until ctx is done. Blocks; intended for a dedicated goroutine. First pass fires immediately so a
// just-started server doesn't wait a full interval to clean a pre-existing DB.
func (r *ProcessTTLRunner) Loop(ctx context.Context) {
	if r.maxAge == 0 {
		r.logger.InfoContext(ctx, "process-ttl reconciliation disabled", "edr.process.ttl_seconds", 0)
		return
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	if _, err := r.Run(ctx); err != nil {
		r.logger.WarnContext(ctx, "process-ttl initial run failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.Run(ctx); err != nil {
				r.logger.WarnContext(ctx, "process-ttl run failed", "err", err)
			}
		}
	}
}

// Run executes one reconciliation pass and returns rows reconciled.
func (r *ProcessTTLRunner) Run(ctx context.Context) (int64, error) {
	if r.maxAge == 0 {
		return 0, nil
	}
	nowNs := r.now().UnixNano()
	maxAgeNs := r.maxAge.Nanoseconds()
	cutoffNs := nowNs - maxAgeNs

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.Int64("edr.process.ttl_ns", maxAgeNs),
		attribute.Int64("edr.process.ttl_cutoff_ns", cutoffNs),
	)

	n, err := r.store.ReconcileStaleProcesses(ctx, cutoffNs, maxAgeNs)
	if err != nil {
		return 0, fmt.Errorf("reconcile: %w", err)
	}

	span.SetAttributes(attribute.Int64("edr.process.ttl_reconciled", n))
	if r.metrics != nil {
		r.metrics.ProcessesTTLReconciled(ctx, n)
	}
	if n > 0 {
		r.logger.InfoContext(ctx, "process-ttl reconciliation",
			"edr.process.ttl_ns", maxAgeNs,
			"edr.process.ttl_cutoff_ns", cutoffNs,
			"edr.process.ttl_reconciled", n,
		)
	}
	return n, nil
}
