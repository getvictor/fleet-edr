package pipeline

import (
	"context"
	"sync"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/coordination/leader"
	"github.com/fleetdm/edr/server/detection/api"
)

// Lock names for the leader-gated periodic tasks. MySQL GET_LOCK names are server-global, so these identify each task across every
// replica of one deployment (the assumption is one EDR deployment per MySQL server; see the server-availability spec).
const (
	lockProcessTTL = "edr_process_ttl"
	lockRetention  = "edr_retention"
	lockQueuePrune = "edr_queue_prune"
)

// Runner composes the background goroutines that the detection context
// owns: processor (event materialisation + rule evaluation), processttl
// (stale-process janitor), retention (process-record purge), and
// queueprune (acked-event sweep of the visibility work queue).
//
// One Run(ctx) call fans them out under a shared WaitGroup; each loop
// honours ctx cancellation independently. Run returns when all of them
// have returned.
type Runner struct {
	processor       *Processor
	processTTL      *ProcessTTLRunner
	retention       *RetentionRunner
	queuePrune      *QueuePruneRunner
	webhookDelivery *WebhookDeliveryRunner
	coordinator     leader.Coordinator
}

// RunnerOptions bundles what the Runner needs from its callers.
type RunnerOptions struct {
	Processor       *Processor
	ProcessTTL      *ProcessTTLRunner
	Retention       *RetentionRunner
	QueuePrune      *QueuePruneRunner
	WebhookDelivery *WebhookDeliveryRunner
	DB              *sqlx.DB
	// Coordinator gates the single-replica periodic tasks (processTTL + retention) so they run on exactly one replica at a time.
	// Nil disables coordination: the tasks run directly on this process, which is correct for a single-replica deployment and for
	// tests. The processor is never gated: it scales across replicas via SKIP LOCKED.
	Coordinator leader.Coordinator
}

// NewRunner builds a Runner. Any of the three component pointers may
// be nil to disable that loop (e.g. ModeIntake disables all three).
func NewRunner(opts RunnerOptions) *Runner {
	return &Runner{
		processor:       opts.Processor,
		processTTL:      opts.ProcessTTL,
		retention:       opts.Retention,
		queuePrune:      opts.QueuePrune,
		webhookDelivery: opts.WebhookDelivery,
		coordinator:     opts.Coordinator,
	}
}

// SetMetrics propagates the metrics recorder to the processTTL, retention, and queue-prune sweeps (the processor itself doesn't take a
// recorder directly; alert metrics flow through engine.SetMetrics). Called by Detection.SetMetrics.
func (r *Runner) SetMetrics(m api.MetricsRecorder) {
	if r.processTTL != nil {
		r.processTTL.SetMetrics(m)
	}
	if r.retention != nil {
		r.retention.SetMetrics(m)
	}
	if r.queuePrune != nil {
		r.queuePrune.SetMetrics(m)
	}
}

// Run launches the configured loops (processor, process-TTL, retention, queue-prune) and blocks until ctx is cancelled and every loop
// returns. Each loop logs its own errors; a single goroutine panic recovers via slog.Default per goroutine.
func (r *Runner) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	if r.processor != nil {
		// Not leader-gated: the processor claims disjoint event batches via SELECT ... FOR UPDATE SKIP LOCKED, so it scales
		// across every replica rather than running on only one.
		wg.Go(func() {
			_ = r.processor.Run(ctx)
		})
	}
	if r.webhookDelivery != nil {
		// Not leader-gated: the delivery worker leases disjoint outbox rows via SELECT ... FOR UPDATE OF ... SKIP LOCKED, so it
		// scales across replicas the same way the processor does.
		wg.Go(func() {
			r.webhookDelivery.Loop(ctx)
		})
	}
	if r.processTTL != nil {
		wg.Go(func() {
			r.runLeaderGated(ctx, lockProcessTTL, func(ctx context.Context) error {
				r.processTTL.Loop(ctx)
				return nil
			})
		})
	}
	if r.retention != nil {
		wg.Go(func() {
			r.runLeaderGated(ctx, lockRetention, func(ctx context.Context) error {
				r.retention.Loop(ctx)
				return nil
			})
		})
	}
	if r.queuePrune != nil {
		wg.Go(func() {
			r.runLeaderGated(ctx, lockQueuePrune, func(ctx context.Context) error {
				r.queuePrune.Loop(ctx)
				return nil
			})
		})
	}
	wg.Wait()
	return nil
}

// runLeaderGated runs fn under the coordinator so it executes on exactly one replica at a time. With no coordinator wired (single
// replica or tests) it runs fn directly, which is the same behaviour as before leader election existed.
func (r *Runner) runLeaderGated(ctx context.Context, lockName string, fn func(context.Context) error) {
	if r.coordinator == nil {
		_ = fn(ctx)
		return
	}
	_ = r.coordinator.RunIfLeader(ctx, lockName, fn)
}
