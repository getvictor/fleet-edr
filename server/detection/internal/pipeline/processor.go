package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/fleetdm/edr/server/detection/internal/engine"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// Processor claims events from the visibility EventLog work queue and runs them through the graph builder, then evaluates detection
// rules over the same batch. Decouples event ingestion from graph materialization so the write path (intake) runs independently of the
// processing path. Post-cutover (ADR-0015) the queue is the only work source; the durable archive is read-only correlation storage.
type Processor struct {
	eventLog    visibilityapi.EventLog
	builder     *graph.Builder
	detection   *engine.Engine
	logger      *slog.Logger
	interval    time.Duration
	batch       int
	concurrency int
}

// NewProcessor creates a Processor that claims from the given EventLog with the given poll interval and batch size. concurrency is
// the number of in-process workers that claim disjoint batches via SKIP LOCKED (issue #535); a value <= 1 runs a single worker, the
// historical behaviour. The workers share this Processor's builder and engine, both of which are safe under concurrent batches (the
// graph builder serialises its cross-batch exit buffer, and rule evaluation is read-then-dedup-insert).
func NewProcessor(
	eventLog visibilityapi.EventLog,
	builder *graph.Builder,
	det *engine.Engine,
	logger *slog.Logger,
	interval time.Duration,
	batchSize int,
	concurrency int,
) *Processor {
	if logger == nil {
		logger = slog.Default()
	}
	if concurrency < 1 {
		concurrency = 1
	}
	// A non-positive batch size would make the drain loop (`for processOnce(ctx) >= p.batch`) spin: an empty claim returns 0 and
	// 0 >= 0 stays true forever. Clamp to at least 1 so an empty queue always breaks the drain and yields back to the ticker.
	if batchSize < 1 {
		batchSize = 1
	}
	return &Processor{
		eventLog:    eventLog,
		builder:     builder,
		detection:   det,
		logger:      logger,
		interval:    interval,
		batch:       batchSize,
		concurrency: concurrency,
	}
}

// Run fans out p.concurrency worker loops and blocks until ctx is cancelled and every worker returns. Each worker claims its own
// disjoint batches, so the processor scales across the replica's cores the same way it scales across replicas (server-availability spec).
func (p *Processor) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for range p.concurrency {
		wg.Go(func() {
			p.runWorker(ctx)
		})
	}
	wg.Wait()
	return nil
}

// runWorker is one claim loop. On each tick it drains: while a cycle returns a full batch there is likely more backlog, so it claims
// again immediately rather than waiting a full interval, which lets the worker fleet work a backlog down quickly. A non-full cycle
// (empty, or a nacked failure) yields back to the ticker so a persistently failing batch cannot hot-spin.
func (p *Processor) runWorker(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for p.processOnce(ctx) >= p.batch {
				if ctx.Err() != nil {
					return
				}
			}
		}
	}
}

// ProcessOnce runs a single processing cycle. Exported for testing.
func (p *Processor) ProcessOnce(ctx context.Context) {
	p.processOnce(ctx)
}

// processOnce claims and processes one batch, returning the number of events claimed (0 on an empty queue, a claim error, or a
// builder/detection failure that nacked the batch). The count lets runWorker decide whether to keep draining.
func (p *Processor) processOnce(ctx context.Context) int {
	events, err := p.eventLog.Claim(ctx, p.batch)
	if err != nil {
		p.logger.ErrorContext(ctx, "claim events", "err", err)
		return 0
	}
	if len(events) == 0 {
		return 0
	}

	eventIDs := make([]string, len(events))
	for i, e := range events {
		eventIDs[i] = e.EventID
	}

	if err := p.builder.ProcessBatch(ctx, events); err != nil {
		p.logger.WarnContext(ctx, "graph builder failure, will retry batch", "err", err)
		if nackErr := p.eventLog.Nack(ctx, eventIDs); nackErr != nil {
			p.logger.ErrorContext(ctx, "nack events after builder failure", "err", nackErr)
		}
		return 0 // nacked: stop draining so a persistently failing batch cannot hot-spin
	}

	// Run detection rules after processes are materialized.
	if p.detection != nil {
		if err := p.detection.Evaluate(ctx, events); err != nil {
			p.logger.WarnContext(ctx, "detection failure, will retry batch", "err", err)
			if nackErr := p.eventLog.Nack(ctx, eventIDs); nackErr != nil {
				p.logger.ErrorContext(ctx, "nack events after detection failure", "err", nackErr)
			}
			return 0
		}
	}

	if err := p.eventLog.Ack(ctx, eventIDs); err != nil {
		// The batch processed but the queue was not durably advanced (the rows stay leased until the claim lease expires).
		// Returning 0 stops the drain loop so the worker waits for the next tick rather than treating this as a full-batch
		// drain and immediately re-claiming, which would spread a transient ack outage into a tight re-processing loop.
		p.logger.ErrorContext(ctx, "ack events", "err", err)
		return 0
	}
	return len(events)
}
