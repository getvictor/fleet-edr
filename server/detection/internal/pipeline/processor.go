package pipeline

import (
	"context"
	"log/slog"
	"time"

	"github.com/fleetdm/edr/server/detection/internal/engine"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// Processor claims events from the visibility EventLog work queue and runs them through the graph builder, then evaluates detection
// rules over the same batch. Decouples event ingestion from graph materialization so the write path (intake) runs independently of the
// processing path. Post-cutover (ADR-0015) the queue is the only work source; the durable archive is read-only correlation storage.
type Processor struct {
	eventLog  visibilityapi.EventLog
	builder   *graph.Builder
	detection *engine.Engine
	logger    *slog.Logger
	interval  time.Duration
	batch     int
}

// NewProcessor creates a Processor that claims from the given EventLog with the given poll interval and batch size.
func NewProcessor(
	eventLog visibilityapi.EventLog,
	builder *graph.Builder,
	det *engine.Engine,
	logger *slog.Logger,
	interval time.Duration,
	batchSize int,
) *Processor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Processor{
		eventLog:  eventLog,
		builder:   builder,
		detection: det,
		logger:    logger,
		interval:  interval,
		batch:     batchSize,
	}
}

// Run polls for unprocessed events until the context is cancelled.
func (p *Processor) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.processOnce(ctx)
		}
	}
}

// ProcessOnce runs a single processing cycle. Exported for testing.
func (p *Processor) ProcessOnce(ctx context.Context) {
	p.processOnce(ctx)
}

func (p *Processor) processOnce(ctx context.Context) {
	events, err := p.eventLog.Claim(ctx, p.batch)
	if err != nil {
		p.logger.ErrorContext(ctx, "claim events", "err", err)
		return
	}
	if len(events) == 0 {
		return
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
		return
	}

	// Run detection rules after processes are materialized.
	if p.detection != nil {
		if err := p.detection.Evaluate(ctx, events); err != nil {
			p.logger.WarnContext(ctx, "detection failure, will retry batch", "err", err)
			if nackErr := p.eventLog.Nack(ctx, eventIDs); nackErr != nil {
				p.logger.ErrorContext(ctx, "nack events after detection failure", "err", nackErr)
			}
			return
		}
	}

	if err := p.eventLog.Ack(ctx, eventIDs); err != nil {
		p.logger.ErrorContext(ctx, "ack events", "err", err)
	}
}
