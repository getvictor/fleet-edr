// Package processor polls for unprocessed events and feeds them through the
// graph builder. It decouples event ingestion from graph materialization so
// that the write path (ingest) can run independently of the processing path.
package processor

import (
	"context"
	"log/slog"
	"time"

	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

// Processor polls for unprocessed events and runs them through the graph builder.
type Processor struct {
	store    *store.Store
	builder  *graph.Builder
	logger   *slog.Logger
	interval time.Duration
	batch    int
}

// New creates a Processor with the given poll interval and batch size.
func New(s *store.Store, builder *graph.Builder, logger *slog.Logger, interval time.Duration, batchSize int) *Processor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Processor{
		store:    s,
		builder:  builder,
		logger:   logger,
		interval: interval,
		batch:    batchSize,
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
	events, err := p.store.FetchUnprocessed(ctx, p.batch)
	if err != nil {
		p.logger.ErrorContext(ctx, "fetch unprocessed events", "err", err)
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
		// Unclaim events so they can be retried in a future cycle.
		if unclaimErr := p.store.UnclaimEvents(ctx, eventIDs); unclaimErr != nil {
			p.logger.ErrorContext(ctx, "unclaim events after builder failure", "err", unclaimErr)
		}
		return
	}

	if err := p.store.MarkProcessed(ctx, eventIDs); err != nil {
		p.logger.ErrorContext(ctx, "mark events processed", "err", err)
	}
}
