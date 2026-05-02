package pipeline

import (
	"context"
	"sync"

	"github.com/jmoiron/sqlx"
)

// Runner composes the three background goroutines that the detection
// context owns: processor (event materialisation + rule evaluation),
// processttl (stale-process janitor), and retention (event purge).
//
// One Run(ctx) call fans them out under a shared WaitGroup; each loop
// honours ctx cancellation independently. Run returns when all three
// have returned.
type Runner struct {
	processor  *Processor
	processTTL *ProcessTTLRunner
	retention  *RetentionRunner
}

// RunnerOptions bundles what the Runner needs from its callers.
type RunnerOptions struct {
	Processor  *Processor
	ProcessTTL *ProcessTTLRunner
	Retention  *RetentionRunner
	DB         *sqlx.DB
}

// NewRunner builds a Runner. Any of the three component pointers may
// be nil to disable that loop (e.g. ModeIntake disables all three).
func NewRunner(opts RunnerOptions) *Runner {
	return &Runner{
		processor:  opts.Processor,
		processTTL: opts.ProcessTTL,
		retention:  opts.Retention,
	}
}

// Run launches the three loops and blocks until ctx is cancelled and
// every loop returns. Each loop logs its own errors; a single
// goroutine panic recovers via slog.Default per goroutine.
func (r *Runner) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	if r.processor != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.processor.Run(ctx)
		}()
	}
	if r.processTTL != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.processTTL.Loop(ctx)
		}()
	}
	if r.retention != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.retention.Loop(ctx)
		}()
	}
	wg.Wait()
	return nil
}
