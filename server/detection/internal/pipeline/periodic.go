package pipeline

import (
	"context"
	"log/slog"
	"time"
)

// runPeriodic runs fn once immediately and then every interval until ctx is cancelled, logging a warning when a run returns an error.
// The retention, process-TTL, and queue-prune sweeps share this driver: each is a "do one pass, sleep, repeat" loop whose only
// differences are the interval, the log label, and the pass itself, so the ticker plumbing lives here once rather than copied per
// runner. The pass returns a count the driver ignores (the runner records it); only the error reaches the log. A run that fails
// because ctx was cancelled (a graceful shutdown mid-pass) is not logged: that error is expected, not a fault, so we suppress it to
// keep shutdown quiet.
func runPeriodic(ctx context.Context, interval time.Duration, logger *slog.Logger, name string, fn func(context.Context) (int64, error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	if _, err := fn(ctx); err != nil && ctx.Err() == nil {
		logger.WarnContext(ctx, name+" initial run failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := fn(ctx); err != nil && ctx.Err() == nil {
				logger.WarnContext(ctx, name+" run failed", "err", err)
			}
		}
	}
}
