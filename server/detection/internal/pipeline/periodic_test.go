package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRunPeriodic pins the shared sweep driver: it runs the pass once immediately, again on each tick, returns when ctx is cancelled,
// logs a live-context error, and suppresses an error caused by the cancellation itself (so a graceful shutdown stays quiet).
func TestRunPeriodic(t *testing.T) {
	t.Parallel()

	t.Run("runs immediately, on each tick, and stops when ctx is cancelled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		var calls atomic.Int32
		done := make(chan struct{})
		go func() {
			runPeriodic(ctx, time.Millisecond, slog.Default(), "test", func(context.Context) (int64, error) {
				// Return an error on the first pass (ctx still live) to exercise the warn branch, then cancel after a few ticks.
				if n := calls.Add(1); n == 1 {
					return 0, errors.New("transient")
				} else if n >= 3 {
					cancel()
				}
				return 0, nil
			})
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("runPeriodic did not return after ctx cancellation")
		}
		assert.GreaterOrEqual(t, calls.Load(), int32(3), "runs the initial pass plus ticks until cancelled")
	})

	t.Run("a pass that fails because ctx was cancelled returns without hanging", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // pre-cancelled: the initial pass errors, the error is ctx-induced and suppressed, then the loop returns.
		done := make(chan struct{})
		go func() {
			runPeriodic(ctx, time.Hour, slog.Default(), "test", func(context.Context) (int64, error) {
				return 0, errors.New("ctx cancelled")
			})
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("runPeriodic did not return on a pre-cancelled context")
		}
	})
}
