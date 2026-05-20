package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePinger implements xpcPinger for tests. Configure pingFn to control
// per-call behaviour; count tracks how many times Ping has been invoked.
type fakePinger struct {
	count  atomic.Int64
	pingFn func(timeout time.Duration) error
}

func (f *fakePinger) Ping(timeout time.Duration) error {
	f.count.Add(1)
	if f.pingFn != nil {
		return f.pingFn(timeout)
	}
	return nil
}

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestRunXPCHeartbeat(t *testing.T) {
	t.Parallel()

	t.Run("exits on done close without signalling failed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		pinger := &fakePinger{}
		done := make(chan struct{})
		failed := make(chan struct{}, 1)

		// Use a long interval so no tick fires; we rely on done to exit.
		doneCh := make(chan struct{})
		go func() {
			runXPCHeartbeat(ctx, newDiscardLogger(), pinger, xpcHeartbeatConfig{
				XPCService:  "svc",
				Interval:    time.Hour,
				PingTimeout: time.Second,
				Done:        done,
				Failed:      failed,
			})
			close(doneCh)
		}()

		close(done)
		select {
		case <-doneCh:
		case <-time.After(time.Second):
			t.Fatal("runXPCHeartbeat did not exit after done was closed")
		}

		assert.Equal(t, int64(0), pinger.count.Load(), "ping must not fire when no tick elapsed")
		assert.Empty(t, failed, "failed must not be signalled on clean exit")
	})

	t.Run("exits on ctx cancel without signalling failed", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		pinger := &fakePinger{}
		done := make(chan struct{})
		defer close(done)
		failed := make(chan struct{}, 1)

		doneCh := make(chan struct{})
		go func() {
			runXPCHeartbeat(ctx, newDiscardLogger(), pinger, xpcHeartbeatConfig{
				XPCService:  "svc",
				Interval:    time.Hour,
				PingTimeout: time.Second,
				Done:        done,
				Failed:      failed,
			})
			close(doneCh)
		}()

		cancel()
		select {
		case <-doneCh:
		case <-time.After(time.Second):
			t.Fatal("runXPCHeartbeat did not exit after ctx cancel")
		}

		assert.Empty(t, failed, "failed must not be signalled on ctx cancel")
	})

	t.Run("ping success keeps heartbeat alive across multiple ticks", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		pinger := &fakePinger{pingFn: func(time.Duration) error { return nil }}
		done := make(chan struct{})
		failed := make(chan struct{}, 1)

		// Short interval so several ticks fire before we close done.
		doneCh := make(chan struct{})
		go func() {
			runXPCHeartbeat(ctx, newDiscardLogger(), pinger, xpcHeartbeatConfig{
				XPCService:  "svc",
				Interval:    10 * time.Millisecond,
				PingTimeout: time.Second,
				Done:        done,
				Failed:      failed,
			})
			close(doneCh)
		}()

		require.Eventually(t, func() bool { return pinger.count.Load() >= 3 }, time.Second, 5*time.Millisecond,
			"expected at least 3 pings while channel was healthy")
		close(done)
		select {
		case <-doneCh:
		case <-time.After(time.Second):
			t.Fatal("runXPCHeartbeat did not exit after done close")
		}
		assert.Empty(t, failed, "failed must not be signalled while pings succeed")
	})

	t.Run("first ping failure signals failed and exits", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		pinger := &fakePinger{pingFn: func(time.Duration) error { return errors.New("boom") }}
		done := make(chan struct{})
		defer close(done)
		failed := make(chan struct{}, 1)

		doneCh := make(chan struct{})
		go func() {
			runXPCHeartbeat(ctx, newDiscardLogger(), pinger, xpcHeartbeatConfig{
				XPCService:  "svc",
				Interval:    10 * time.Millisecond,
				PingTimeout: time.Second,
				Done:        done,
				Failed:      failed,
			})
			close(doneCh)
		}()

		select {
		case <-failed:
		case <-time.After(time.Second):
			t.Fatal("expected failed signal after first ping failure")
		}
		select {
		case <-doneCh:
		case <-time.After(time.Second):
			t.Fatal("heartbeat goroutine did not exit after failure signal")
		}
		assert.Equal(t, int64(1), pinger.count.Load(), "expected exactly one ping attempt before exit")
	})

	t.Run("failed channel full does not deadlock", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		pinger := &fakePinger{pingFn: func(time.Duration) error { return errors.New("boom") }}
		done := make(chan struct{})
		defer close(done)
		// Pre-fill failed so the non-blocking send drops.
		failed := make(chan struct{}, 1)
		failed <- struct{}{}

		doneCh := make(chan struct{})
		go func() {
			runXPCHeartbeat(ctx, newDiscardLogger(), pinger, xpcHeartbeatConfig{
				XPCService:  "svc",
				Interval:    10 * time.Millisecond,
				PingTimeout: time.Second,
				Done:        done,
				Failed:      failed,
			})
			close(doneCh)
		}()

		select {
		case <-doneCh:
		case <-time.After(time.Second):
			t.Fatal("heartbeat goroutine must not block when failed channel is full")
		}
	})
}
