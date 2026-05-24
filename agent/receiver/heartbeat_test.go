package receiver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pingerConnector is a Connector stub whose only configured method is Ping - used by the heartbeat-isolation tests below to drive
// runHeartbeat without also exercising the connect / event-pump paths. Methods unrelated to Ping panic so an accidental wider use
// surfaces immediately.
type pingerConnector struct {
	count  atomic.Int64
	pingFn func(timeout time.Duration) error
}

func (p *pingerConnector) Connect() error       { panic("pingerConnector.Connect: unused") }
func (p *pingerConnector) Disconnect()          { panic("pingerConnector.Disconnect: unused") }
func (p *pingerConnector) Events() <-chan Event { panic("pingerConnector.Events: unused") }
func (p *pingerConnector) Errors() <-chan int   { panic("pingerConnector.Errors: unused") }
func (p *pingerConnector) SendApplicationControl(b []byte) error {
	panic("pingerConnector.SendApplicationControl: unused")
}

func (p *pingerConnector) Ping(timeout time.Duration) error {
	p.count.Add(1)
	if p.pingFn != nil {
		return p.pingFn(timeout)
	}
	return nil
}

// newHeartbeatLoop builds a Loop with the supplied interval / timeout and a
// discard logger, just enough for runHeartbeat to be driven in isolation.
func newHeartbeatLoop(interval, timeout time.Duration) *Loop {
	return &Loop{
		cfg: LoopConfig{
			ServiceName:       "svc",
			HeartbeatInterval: interval,
			HeartbeatTimeout:  timeout,
		},
		logger: discardLogger(),
	}
}

// These tests cover the heartbeat goroutine in isolation. They previously lived in agent/cmd/fleet-edr-agent/heartbeat_test.go against
// the standalone runXPCHeartbeat function; the heartbeat moved into Loop.runHeartbeat when the reconnect/backoff/heartbeat machinery
// consolidated into the receiver package.

func TestLoopRunHeartbeat(t *testing.T) {
	t.Parallel()

	t.Run("exits on done close without signalling failed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		pinger := &pingerConnector{}
		done := make(chan struct{})
		failed := make(chan struct{}, 1)
		loop := newHeartbeatLoop(time.Hour, time.Second)

		doneCh := make(chan struct{})
		go func() {
			loop.runHeartbeat(ctx, pinger, done, failed)
			close(doneCh)
		}()

		close(done)
		select {
		case <-doneCh:
		case <-time.After(time.Second):
			t.Fatal("runHeartbeat did not exit after done was closed")
		}
		assert.Equal(t, int64(0), pinger.count.Load(), "ping must not fire when no tick elapsed")
		assert.Empty(t, failed, "failed must not be signalled on clean exit")
	})

	t.Run("exits on ctx cancel without signalling failed", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		pinger := &pingerConnector{}
		done := make(chan struct{})
		defer close(done)
		failed := make(chan struct{}, 1)
		loop := newHeartbeatLoop(time.Hour, time.Second)

		doneCh := make(chan struct{})
		go func() {
			loop.runHeartbeat(ctx, pinger, done, failed)
			close(doneCh)
		}()

		cancel()
		select {
		case <-doneCh:
		case <-time.After(time.Second):
			t.Fatal("runHeartbeat did not exit after ctx cancel")
		}
		assert.Empty(t, failed, "failed must not be signalled on ctx cancel")
	})

	t.Run("ping success keeps heartbeat alive across multiple ticks", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		pinger := &pingerConnector{pingFn: func(time.Duration) error { return nil }}
		done := make(chan struct{})
		failed := make(chan struct{}, 1)
		loop := newHeartbeatLoop(10*time.Millisecond, time.Second)

		doneCh := make(chan struct{})
		go func() {
			loop.runHeartbeat(ctx, pinger, done, failed)
			close(doneCh)
		}()

		require.Eventually(t, func() bool { return pinger.count.Load() >= 3 }, time.Second, 5*time.Millisecond,
			"expected at least 3 pings while channel was healthy")
		close(done)
		select {
		case <-doneCh:
		case <-time.After(time.Second):
			t.Fatal("runHeartbeat did not exit after done close")
		}
		assert.Empty(t, failed, "failed must not be signalled while pings succeed")
	})

	t.Run("first ping failure signals failed and exits", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		pinger := &pingerConnector{pingFn: func(time.Duration) error { return errors.New("boom") }}
		done := make(chan struct{})
		defer close(done)
		failed := make(chan struct{}, 1)
		loop := newHeartbeatLoop(10*time.Millisecond, time.Second)

		doneCh := make(chan struct{})
		go func() {
			loop.runHeartbeat(ctx, pinger, done, failed)
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
		pinger := &pingerConnector{pingFn: func(time.Duration) error { return errors.New("boom") }}
		done := make(chan struct{})
		defer close(done)
		// Pre-fill failed so the non-blocking send drops.
		failed := make(chan struct{}, 1)
		failed <- struct{}{}
		loop := newHeartbeatLoop(10*time.Millisecond, time.Second)

		doneCh := make(chan struct{})
		go func() {
			loop.runHeartbeat(ctx, pinger, done, failed)
			close(doneCh)
		}()

		select {
		case <-doneCh:
		case <-time.After(time.Second):
			t.Fatal("heartbeat goroutine must not block when failed channel is full")
		}
	})
}
