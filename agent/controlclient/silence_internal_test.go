package controlclient

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/control"
)

// The silence watchdog is what tears down a stream the server has forgotten, and its decision is a subtraction of two clock
// reads. Tested here rather than through the gRPC client, because through the client both operands move on their own goroutines
// and the assertion becomes a bet on the scheduler: that is what made TestAHeartbeatingStreamIsLeftAlone flaky (issue #834). With
// the clock and the frame stamp both driven by the test, the two directions of the decision are decided by arithmetic.

// controlledClock returns whatever the test last set. Read from the watchdog goroutine, written from the test, so it locks.
type controlledClock struct {
	mu sync.Mutex
	at time.Time
}

func newControlledClock() *controlledClock {
	return &controlledClock{at: time.Unix(0, 0)}
}

func (c *controlledClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *controlledClock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
}

// watchdogUnderTest starts watchSilence against a controlled clock and reports whether it has cancelled.
func watchdogUnderTest(t *testing.T, deadline time.Duration) (clock *controlledClock, lastFrame *atomic.Int64, cancelled func() bool) {
	t.Helper()
	clock = newControlledClock()
	c := &Client{
		logger:          slog.New(slog.DiscardHandler),
		silenceDeadline: deadline,
		now:             clock.Now,
	}
	var torn atomic.Bool
	lastFrame = &atomic.Int64{}
	lastFrame.Store(clock.Now().UnixNano())

	ctx, stop := context.WithCancel(t.Context())
	t.Cleanup(stop)
	go c.watchSilence(ctx, lastFrame, func() { torn.Store(true) })
	return clock, lastFrame, torn.Load
}

// TestWatchSilenceLeavesAHeartbeatingStreamAlone is the property TestAHeartbeatingStreamIsLeftAlone asserts, decided by
// arithmetic instead of by timing. Each step moves the clock by less than the deadline and moves the frame stamp with it, which
// is what a frame arriving does, so the difference the watchdog subtracts is under the deadline at every instant. The order in
// which the two writes land does not matter: reading the new clock against the old stamp still gives half a deadline.
func TestWatchSilenceLeavesAHeartbeatingStreamAlone(t *testing.T) {
	t.Parallel()
	const deadline = 40 * time.Millisecond
	clock, lastFrame, cancelled := watchdogUnderTest(t, deadline)

	at := time.Unix(0, 0)
	for range 40 {
		at = at.Add(deadline / 2)
		clock.set(at)
		lastFrame.Store(at.UnixNano())
		time.Sleep(deadline / 8) // let the watchdog tick; a slow runner gives it MORE ticks, not a different verdict
	}
	assert.False(t, cancelled(), "a stream whose frames keep arriving must not be torn down, however long it runs")
}

// TestWatchSilenceTearsDownASilentStream is the same decision in the other direction, and it is what keeps the test above from
// passing against a watchdog that never fires at all.
func TestWatchSilenceTearsDownASilentStream(t *testing.T) {
	t.Parallel()
	const deadline = 40 * time.Millisecond
	clock, _, cancelled := watchdogUnderTest(t, deadline)

	// The frame stamp stays where it started while the clock moves past the deadline, which is a stream delivering nothing.
	clock.set(time.Unix(0, 0).Add(deadline * 2))
	require.Eventually(t, cancelled, 2*time.Second, time.Millisecond,
		"a stream silent past its deadline must be torn down so the client reconnects")
}

// TestWatchSilenceHoldsAtExactlyTheDeadline pins which side of the comparison the boundary falls on. The check is `since >=
// deadline`, so a stream silent for exactly the deadline is torn down; one a nanosecond short is not.
func TestWatchSilenceHoldsAtExactlyTheDeadline(t *testing.T) {
	t.Parallel()
	const deadline = 40 * time.Millisecond

	t.Run("one nanosecond short is left alone", func(t *testing.T) {
		t.Parallel()
		clock, _, cancelled := watchdogUnderTest(t, deadline)
		clock.set(time.Unix(0, 0).Add(deadline - 1))
		time.Sleep(deadline) // several ticks at the deadline/4 cadence
		assert.False(t, cancelled())
	})

	t.Run("exactly the deadline tears down", func(t *testing.T) {
		t.Parallel()
		clock, _, cancelled := watchdogUnderTest(t, deadline)
		clock.set(time.Unix(0, 0).Add(deadline))
		require.Eventually(t, cancelled, 2*time.Second, time.Millisecond)
	})
}

// scriptedStream delivers exactly the frames a test hands it, so pumpStream's frame path can be driven a step at a time.
//
// The channel is unbuffered on purpose: a send returns only once Recv has taken the frame, so the test knows the client has the
// frame before it moves the clock again. That is what bounds how far the clock can run ahead of the last stamp.
type scriptedStream struct {
	control.ControlChannel_ConnectClient
	frames chan *control.ServerFrame
}

func (s *scriptedStream) Recv() (*control.ServerFrame, error) {
	frame, ok := <-s.frames
	if !ok {
		return nil, io.EOF
	}
	return frame, nil
}

// TestAFrameRefreshesTheSilenceWatchdog is the WIRING between the two halves: watchSilence measures from a stamp, and pumpStream
// is what moves that stamp when a frame lands. The decision tests above drive the stamp themselves, so they cannot see this, and
// the client-level test cannot either without betting on the scheduler. Here both the clock and the frames are the test's.
//
// The clock moves an eighth of a deadline per frame and a send blocks until Recv takes it, so at most one frame can be in flight
// and the clock can be at most two steps ahead of the last stamp: a quarter of the deadline, against a deadline it would have to
// reach. A stream stamped on every frame therefore never trips, and one that is not trips within eight frames.
func TestAFrameRefreshesTheSilenceWatchdog(t *testing.T) {
	t.Parallel()
	const deadline = 40 * time.Millisecond
	clock := newControlledClock()
	c := &Client{
		logger:          slog.New(slog.DiscardHandler),
		silenceDeadline: deadline,
		now:             clock.Now,
	}

	stream := &scriptedStream{frames: make(chan *control.ServerFrame)}
	var torn atomic.Bool
	ctx, stop := context.WithCancel(t.Context())
	t.Cleanup(stop)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.pumpStream(ctx, stream, func() { torn.Store(true) })
	}()

	at := time.Unix(0, 0)
	for range 20 {
		at = at.Add(deadline / 8)
		clock.set(at)
		stream.frames <- &control.ServerFrame{} // a heartbeat: no command, which is the case the watchdog exists for
		// Paced so the watchdog actually samples: it ticks at a quarter of the deadline, and without this the twenty iterations
		// finish inside one tick and the test proves nothing. The pacing only ever gives it MORE ticks on a slow runner, and the
		// clock moves only when this loop moves it, so extra ticks cannot manufacture silence.
		time.Sleep(deadline / 4)
		require.False(t, torn.Load(), "a stream delivering frames must not be torn down for silence")
	}

	close(stream.frames)
	<-done
	assert.False(t, torn.Load())
}
