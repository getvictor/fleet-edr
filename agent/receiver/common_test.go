package receiver

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spec:agent-xpc-receiver/events-flow-into-the-queue-without-blocking-the-receiver/downstream-consumer-falls-behind
//
// Pins the receiver's drop-and-warn contract for a slow downstream consumer: when the events channel is full,
// tryDeliverEvent MUST NOT block (so the XPC kernel callback returns promptly and the receiver continues reading
// subsequent events), MUST drop the affected event, and MUST emit a warning identifying the affected service so
// operators see the loss in SigNoz. The production CGo onEvent callback (receiver.go) delegates to this helper so
// the test exercises exactly the production drop path without standing up a Mach service.
func TestTryDeliverEvent_DropsAndWarnsOnFullChannel(t *testing.T) {
	// Reset the package logger after the test so concurrent tests don't see our buffer logger.
	prev := logger.Load()
	t.Cleanup(func() { logger.Store(prev) })

	// Reset the shared drop reporter so a prior test's drops on the same service name don't suppress this test's warning.
	prevDrops := drops
	drops = newDropReporter()
	t.Cleanup(func() { drops = prevDrops })

	// Capture warn-level output to assert on the log line. A bytes.Buffer + mutex is enough since the test drives tryDeliverEvent
	// synchronously from a single goroutine; the lock is defensive against a future test that runs the helper concurrently.
	var (
		mu  sync.Mutex
		buf bytes.Buffer
	)
	lockedWriter := &mutexWriter{w: &buf, mu: &mu}
	SetLogger(slog.New(slog.NewTextHandler(lockedWriter, &slog.HandlerOptions{Level: slog.LevelDebug})))

	// Buffer of 1 so the second send fills the channel and the third tryDeliverEvent call hits the drop branch.
	ch := make(chan Event, 1)
	first := Event{Data: []byte("first")}
	dropped := Event{Data: []byte("dropped")}

	tryDeliverEvent(ch, first, "svc-xpc")
	// Channel now full. The next call MUST drop without blocking. If the implementation regressed to a blocking send, the test
	// would otherwise deadlock until go test's package-level timeout (default 10m). Use a tight time.After timeout so a regression
	// fails the test in a second instead of hanging the suite.
	done := make(chan struct{})
	go func() {
		tryDeliverEvent(ch, dropped, "svc-xpc")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tryDeliverEvent did not return within 1s on a full channel; non-blocking contract regressed")
	}

	// Surviving event in the channel is the first one; the dropped one was discarded.
	got := <-ch
	assert.Equal(t, "first", string(got.Data), "dropped event MUST not displace the in-flight one")

	mu.Lock()
	logged := buf.String()
	mu.Unlock()
	assert.Contains(t, logged, "receiver event channel full",
		"the drop branch MUST emit a warning so operators detect the condition")
	assert.Contains(t, logged, "svc-xpc",
		"the warning MUST identify the affected service so multi-loop deployments can attribute the loss")
	assert.Contains(t, logged, "dropped=1",
		"the warning MUST carry the dropped-event count; the first drop accounts for exactly one event")

	// The receiver continues reading: a fresh send (after the test drained `first`) succeeds.
	next := Event{Data: []byte("next")}
	tryDeliverEvent(ch, next, "svc-xpc")
	got = <-ch
	assert.Equal(t, "next", string(got.Data), "after a drop, the receiver MUST keep accepting subsequent events")
}

// Happy-path companion: when the channel has space, tryDeliverEvent delivers the event and emits no warning. Pins the "no spurious
// log lines under steady-state load" half of the contract; a regression that logged on every successful delivery would surface here.
func TestTryDeliverEvent_DeliversWhenChannelHasSpace(t *testing.T) {
	prev := logger.Load()
	t.Cleanup(func() { logger.Store(prev) })

	var (
		mu  sync.Mutex
		buf bytes.Buffer
	)
	SetLogger(slog.New(slog.NewTextHandler(&mutexWriter{w: &buf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelDebug})))

	ch := make(chan Event, 4)
	for _, b := range [][]byte{[]byte("a"), []byte("b"), []byte("c")} {
		tryDeliverEvent(ch, Event{Data: b}, "svc-xpc")
	}
	require.Len(t, ch, 3, "three sends MUST land when the channel has room")

	mu.Lock()
	logged := buf.String()
	mu.Unlock()
	assert.NotContains(t, logged, "channel full", "no warning on the happy path")
}

// spec:agent-xpc-receiver/events-flow-into-the-queue-without-blocking-the-receiver/sustained-drops-are-coalesced-into-a-throttled-summary
//
// Pins the rate-limiting half of the drop-and-warn contract: a sustained overflow MUST NOT emit one warning per dropped event
// (which floods the agent log when a slow consumer falls behind). The first drop after a quiet period warns immediately so the
// onset is visible; further drops within dropWarnInterval are counted and folded into the next summary, which carries the
// accumulated dropped-event count. Driven through dropReporter with a fake clock so the window boundary is deterministic.
func TestDropReporter_CoalescesSustainedDrops(t *testing.T) {
	now := time.Unix(0, 0)
	r := newDropReporter()
	r.now = func() time.Time { return now }

	// First drop for the service: emits immediately, accounting for exactly one event.
	count, emit := r.record("svc-xpc")
	require.True(t, emit, "the first drop after a quiet period MUST warn immediately so operators see the onset")
	assert.Equal(t, int64(1), count, "the first warning accounts for the single drop seen so far")

	// A burst of further drops inside the interval is suppressed, not logged one-per-event.
	for range 999 {
		count, emit = r.record("svc-xpc")
		assert.False(t, emit, "drops within dropWarnInterval MUST be suppressed to avoid flooding the log")
		assert.Zero(t, count, "a suppressed drop reports no count")
	}

	// Crossing the interval boundary emits a single summary carrying every suppressed drop plus the boundary drop.
	now = now.Add(dropWarnInterval)
	count, emit = r.record("svc-xpc")
	require.True(t, emit, "the first drop after the interval MUST emit an aggregated summary")
	assert.Equal(t, int64(1000), count, "the summary MUST account for all drops suppressed since the previous warning")

	// A different service tracks its own window: its first drop warns independently of svc-xpc's throttle.
	count, emit = r.record("svc-net")
	require.True(t, emit, "a distinct service MUST warn on its own first drop, not share another service's throttle")
	assert.Equal(t, int64(1), count)
}

// mutexWriter serialises Write calls so the slog text handler doesn't interleave records when multiple goroutines log into the same
// buffer. Used by the drop test to keep the captured log deterministic across the helper's non-blocking send + the test's drain.
type mutexWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (m *mutexWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.w.Write(p)
}
