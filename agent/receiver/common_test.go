package receiver

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"

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
	// Channel now full. The next call MUST drop without blocking - if the implementation regressed to a blocking
	// send, the test would deadlock and fall back to the package-level timeout rather than this assertion.
	done := make(chan struct{})
	go func() {
		tryDeliverEvent(ch, dropped, "svc-xpc")
		close(done)
	}()
	select {
	case <-done:
	case <-context.Background().Done():
		t.Fatal("unreachable: ctx.Background is never done")
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
