package receiver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubConnector is a deterministic Connector for testing the Loop. It
// satisfies the Connector interface without any CGo or XPC dependency.
//
// Behaviour is configured per-call via the script field: stubScripts are
// dequeued in order, one per factory call. Each script controls whether the
// connector's Connect succeeds, what events / errors the connector emits, and
// when (if ever) the script tells the loop's pipeEvents to return by closing
// the connector's error channel or by ctx-cancel.
type stubConnector struct {
	script stubScript

	mu           sync.Mutex
	connected    atomic.Bool
	disconnected atomic.Bool
	pingCalls    atomic.Int64
	sentPayloads [][]byte
	events       chan Event
	errs         chan int
}

// stubScript declares a single connector's lifecycle.
type stubScript struct {
	// connectErr, when non-nil, makes Connect return this error. The Loop will then count the attempt as "never connected" and
	// apply the backoff progression to the next factory call.
	connectErr error

	// pingErr, when non-nil, makes every Ping call return this error. Production wires this into the heartbeat goroutine, which
	// in turn signals the loop to reconnect.
	pingErr error

	// sendErr, when non-nil, makes SendApplicationControl return this error.
	sendErr error

	// onConnect runs immediately after a successful Connect, in a separate goroutine so it can drive events / errors back into
	// the connector without deadlocking the loop. nil is allowed.
	onConnect func(c *stubConnector)
}

func newStubConnector(s stubScript) *stubConnector {
	// Unbuffered channels make emitEvent / emitError synchronization points: a sequential onConnect that emits an event
	// then a terminal error is guaranteed to deliver them in that order to pipeEvents, because the second send cannot
	// start until the first send is paired with a receive. A buffered design lets both sends complete before pipeEvents
	// reaches its select, and Go's select then picks randomly between the two ready channels - which makes any test
	// that asserts "event delivered, then reconnect" intermittently fail on errors-picked-first.
	return &stubConnector{
		script: s,
		events: make(chan Event),
		errs:   make(chan int),
	}
}

func (s *stubConnector) Connect() error {
	if s.script.connectErr != nil {
		return s.script.connectErr
	}
	s.connected.Store(true)
	if s.script.onConnect != nil {
		go s.script.onConnect(s)
	}
	return nil
}

func (s *stubConnector) Disconnect() {
	s.disconnected.Store(true)
}

func (s *stubConnector) Events() <-chan Event { return s.events }
func (s *stubConnector) Errors() <-chan int   { return s.errs }

func (s *stubConnector) Ping(timeout time.Duration) error {
	s.pingCalls.Add(1)
	return s.script.pingErr
}

func (s *stubConnector) SendApplicationControl(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.script.sendErr != nil {
		return s.script.sendErr
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	s.sentPayloads = append(s.sentPayloads, cp)
	return nil
}

func (s *stubConnector) emitEvent(b []byte) { s.events <- Event{Data: b} }
func (s *stubConnector) emitError(code int) { s.errs <- code }

// scriptedFactory returns a ConnectorFactory that hands out the supplied stubScripts in order, one per call, plus a snapshot function
// the test can call to read the built-connector list without racing the factory goroutine. Extra calls past len(scripts) reuse the last
// script: tests rely on this when the loop is expected to keep retrying forever in the steady state.
func scriptedFactory(scripts []stubScript) (ConnectorFactory, func() []*stubConnector) {
	var mu sync.Mutex
	var built []*stubConnector
	idx := 0
	factory := func() Connector {
		mu.Lock()
		defer mu.Unlock()
		var s stubScript
		switch {
		case idx < len(scripts):
			s = scripts[idx]
		default:
			s = scripts[len(scripts)-1]
		}
		idx++
		conn := newStubConnector(s)
		built = append(built, conn)
		return conn
	}
	snapshot := func() []*stubConnector {
		mu.Lock()
		defer mu.Unlock()
		out := make([]*stubConnector, len(built))
		copy(out, built)
		return out
	}
	return factory, snapshot
}

// recordingSleep is a Sleep hook that records every requested duration and returns immediately (the bounded poll never actually waits
// real time). Tests use this to make the loop's backoff progression observable.
type recordingSleep struct {
	mu        sync.Mutex
	durations []time.Duration
	ctxErr    func() error
}

func (r *recordingSleep) Sleep(ctx context.Context, d time.Duration) bool {
	r.mu.Lock()
	r.durations = append(r.durations, d)
	r.mu.Unlock()
	if r.ctxErr != nil {
		if err := r.ctxErr(); err != nil {
			return false
		}
	}
	if ctx.Err() != nil {
		return false
	}
	// Yield so an always-failing-connector test (e.g. TestLoop_TwoParallelLoops_NetworkExtensionDown) doesn't busy-spin
	// the scheduler between iterations. The actual loop semantics under test - that retries occur and that backoff durations
	// are recorded - are unaffected by the yield, but it keeps the test from monopolizing a P thread under -race.
	runtime.Gosched()
	return true
}

func (r *recordingSleep) snapshot() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]time.Duration, len(r.durations))
	copy(out, r.durations)
	return out
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// spec:agent-xpc-receiver/two-parallel-receiver-loops/network-extension-is-down-while-system-extension-is-up
//
// Two Loop instances run side by side. The system-extension service connects and delivers events; the
// network-extension service's connector always fails Connect. The system loop must keep delivering events
// while the network loop keeps retrying - independence of the two loops is the property under test.
func TestLoop_TwoParallelLoops_NetworkExtensionDown(t *testing.T) {
	t.Parallel()

	sysFactory, _ := scriptedFactory([]stubScript{{
		onConnect: func(c *stubConnector) {
			c.emitEvent([]byte(`{"sys":1}`))
			c.emitEvent([]byte(`{"sys":2}`))
		},
	}})
	netFactory, netConns := scriptedFactory([]stubScript{{connectErr: errors.New("network ext down")}})

	sysSeen := make(chan []byte, 4)
	sysSleep := &recordingSleep{}
	netSleep := &recordingSleep{}

	sysLoop := NewLoop(sysFactory, LoopConfig{ServiceName: "sys", HeartbeatInterval: time.Hour, HeartbeatTimeout: time.Second},
		LoopHooks{
			OnEvent: func(ctx context.Context, evt Event) { sysSeen <- evt.Data },
			Sleep:   sysSleep.Sleep,
		}, discardLogger())
	netLoop := NewLoop(netFactory, LoopConfig{ServiceName: "net", HeartbeatInterval: time.Hour, HeartbeatTimeout: time.Second},
		LoopHooks{Sleep: netSleep.Sleep}, discardLogger())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sysDone := make(chan struct{})
	netDone := make(chan struct{})
	go func() { sysLoop.Run(ctx); close(sysDone) }()
	go func() { netLoop.Run(ctx); close(netDone) }()

	require.Equal(t, []byte(`{"sys":1}`), <-sysSeen)
	require.Equal(t, []byte(`{"sys":2}`), <-sysSeen)

	// Net loop should be in the backoff retry cycle; the recordingSleep returns
	// true so the loop keeps spinning. Confirm it tried more than once.
	require.Eventually(t, func() bool { return len(netSleep.snapshot()) >= 3 }, time.Second, 5*time.Millisecond)
	require.GreaterOrEqual(t, len(netConns()), 3, "net loop must retry against a dead peer")

	cancel()
	<-sysDone
	<-netDone
}

// spec:agent-xpc-receiver/two-parallel-receiver-loops/system-extension-restarts-while-network-extension-stays-up
//
// Mirror of the previous test: this time the system-extension cycles connect→error→reconnect while the
// network-extension stays connected the whole time. Property: cycling one loop must not interrupt event
// flow on the other.
func TestLoop_TwoParallelLoops_SystemExtensionRestarts(t *testing.T) {
	t.Parallel()

	netFactory, _ := scriptedFactory([]stubScript{{
		onConnect: func(c *stubConnector) {
			for i := range 5 {
				c.emitEvent([]byte{byte('a' + i)})
			}
		},
	}})

	sysFactory, _ := scriptedFactory([]stubScript{
		{onConnect: func(c *stubConnector) { c.emitEvent([]byte("sys-1")); c.emitError(ErrorTerminated) }},
		{onConnect: func(c *stubConnector) { c.emitEvent([]byte("sys-2")) }},
	})

	netSeen := make(chan []byte, 8)
	sysSeen := make(chan []byte, 4)
	netLoop := NewLoop(netFactory, LoopConfig{ServiceName: "net", HeartbeatInterval: time.Hour, HeartbeatTimeout: time.Second},
		LoopHooks{OnEvent: func(ctx context.Context, evt Event) { netSeen <- evt.Data }, Sleep: (&recordingSleep{}).Sleep},
		discardLogger())
	sysLoop := NewLoop(sysFactory, LoopConfig{ServiceName: "sys", HeartbeatInterval: time.Hour, HeartbeatTimeout: time.Second},
		LoopHooks{OnEvent: func(ctx context.Context, evt Event) { sysSeen <- evt.Data }, Sleep: (&recordingSleep{}).Sleep},
		discardLogger())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	netDone, sysDone := make(chan struct{}), make(chan struct{})
	go func() { netLoop.Run(ctx); close(netDone) }()
	go func() { sysLoop.Run(ctx); close(sysDone) }()

	// Collect 5 net events regardless of the sys cycle.
	for range 5 {
		select {
		case <-netSeen:
		case <-time.After(time.Second):
			t.Fatal("net loop did not deliver event during sys cycle")
		}
	}
	// And both sys events (across the restart boundary).
	require.Equal(t, []byte("sys-1"), <-sysSeen)
	require.Equal(t, []byte("sys-2"), <-sysSeen)

	cancel()
	<-netDone
	<-sysDone
}

// spec:agent-xpc-receiver/exponential-reconnect-backoff/repeated-connection-failures-back-off
//
// All connect attempts fail. The Sleep hook captures the requested durations; after enough attempts the
// progression must be 1s, 2s, 4s, 8s, 16s, 30s, 30s, ... (capped at MaxBackoff). The cap behaviour is part
// of the test so a regression that lets the backoff grow unbounded fails here.
func TestLoop_RepeatedConnectionFailuresBackOff(t *testing.T) {
	t.Parallel()

	factory, _ := scriptedFactory([]stubScript{{connectErr: errors.New("peer down")}})
	sleep := &recordingSleep{}
	sleep.ctxErr = func() error { return nil }

	// Stop the loop after the 7th sleep so the test does not run forever.
	limit := 7
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(t.Context())
	sleep.ctxErr = func() error {
		if len(sleep.snapshot()) >= limit {
			cancel()
		}
		return ctx.Err()
	}

	loop := NewLoop(factory, LoopConfig{
		ServiceName:       "svc",
		InitialBackoff:    time.Second,
		MaxBackoff:        30 * time.Second,
		HeartbeatInterval: time.Hour,
		HeartbeatTimeout:  time.Second,
	}, LoopHooks{Sleep: sleep.Sleep}, discardLogger())
	loop.Run(ctx)

	durations := sleep.snapshot()
	require.GreaterOrEqual(t, len(durations), limit)
	want := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 30 * time.Second, 30 * time.Second,
	}
	for i, expected := range want {
		assert.Equalf(t, expected, durations[i], "backoff step %d", i)
	}
}

// spec:agent-xpc-receiver/exponential-reconnect-backoff/backoff-resets-after-a-successful-connection
//
// Fail twice → success (deliver event + emit error to end the session) → fail again. Verify the backoff
// resets to InitialBackoff after the success, so the post-success failure waits 1s, not the grown value.
func TestLoop_BackoffResetsAfterSuccess(t *testing.T) {
	t.Parallel()

	connectFail := stubScript{connectErr: errors.New("down")}
	connectOnce := stubScript{onConnect: func(c *stubConnector) { c.emitEvent([]byte("ok")); c.emitError(ErrorConnectionInterrupted) }}
	factory, _ := scriptedFactory([]stubScript{connectFail, connectFail, connectOnce, connectFail})

	sleep := &recordingSleep{}
	stopAfter := 4
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(t.Context())
	sleep.ctxErr = func() error {
		if len(sleep.snapshot()) >= stopAfter {
			cancel()
		}
		return ctx.Err()
	}

	seen := make(chan []byte, 1)
	loop := NewLoop(factory, LoopConfig{
		ServiceName:       "svc",
		InitialBackoff:    time.Second,
		MaxBackoff:        30 * time.Second,
		HeartbeatInterval: time.Hour,
		HeartbeatTimeout:  time.Second,
	}, LoopHooks{
		OnEvent: func(ctx context.Context, evt Event) {
			select {
			case seen <- evt.Data:
			default:
			}
		},
		Sleep: sleep.Sleep,
	}, discardLogger())
	loop.Run(ctx)

	require.Equal(t, []byte("ok"), <-seen)
	durations := sleep.snapshot()
	require.GreaterOrEqual(t, len(durations), 4)
	// Two pre-success failures: 1s, 2s. Then the successful session ends - its reconnect retry uses InitialBackoff because the
	// session was connected. Then the next failure starts the backoff sequence over again at InitialBackoff because it follows the
	// connected reset.
	assert.Equal(t, time.Second, durations[0], "first failure")
	assert.Equal(t, 2*time.Second, durations[1], "second failure grows")
	assert.Equal(t, time.Second, durations[2], "post-success reconnect uses InitialBackoff")
	assert.Equal(t, time.Second, durations[3], "post-success failure starts the backoff over")
}

// spec:agent-xpc-receiver/auto-reconnect-after-extension-restart/extension-is-killed-and-respawned
//
// First connector connects, delivers an event, then emits a terminal error. Second connector connects and
// delivers a second event. Without the reconnect, the second event would never be seen.
func TestLoop_AutoReconnectAfterExtensionRestart(t *testing.T) {
	t.Parallel()

	factory, conns := scriptedFactory([]stubScript{
		{onConnect: func(c *stubConnector) { c.emitEvent([]byte("pre")); c.emitError(ErrorTerminated) }},
		{onConnect: func(c *stubConnector) { c.emitEvent([]byte("post")) }},
	})

	seen := make(chan []byte, 2)
	sleep := &recordingSleep{}
	loop := NewLoop(factory, LoopConfig{
		ServiceName:       "svc",
		HeartbeatInterval: time.Hour,
		HeartbeatTimeout:  time.Second,
	}, LoopHooks{
		OnEvent: func(ctx context.Context, evt Event) { seen <- evt.Data },
		Sleep:   sleep.Sleep,
	}, discardLogger())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { loop.Run(ctx); close(done) }()

	require.Equal(t, []byte("pre"), <-seen)
	require.Equal(t, []byte("post"), <-seen)

	cancel()
	<-done
	built := conns()
	require.GreaterOrEqual(t, len(built), 2, "factory should have built at least two connectors")
	assert.True(t, built[0].disconnected.Load(), "first connector must have been disconnected")
}

// spec:agent-xpc-receiver/dropped-events-during-disconnect-are-tolerated/events-occur-during-a-reconnect-window
//
// Connector A delivers event "A1", then terminates. The Loop reconnects to a fresh connector B which
// delivers "B1". The two events the test observes must be exactly {A1, B1}: events generated against A
// after Disconnect are simulated as "dropped during the reconnect window" by simply not emitting them on
// the post-error connector. The property under test is that the Loop tolerates the gap and resumes
// delivery on the new connection - no error path, no panic, no duplicate.
func TestLoop_DroppedEventsDuringDisconnectAreTolerated(t *testing.T) {
	t.Parallel()

	factory, _ := scriptedFactory([]stubScript{
		{onConnect: func(c *stubConnector) {
			c.emitEvent([]byte("A1"))
			// Pretend events were generated here on the peer but lost in the reconnect window - we model the loss by NOT
			// sending them on this connector and NOT sending them on the next either. With unbuffered channels, the
			// emitEvent above already blocked until pipeEvents read A1, so the terminal error below is delivered AFTER
			// the event without needing an explicit handshake.
			c.emitError(ErrorConnectionInterrupted)
		}},
		{onConnect: func(c *stubConnector) { c.emitEvent([]byte("B1")) }},
	})

	seen := make(chan []byte, 4)
	sleep := &recordingSleep{}
	loop := NewLoop(factory, LoopConfig{
		ServiceName:       "svc",
		HeartbeatInterval: time.Hour,
		HeartbeatTimeout:  time.Second,
	}, LoopHooks{
		OnEvent: func(ctx context.Context, evt Event) { seen <- evt.Data },
		Sleep:   sleep.Sleep,
	}, discardLogger())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { loop.Run(ctx); close(done) }()

	assert.Equal(t, []byte("A1"), <-seen)
	assert.Equal(t, []byte("B1"), <-seen)

	cancel()
	<-done
}

// spec:agent-xpc-receiver/outbound-policy-push-routed-to-active-connection/policy-push-during-an-active-connection
//
// While a connection is active, the Dispatcher routes SendApplicationControl to that connector. The test
// publishes a connector via Loop's OnConnected hook (production wiring) and verifies a push lands.
func TestDispatcher_SendDuringActiveConnection(t *testing.T) {
	t.Parallel()

	d := NewDispatcher()
	ready := make(chan struct{})
	factory, conns := scriptedFactory([]stubScript{{onConnect: func(c *stubConnector) { /* stay connected */ }}})

	loop := NewLoop(factory, LoopConfig{ServiceName: "svc", HeartbeatInterval: time.Hour, HeartbeatTimeout: time.Second},
		LoopHooks{
			OnConnected:    func(c Connector) { d.Set(c); close(ready) },
			OnDisconnected: d.Clear,
			Sleep:          (&recordingSleep{}).Sleep,
		}, discardLogger())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { loop.Run(ctx); close(done) }()
	<-ready

	payload := []byte(`{"app":"control","allow":true}`)
	require.NoError(t, d.SendApplicationControl(payload))

	cancel()
	<-done
	built := conns()
	require.GreaterOrEqual(t, len(built), 1)
	built[0].mu.Lock()
	defer built[0].mu.Unlock()
	require.Equal(t, [][]byte{payload}, built[0].sentPayloads)
}

// spec:agent-xpc-receiver/outbound-policy-push-routed-to-active-connection/policy-push-while-disconnected
//
// Before any connector is published - equivalently, between Clear and the next Set during a reconnect
// window - the Dispatcher returns ErrNoConnector so the commander can mark the push as failed and let the
// server's next push reconverge the agent.
func TestDispatcher_SendWhileDisconnected(t *testing.T) {
	t.Parallel()

	d := NewDispatcher()
	err := d.SendApplicationControl([]byte("x"))
	require.ErrorIs(t, err, ErrNoConnector)

	// And after Set + Clear, we should be back to ErrNoConnector.
	c := newStubConnector(stubScript{})
	d.Set(c)
	require.NoError(t, d.SendApplicationControl([]byte("y")))
	d.Clear()
	require.ErrorIs(t, d.SendApplicationControl([]byte("z")), ErrNoConnector)
}

// spec:agent-xpc-receiver/clean-shutdown-on-context-cancellation/agent-receives-sigterm
//
// With a live connection in progress, cancelling the context must make Run return promptly AND the active
// connector's Disconnect must be called so the underlying XPC connection is released.
func TestLoop_CleanShutdownOnContextCancellation(t *testing.T) {
	t.Parallel()

	ready := make(chan struct{})
	factory, conns := scriptedFactory([]stubScript{{onConnect: func(c *stubConnector) { close(ready) }}})
	loop := NewLoop(factory, LoopConfig{ServiceName: "svc", HeartbeatInterval: time.Hour, HeartbeatTimeout: time.Second},
		LoopHooks{Sleep: (&recordingSleep{}).Sleep}, discardLogger())

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { loop.Run(ctx); close(done) }()
	<-ready

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return within 1s of ctx cancel")
	}

	built := conns()
	require.GreaterOrEqual(t, len(built), 1)
	assert.True(t, built[0].disconnected.Load(), "Disconnect must run on shutdown")
}
