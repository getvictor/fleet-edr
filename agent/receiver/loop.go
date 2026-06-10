// Package receiver: Loop owns the reconnect/backoff/heartbeat machinery that
// drives a single XPC service's connection lifecycle. It depends on the
// Connector interface (production: *Receiver, tests: a stub) so the loop
// semantics (exponential backoff, post-success reset, heartbeat-driven
// reconnect, clean shutdown) can be exercised without standing up a real
// Mach service. The agent main wires one Loop per service (ESF + network
// extension) plus a Dispatcher so outbound application_control pushes can
// route to whichever connector is currently active.
//
// This file is build-tag-free: the Loop talks to Connector, never to CGo,
// so the same loop code runs on linux against the non-darwin stub.
package receiver

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

const (
	// defaultInitialBackoff is the first reconnect wait when a connect attempt fails. It doubles on every subsequent failure up to
	// defaultMaxBackoff, then resets to this value after a successful session ends.
	defaultInitialBackoff = time.Second
	// defaultMaxBackoff caps the reconnect wait so a dead peer never produces a multi-minute gap before the next attempt.
	defaultMaxBackoff = 30 * time.Second
	// defaultHeartbeatInterval is the cadence at which the heartbeat goroutine pings the peer to detect a silently-dead XPC channel
	// (issue #178). Tuned alongside defaultHeartbeatTimeout to keep the worst-case detection window safely under the spec's ≤30s bound.
	defaultHeartbeatInterval = 10 * time.Second
	// defaultHeartbeatTimeout is the per-ping wait for a "hello-ack". Aligned with HELLO_ACK_TIMEOUT_NS in agent/xpcbridge/xpc_bridge.c
	// and comfortably above the observed round-trip latency on edr-dev.
	defaultHeartbeatTimeout = 5 * time.Second
)

// Connector represents a single XPC connection's lifecycle. Production code satisfies it with *Receiver; tests pass a deterministic
// stub. The Loop constructs one fresh Connector per reconnect cycle via a ConnectorFactory, so a Connector's Connect / Disconnect
// contract only needs to support one connect followed by one disconnect: re-use across cycles is not required.
type Connector interface {
	Connect() error
	Disconnect()
	Events() <-chan Event
	Errors() <-chan int
	Ping(timeout time.Duration) error
	SendApplicationControl(payload []byte) error
}

// Compile-time check that *Receiver (darwin/cgo build) and the non-darwin stub both satisfy Connector. The stub's Inject method is
// additive and does not affect interface satisfaction.
var _ Connector = (*Receiver)(nil)

// ConnectorFactory builds a fresh Connector for each connect attempt. Each call MUST return a new instance: the Loop will call
// Connect followed by Disconnect on the returned object, then call the factory again for the next reconnect.
type ConnectorFactory func() Connector

// LoopConfig holds the Loop's tunables. Zero-valued fields take the production defaults applied by NewLoop. ServiceName is the
// only required field and is used for log line scoping.
type LoopConfig struct {
	ServiceName       string
	InitialBackoff    time.Duration
	MaxBackoff        time.Duration
	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
}

// LoopHooks lets callers observe lifecycle transitions and override the reconnect-wait clock for tests. All fields are optional;
// nil hooks no-op.
type LoopHooks struct {
	// OnEvent is invoked synchronously from the Loop goroutine for every event the active Connector delivers. Heavy work should be
	// queued so the loop keeps reading the Connector's Events channel without blocking.
	OnEvent func(ctx context.Context, evt Event)

	// OnConnected fires after each successful Connect, before any events are dispatched. Production wires this to Dispatcher.Set
	// so outbound senders route to the live connection.
	OnConnected func(c Connector)

	// OnDisconnected fires immediately before Disconnect, after the connection's event/error select returns. Production wires this
	// to Dispatcher.Clear so outbound sends between disconnect and the next reconnect return an error instead of writing to a dead
	// handle.
	OnDisconnected func()

	// Sleep, when non-nil, replaces the loop's reconnect-wait timer. Tests pass an injected clock so backoff progression is
	// observable without real wall-clock waits. The function returns false if ctx was cancelled during the wait, true if the
	// duration elapsed normally.
	Sleep func(ctx context.Context, d time.Duration) bool
}

// Loop runs a single XPC service's connect/reconnect/event-pump cycle. Build one with NewLoop and call Run(ctx) in its own goroutine.
// Run blocks until ctx is cancelled.
type Loop struct {
	factory ConnectorFactory
	cfg     LoopConfig
	hooks   LoopHooks
	logger  *slog.Logger
}

// NewLoop constructs a Loop. The factory MUST return a fresh Connector per call. A nil logger falls back to slog.Default(). Zero-valued
// config fields take the production defaults: 1s initial backoff, 30s cap, 10s heartbeat interval, 5s heartbeat ping timeout.
func NewLoop(factory ConnectorFactory, cfg LoopConfig, hooks LoopHooks, logger *slog.Logger) *Loop {
	if factory == nil {
		// A nil factory would nil-deref on the first runOnce. Surface the misconfiguration at construction time so the
		// agent fails to start instead of crashing mid-reconnect once XPC actually errors.
		panic("receiver.NewLoop: ConnectorFactory must not be nil")
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = defaultInitialBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.MaxBackoff < cfg.InitialBackoff {
		// A MaxBackoff below InitialBackoff would make the doubling step in Run actively shrink the wait (never reaching
		// the cap) and confuse operators. Clamp to InitialBackoff so the loop still makes forward progress.
		cfg.MaxBackoff = cfg.InitialBackoff
	}
	if cfg.HeartbeatInterval <= 0 {
		// time.NewTicker panics on a non-positive interval. Defaulting here keeps the agent process alive across a
		// misconfigured LoopConfig instead of crashing the receiver goroutine.
		cfg.HeartbeatInterval = defaultHeartbeatInterval
	}
	if cfg.HeartbeatTimeout <= 0 {
		cfg.HeartbeatTimeout = defaultHeartbeatTimeout
	}
	if hooks.Sleep == nil {
		hooks.Sleep = sleepCtx
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Loop{factory: factory, cfg: cfg, hooks: hooks, logger: logger}
}

// Run drives the connect/reconnect cycle until ctx is cancelled. On each iteration it builds a fresh Connector via the factory,
// connects, pumps events until an error / heartbeat-fail / ctx-cancel ends the session, disconnects, and (unless ctx ended) waits for
// the next backoff window before trying again. Failed connect attempts grow the backoff; a successful session resets it to
// InitialBackoff.
func (l *Loop) Run(ctx context.Context) {
	backoff := l.cfg.InitialBackoff
	for ctx.Err() == nil {
		reconnect, connected := l.runOnce(ctx)
		if connected {
			// Successful session: reset the backoff so the next reconnect (if
			// the session ended for some other reason) is fast.
			backoff = l.cfg.InitialBackoff
		}
		if !reconnect {
			return
		}
		retryIn := l.cfg.InitialBackoff
		if !connected {
			// Connection never established: back off exponentially before
			// retrying to avoid a tight reconnect loop against a dead peer.
			retryIn = backoff
			backoff = min(backoff*2, l.cfg.MaxBackoff)
		} else {
			l.logger.InfoContext(ctx, "receiver reconnecting", "service", l.cfg.ServiceName, "retry_in", retryIn)
		}
		if !l.hooks.Sleep(ctx, retryIn) {
			return
		}
	}
}

func (l *Loop) runOnce(ctx context.Context) (reconnect, connected bool) {
	conn := l.factory()
	if err := conn.Connect(); err != nil {
		l.logger.WarnContext(ctx, "receiver connect", "service", l.cfg.ServiceName, "err", err)
		return true, false
	}
	l.logger.InfoContext(ctx, "receiver connected", "service", l.cfg.ServiceName)

	if l.hooks.OnConnected != nil {
		l.hooks.OnConnected(conn)
	}
	reconnect = l.pipeEvents(ctx, conn)
	if l.hooks.OnDisconnected != nil {
		l.hooks.OnDisconnected()
	}
	conn.Disconnect()
	return reconnect, true
}

// pipeEvents reads from the connector's event + error channels and dispatches
// to OnEvent until ctx is cancelled, the connector errors, or the heartbeat
// detects a silently-dead channel. Returns true if the caller should
// reconnect (XPC error or heartbeat failure), false if ctx was cancelled.
//
// The heartbeat goroutine is the agent's positive liveness probe (issue #178)
// for the case where macOS XPC silently routes an open connection to a stale
// Mach port after a system-extension respawn. The defer close(heartbeatDone)
// ensures the heartbeat goroutine doesn't outlive the connector.
func (l *Loop) pipeEvents(ctx context.Context, conn Connector) bool {
	heartbeatDone := make(chan struct{})
	heartbeatFailed := make(chan struct{}, 1)
	go l.runHeartbeat(ctx, conn, heartbeatDone, heartbeatFailed)
	defer close(heartbeatDone)

	// Bind the channels once so the select reads stable references even if the connector swaps internal state under us.
	// More importantly, the two-value receive forms below detect a closed channel: if a Connector implementation ever
	// closes Events / Errors on its way out, we treat that as a reconnect signal instead of either tight-looping on a
	// zero-value Event (Events closed) or treating a synthetic 0 as a real XPC error code (Errors closed).
	eventsCh := conn.Events()
	errorsCh := conn.Errors()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-heartbeatFailed:
			// Heartbeat ping did not get a "hello-ack" within the timeout. The XPC channel is one-way dead even though no error
			// event arrived. Reconnect to bind a fresh Mach port.
			l.logger.WarnContext(ctx, "xpc heartbeat failed, reconnecting", "service", l.cfg.ServiceName)
			return true
		case evt, ok := <-eventsCh:
			if !ok {
				l.logger.WarnContext(ctx, "xpc events channel closed, reconnecting", "service", l.cfg.ServiceName)
				return true
			}
			if l.hooks.OnEvent != nil {
				l.hooks.OnEvent(ctx, evt)
			}
		case errCode, ok := <-errorsCh:
			if !ok {
				l.logger.WarnContext(ctx, "xpc errors channel closed, reconnecting", "service", l.cfg.ServiceName)
				return true
			}
			// All XPC error codes force a reconnect today; the classification is for log fidelity so SigNoz operators can tell
			// expected transient codes apart from unexpected ones at a glance. service is included so concurrent ESF +
			// network-extension loops produce distinguishable log lines.
			l.logger.WarnContext(ctx, "xpc error",
				"service", l.cfg.ServiceName,
				"code", errCode,
				"expected", errCode == ErrorConnectionInvalid ||
					errCode == ErrorConnectionInterrupted ||
					errCode == ErrorTerminated)
			return true
		}
	}
}

// runHeartbeat periodically pings the connector to detect a silently-dead channel. On ping failure or context cancellation the
// goroutine exits; on failure it also signals failed once so pipeEvents can trigger a reconnect. done is closed by pipeEvents when
// it returns, ensuring this goroutine does not outlive its connector.
func (l *Loop) runHeartbeat(ctx context.Context, conn Connector, done <-chan struct{}, failed chan<- struct{}) {
	ticker := time.NewTicker(l.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			if err := conn.Ping(l.cfg.HeartbeatTimeout); err != nil {
				l.logger.WarnContext(ctx, "xpc heartbeat ping failed", "service", l.cfg.ServiceName, "err", err)
				select {
				case failed <- struct{}{}:
				default:
				}
				return
			}
		}
	}
}

// sleepCtx is the production Sleep hook: a real-time wait with context
// cancellation. Tests override this with a deterministic stub.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Dispatcher publishes the Loop's currently active Connector so outbound
// senders (e.g. the commander's application_control push) can route to a
// live connection. Between Clear and the next Set the dispatcher returns
// ErrNoConnector so the caller can mark the command as failed and let the
// server's next policy fan-out reconverge the agent.
//
// Storage uses atomic.Pointer over an immutable box so the SendApplicationControl
// hot path stays lock-free even when the Loop is mid-reconnect.
type Dispatcher struct {
	cur atomic.Pointer[dispatcherBox]
}

type dispatcherBox struct {
	c Connector
}

// NewDispatcher returns a fresh Dispatcher with no Connector published.
func NewDispatcher() *Dispatcher { return &Dispatcher{} }

// ErrNoConnector is returned by SendApplicationControl when no Connector is currently published. This is the expected error during
// reconnect windows; callers should treat the command as failed and let the server retry.
var ErrNoConnector = errors.New("receiver dispatcher: no connector published")

// Set publishes c as the active Connector. Safe to call concurrently with SendApplicationControl. Wire this to LoopHooks.OnConnected
// so the dispatcher always reflects the Loop's current state.
func (d *Dispatcher) Set(c Connector) {
	d.cur.Store(&dispatcherBox{c: c})
}

// Clear unpublishes the active Connector. Wire this to LoopHooks.OnDisconnected so SendApplicationControl returns ErrNoConnector
// between connect cycles instead of writing to a dead handle.
func (d *Dispatcher) Clear() {
	d.cur.Store(nil)
}

// SendApplicationControl satisfies commander.ApplicationControlSender. Returns ErrNoConnector when no Connector is published;
// otherwise forwards to the active Connector. Lock-free read of d.cur means this stays cheap even when the Loop is mid-reconnect.
func (d *Dispatcher) SendApplicationControl(payload []byte) error {
	b := d.cur.Load()
	if b == nil || b.c == nil {
		return ErrNoConnector
	}
	return b.c.SendApplicationControl(payload)
}
