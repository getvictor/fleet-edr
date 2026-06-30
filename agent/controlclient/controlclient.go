// Package controlclient is the agent side of the persistent control channel (issue #477): it holds one gRPC bidirectional stream to the
// server's control gateway, executes pushed commands in real time, and reports their outcomes back over the same stream. It reuses the
// commander's Executor so the push path and the poll path run one execution. When the stream is up it signals the commander to suspend
// polling; when it drops, the agent reconnects with backoff and the commander's poll resumes as the degraded floor.
package controlclient

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/fleetdm/edr/agent/commander"
	"github.com/fleetdm/edr/internal/control"
)

const (
	defaultInitialBackoff = 1 * time.Second
	defaultMaxBackoff     = 30 * time.Second
	// outcomeCacheCapacity bounds the remembered-outcomes map. Commands are infrequent (operator actions), so a small cache covers the
	// re-delivery window; it is a per-agent ephemeral cache, lost on restart.
	outcomeCacheCapacity = 256
)

// Config holds the control client's dependencies.
type Config struct {
	// Client is the gRPC stub over the (pinned-TLS) connection to the server's control gateway.
	Client control.ControlChannelClient
	HostID string
	// TokenFn returns the current host bearer token, read at each (re)connect so a refreshed token is presented. Nil sends no token
	// (the server then rejects the connect, which is the correct failure for an unauthenticated agent).
	TokenFn func() string
	// OnAuthFail is invoked when the server rejects the stream as unauthenticated, so the agent can re-enroll. Nil is allowed.
	OnAuthFail func(ctx context.Context)
	// ApplicationControlSender is the XPC bridge handed to the shared executor; nil means set_application_control commands fail with a
	// clear reason, matching the poll path.
	ApplicationControlSender commander.ApplicationControlSender
	// OnConnectedChange reports stream up (true) / down (false) so the commander can suspend / resume polling. Nil is allowed.
	OnConnectedChange func(bool)
	Logger            *slog.Logger
	// InitialBackoff / MaxBackoff override the reconnect backoff bounds; zero uses the defaults.
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

// Client maintains the persistent control stream.
type Client struct {
	cfg            Config
	executor       *commander.Executor
	outcomes       *outcomeCache
	logger         *slog.Logger
	initialBackoff time.Duration
	maxBackoff     time.Duration
}

// New builds a control Client. Panics if Client is nil (a programming error: there is nothing to stream over).
func New(cfg Config) *Client {
	if cfg.Client == nil {
		panic("controlclient.New: Client must not be nil")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	initial := cfg.InitialBackoff
	if initial <= 0 {
		initial = defaultInitialBackoff
	}
	maxB := cfg.MaxBackoff
	if maxB < initial {
		maxB = defaultMaxBackoff
	}
	return &Client{
		cfg:            cfg,
		executor:       commander.NewExecutor(cfg.ApplicationControlSender, logger),
		outcomes:       newOutcomeCache(outcomeCacheCapacity),
		logger:         logger,
		initialBackoff: initial,
		maxBackoff:     maxB,
	}
}

// Run holds the control stream open, reconnecting with capped exponential backoff (plus jitter, to avoid a fleet-wide reconnect
// stampede) until ctx is cancelled. A backoff resets after any session that actually connected, so a long-lived connection that drops
// retries immediately rather than inheriting a grown delay.
func (c *Client) Run(ctx context.Context) error {
	backoff := c.initialBackoff
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		connected, err := c.runStream(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if connected {
			backoff = c.initialBackoff
		}
		c.logger.WarnContext(ctx, "control channel disconnected; reconnecting", "err", err, "retry_in", backoff)
		if !sleepCtx(ctx, backoff+jitter(backoff)) {
			return ctx.Err()
		}
		backoff = minDuration(backoff*2, c.maxBackoff)
	}
}

// runStream opens one stream and pumps it until it ends. The bool reports whether the stream actually connected (so Run can reset the
// backoff); the error is the disconnect cause.
func (c *Client) runStream(ctx context.Context) (bool, error) {
	sctx := ctx
	if c.cfg.TokenFn != nil {
		if token := c.cfg.TokenFn(); token != "" {
			sctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		}
	}
	stream, err := c.cfg.Client.Connect(sctx)
	if err != nil {
		return false, err
	}
	c.setConnected(true)
	defer c.setConnected(false)
	c.logger.InfoContext(ctx, "control channel connected", "host_id_present", c.cfg.HostID != "")

	for {
		frame, err := stream.Recv()
		if err != nil {
			if status.Code(err) == codes.Unauthenticated && c.cfg.OnAuthFail != nil {
				c.cfg.OnAuthFail(ctx)
			}
			return true, err
		}
		if cmd := frame.GetCommand(); cmd != nil {
			c.handleCommand(ctx, stream, cmd)
		}
	}
}

// handleCommand executes a pushed command and reports its outcome over the stream. Delivery is at-least-once: if the command has
// already been executed (its outcome is cached), the agent re-reports the recorded outcome instead of running the side effect again, so
// a re-delivery after a lost report still drives the command to terminal and a non-idempotent command (kill_process) is never re-run.
func (c *Client) handleCommand(ctx context.Context, stream control.ControlChannel_ConnectClient, pushed *control.Command) {
	cmd := commander.Command{
		ID:          pushed.GetId(),
		HostID:      pushed.GetHostId(),
		CommandType: pushed.GetCommandType(),
		Payload:     pushed.GetPayload(),
	}
	if prior, ok := c.outcomes.get(cmd.ID); ok {
		// Re-delivery of an already-executed command: replay ack + the recorded terminal outcome (no side effect). The ack drives the
		// server out of pending if its earlier ack was lost; an already-acked command makes the server reject the duplicate ack benignly.
		_ = c.send(stream, cmd.ID, commander.StatusAcked, nil)
		_ = c.send(stream, cmd.ID, prior.status, prior.result)
		return
	}
	c.executor.Execute(ctx, cmd, func(_ context.Context, statusValue string, result json.RawMessage) error {
		if statusValue == commander.StatusCompleted || statusValue == commander.StatusFailed {
			c.outcomes.put(cmd.ID, cachedOutcome{status: statusValue, result: result})
		}
		return c.send(stream, cmd.ID, statusValue, result)
	})
}

func (c *Client) send(stream control.ControlChannel_ConnectClient, id int64, statusValue string, result json.RawMessage) error {
	return stream.Send(&control.AgentFrame{Frame: &control.AgentFrame_Outcome{Outcome: &control.Outcome{
		Id:     id,
		Status: statusValue,
		Result: result,
	}}})
}

func (c *Client) setConnected(v bool) {
	if c.cfg.OnConnectedChange != nil {
		c.cfg.OnConnectedChange(v)
	}
}

// cachedOutcome is a remembered terminal outcome for idempotent re-report.
type cachedOutcome struct {
	status string
	result json.RawMessage
}

// outcomeCache is a bounded most-recent map of command id to terminal outcome. Per-agent ephemeral cache, safe to lose on restart (a
// restart's worst case is re-executing a command the server still has pending, which kill_process tolerates as a no-op "no such
// process" and set_application_control tolerates as an idempotent snapshot re-apply).
type outcomeCache struct {
	mu    sync.Mutex
	m     map[int64]cachedOutcome
	order []int64
	cap   int
}

func newOutcomeCache(capacity int) *outcomeCache {
	return &outcomeCache{m: make(map[int64]cachedOutcome, capacity), cap: capacity}
}

func (o *outcomeCache) get(id int64) (cachedOutcome, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	oc, ok := o.m[id]
	return oc, ok
}

func (o *outcomeCache) put(id int64, oc cachedOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, exists := o.m[id]; !exists {
		if len(o.order) >= o.cap {
			oldest := o.order[0]
			o.order = o.order[1:]
			delete(o.m, oldest)
		}
		o.order = append(o.order, id)
	}
	o.m[id] = oc
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	//nolint:gosec // G404: reconnect-backoff jitter is timing, not security-sensitive; a weak PRNG is correct here.
	return time.Duration(rand.Int64N(int64(d / 2)))
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
