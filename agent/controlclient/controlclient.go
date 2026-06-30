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
	// Ledger is the durable dedup store shared with the poll path so a command executed over the stream is not re-executed on a restart
	// or by the poll path after a stream drop (issue #558). Nil disables dedup (tests).
	Ledger commander.Ledger
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
	if maxB <= 0 {
		// Unset: take the default cap.
		maxB = defaultMaxBackoff
	}
	if maxB < initial {
		// Misordered config (max below initial): clamp up to initial so the doubling step still makes forward progress, matching
		// receiver.NewLoop. Replacing it with the 30s default would silently slow reconnects far past what the caller asked for.
		maxB = initial
	}
	return &Client{
		cfg:            cfg,
		executor:       commander.NewExecutor(cfg.ApplicationControlSender, cfg.Ledger, logger),
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
		// Reset the backoff after a session that actually connected, so a long-lived stream that drops retries immediately.
		// Exception: a stream rejected as Unauthenticated "connects" at the gRPC layer and then fails on the first frame, so
		// resetting would spin a ~1s reconnect + re-enrollment storm against an invalid/revoked token. Let the backoff grow in
		// that case so re-enrollment is attempted at the capped cadence instead.
		if connected && status.Code(err) != codes.Unauthenticated {
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
		// The server's auth interceptor can reject the stream during setup, not only on the first Recv; treat an
		// Unauthenticated rejection here the same way so a revoked/expired token still drives re-enrollment.
		if status.Code(err) == codes.Unauthenticated && c.cfg.OnAuthFail != nil {
			c.cfg.OnAuthFail(ctx)
		}
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
			if err := c.handleCommand(ctx, stream, cmd); err != nil {
				// A send failure means the stream is one-way broken (we can still Recv but can no longer report outcomes). Tear it
				// down and reconnect rather than sit "connected" while silently dropping every outcome.
				return true, err
			}
		}
	}
}

// handleCommand executes a pushed command and reports its outcome over the stream. Delivery is at-least-once; the shared executor keys
// execution on the durable command ledger, so a re-delivery of an already-executed command replays its recorded outcome instead of
// re-running the side effect (a non-idempotent kill_process is never re-run), across both transports and across restarts (issue #558).
// A non-nil return is a stream-send failure: the caller must tear the stream down and reconnect, since outcomes can no longer be
// reported on it. A dropped or misrouted command (host mismatch) is not a send failure and returns nil.
func (c *Client) handleCommand(ctx context.Context, stream control.ControlChannel_ConnectClient, pushed *control.Command) error {
	// Defense in depth: the gateway routes a host's commands to that host's stream, but the agent is the last boundary before a
	// privileged side effect (kill_process). If a command's host_id doesn't match this agent's, drop it without executing and
	// without reporting an outcome: any outcome we sent would carry this command's id, which belongs to another host, and could
	// flip that host's command state on the server. A mismatch means a server-side routing bug, so log it loudly. It is not a stream
	// fault, so keep the stream up (return nil).
	if c.cfg.HostID != "" && pushed.GetHostId() != "" && pushed.GetHostId() != c.cfg.HostID {
		c.logger.ErrorContext(ctx, "control channel: dropping command addressed to a different host",
			"cmd_id", pushed.GetId(), "command_type", pushed.GetCommandType())
		return nil
	}
	cmd := commander.Command{
		ID:          pushed.GetId(),
		HostID:      pushed.GetHostId(),
		CommandType: pushed.GetCommandType(),
		Payload:     pushed.GetPayload(),
	}
	// sendErr captures a stream-send failure from inside the executor callback (the executor only logs report errors). The executor
	// dedupes via the shared ledger, replaying a recorded outcome instead of re-running the side effect; either way each report goes
	// through this callback. handleCommand returns the last send error so runStream reconnects on a one-way-broken stream.
	var sendErr error
	c.executor.Execute(ctx, cmd, func(_ context.Context, statusValue string, result json.RawMessage) error {
		sendErr = c.send(stream, cmd.ID, statusValue, result)
		return sendErr
	})
	return sendErr
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
	half := int64(d / 2)
	if half <= 0 {
		// d <= 1ns: rand.Int64N(0) would panic, and there is no meaningful jitter to add at that scale anyway.
		return 0
	}
	//nolint:gosec // G404: reconnect-backoff jitter is timing, not security-sensitive; a weak PRNG is correct here.
	return time.Duration(rand.Int64N(half))
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
