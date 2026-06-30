// Package gateway is the server side of the agent control channel: a persistent gRPC bidirectional stream that pushes commands to a
// connected host in real time and carries command outcomes back, replacing the GET /api/commands short-poll (issue #477).
//
// It is embedded in the server binary and lives in the response context (which owns the commands table). The gateway is the one
// sanctioned stateful tier under ADR-0010: it holds live connections and per-connection bookkeeping only, persists nothing durable,
// and a gateway loss just forces affected agents to reconnect (and fall back to the retained poll) with no command loss because all
// command state stays in MySQL.
//
// Routing carries no new messaging system (ADR-0016): each gateway learns of queued work two ways. The fast path delivers a command
// queued on this replica for a locally-held connection immediately (Notify). The 1s watch is the cross-replica floor: it queries the
// commands table for pending rows of locally-connected hosts and pushes them, so a command queued on another replica arrives within
// the watch interval.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/fleetdm/edr/internal/control"
	"github.com/fleetdm/edr/server/attrkeys"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/response/api"
)

// Fixed operational intervals, compiled constants rather than operator knobs (server-configuration spec): the cross-replica command
// watch, the connection-presence last-seen bump, and the per-connection token revocation re-check.
const (
	defaultWatchInterval      = 1 * time.Second
	defaultLivenessInterval   = 30 * time.Second
	defaultRevocationInterval = 5 * time.Second
	// defaultStopGrace bounds the graceful shutdown. Control streams are long-lived and never end on their own, so an unbounded
	// GracefulStop would hang shutdown forever; after this window we force the streams closed and the agents reconnect (and poll).
	defaultStopGrace = 5 * time.Second
	// clientKeepaliveMinTime is the minimum spacing the server tolerates between agent keep-alive PINGs. It must be at most the agent's
	// keep-alive interval (the agent reuses its 15s HTTP/2 ReadIdleTimeout) or the server GOAWAYs the connection with "too_many_pings".
	clientKeepaliveMinTime = 10 * time.Second

	// notifyBuffer bounds the fast-path signal queue. A full buffer is harmless: the 1s watch is the backstop, so a dropped notify just
	// means the command waits up to one watch interval instead of arriving immediately.
	notifyBuffer = 256
)

// CommandSource is the slice of the response service the gateway needs: list a connected host's pending commands (to push) and apply an
// outcome reported over the stream (reusing the unchanged status-transition rules). Satisfied by the response service.
type CommandSource interface {
	ListPendingForHosts(ctx context.Context, hostIDs []string) ([]api.Command, error)
	UpdateStatus(ctx context.Context, req api.UpdateStatusRequest) error
}

// TokenVerifier verifies a presented host bearer token to a host id, doing no database lookup (local signature + expiry + in-memory
// revocation snapshot). Satisfied by the endpoint service; reused so the control channel shares one auth mechanism with the HTTP path.
type TokenVerifier interface {
	VerifyToken(ctx context.Context, token string) (string, error)
}

// Heartbeat advances a host's last-seen time. The gateway calls it on connect and on the liveness cadence so connection presence is
// the host's online truth. Same closure the response poll path already receives (detection's RecordHostSeen).
type Heartbeat func(ctx context.Context, hostID string, at time.Time) error

// Deps are the gateway's construction dependencies.
type Deps struct {
	Source    CommandSource
	Verifier  TokenVerifier
	Heartbeat Heartbeat // optional; nil disables the last-seen bump
	Logger    *slog.Logger
	// TLSConfig, when set, secures the gRPC server with these credentials (the server's TLS 1.3 cert, so the agent reaches the control
	// channel on the same pinned identity as the HTTP path). Nil serves without transport credentials, used only by in-memory tests.
	TLSConfig *tls.Config
}

// Gateway holds the agent control connections and the gRPC server that serves them.
type Gateway struct {
	control.UnimplementedControlChannelServer

	src       CommandSource
	verifier  TokenVerifier
	heartbeat Heartbeat
	logger    *slog.Logger

	reg *registry
	// notifyCh is the fast-path signal queue. Per-replica perf cache, safe to lose: a dropped or lost signal only defers delivery to
	// the next 1s watch tick, and command state lives in MySQL (ADR-0010 control-gateway carve-out).
	notifyCh chan string
	grpc     *grpc.Server

	watchInterval      time.Duration
	livenessInterval   time.Duration
	revocationInterval time.Duration
	stopGrace          time.Duration
}

// New builds a Gateway and its gRPC server (auth stream interceptor + OTel trace propagation over stream metadata). Panics if a
// required dependency is missing, matching the other response constructors.
func New(deps Deps) *Gateway {
	if deps.Source == nil {
		panic("response gateway.New: Source must not be nil")
	}
	if deps.Verifier == nil {
		panic("response gateway.New: Verifier must not be nil")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	g := &Gateway{
		src:                deps.Source,
		verifier:           deps.Verifier,
		heartbeat:          deps.Heartbeat,
		logger:             logger,
		reg:                newRegistry(),
		notifyCh:           make(chan string, notifyBuffer),
		watchInterval:      defaultWatchInterval,
		livenessInterval:   defaultLivenessInterval,
		revocationInterval: defaultRevocationInterval,
		stopGrace:          defaultStopGrace,
	}
	opts := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.StreamInterceptor(g.authInterceptor),
		// Permit the agent's keep-alive PINGs. The agent pings on a short cadence (matching its HTTP/2 half-open detection) to notice a
		// dropped link fast; without this the gRPC default enforcement policy (5-minute floor) GOAWAYs the connection with
		// "too_many_pings", so the control stream churns every minute. MinTime must be at most the agent's ping interval.
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             clientKeepaliveMinTime,
			PermitWithoutStream: true,
		}),
	}
	if deps.TLSConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(deps.TLSConfig)))
	}
	g.grpc = grpc.NewServer(opts...)
	control.RegisterControlChannelServer(g.grpc, g)
	return g
}

// GRPCServer returns the configured gRPC server. Exposed for tests; production uses Serve/Stop.
func (g *Gateway) GRPCServer() *grpc.Server { return g.grpc }

// Serve accepts connections on lis until Stop is called. cmd/main supplies a TCP listener on EDR_CONTROL_ADDR; the gRPC server applies
// the TLS credentials from Deps. grpc.ErrServerStopped is the normal shutdown signal, not an error, so it is mapped to nil; the caller
// only logs genuine serve failures.
func (g *Gateway) Serve(lis net.Listener) error {
	if err := g.grpc.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// Stop drains in-flight RPCs and closes all connections, bounded by stopGrace. Long-lived control streams never end on their own, so a
// plain GracefulStop would block shutdown indefinitely; after the grace window we force them closed. Either way agents reconnect (and
// fall back to polling) against a peer replica rather than hanging the shutdown.
func (g *Gateway) Stop() {
	done := make(chan struct{})
	go func() {
		g.grpc.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(g.stopGrace):
		g.grpc.Stop()
		<-done
	}
}

// Run drives the cross-replica watch and the fast-path notify drain until ctx is cancelled. Both call deliverPending; the watch sweeps
// all connected hosts on a tick, the notify path delivers one host immediately after a local insert.
func (g *Gateway) Run(ctx context.Context) {
	watch := time.NewTicker(g.watchInterval)
	defer watch.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-watch.C:
			g.deliverPending(ctx, g.reg.hostIDs())
		case hostID := <-g.notifyCh:
			g.deliverPending(ctx, []string{hostID})
		}
	}
}

// Notify is the fast path: after a command is queued on this replica, the caller signals the target host so a locally-held connection
// receives it without waiting for the watch tick. Non-blocking; the watch is the backstop if the signal queue is full.
func (g *Gateway) Notify(hostID string) {
	select {
	case g.notifyCh <- hostID:
	default:
	}
}

// deliverPending queries pending commands for the given hosts and pushes each to its connection, skipping commands already in flight.
func (g *Gateway) deliverPending(ctx context.Context, hostIDs []string) {
	if len(hostIDs) == 0 {
		return
	}
	cmds, err := g.src.ListPendingForHosts(ctx, hostIDs)
	if err != nil {
		g.logger.WarnContext(ctx, "control gateway list pending", "err", err)
		return
	}
	for i := range cmds {
		cmd := cmds[i]
		c := g.reg.get(cmd.HostID)
		if c == nil {
			continue
		}
		if !c.markInflight(cmd.ID) {
			continue
		}
		frame := &control.ServerFrame{Frame: &control.ServerFrame_Command{Command: &control.Command{
			Id:          cmd.ID,
			HostId:      cmd.HostID,
			CommandType: cmd.CommandType,
			Payload:     cmd.Payload,
		}}}
		if !c.push(frame) {
			c.clearInflight(cmd.ID) // buffer full: let the next watch tick retry rather than block here
			g.logger.WarnContext(ctx, "control gateway push buffer full; will retry", attrkeys.HostID, cmd.HostID)
		}
	}
}

// Connect implements the gRPC service. The auth interceptor has already verified the token and pinned the host id, so here we register
// the connection, start its writer and maintenance goroutines, push any backlog, and read outcomes until the stream ends.
func (g *Gateway) Connect(stream control.ControlChannel_ConnectServer) error {
	ctx := stream.Context()
	hostID, ok := endpointapi.HostIDFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no host context")
	}
	token, _ := tokenFromContext(ctx)

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := newConn(hostID, token, cancel)

	if evicted := g.reg.add(c); evicted != nil {
		evicted.close() // at most one connection per host: tear down the prior one so it cannot leak or receive a duplicate push
		g.logger.InfoContext(ctx, "control gateway replaced existing connection", attrkeys.HostID, hostID)
	}
	defer g.reg.remove(hostID, c)

	g.bumpLastSeen(connCtx, hostID)
	go c.writeLoop(connCtx, stream, g.logger)
	go g.maintain(connCtx, c)
	g.deliverPending(connCtx, []string{hostID}) // push any backlog immediately on connect

	recvErr := make(chan error, 1)
	go func() { recvErr <- g.recvLoop(connCtx, stream, c) }()

	select {
	case <-connCtx.Done():
		// Torn down locally (revocation, expiry, or replacement). Returning ends the RPC, which closes the stream and unblocks recvLoop.
		return status.Error(codes.Unavailable, "control connection closed")
	case err := <-recvErr:
		return err
	}
}

// writeLoop is the connection's single sender (gRPC allows one concurrent Send). It drains the send queue until the context ends or a
// Send fails.
func (c *conn) writeLoop(ctx context.Context, stream control.ControlChannel_ConnectServer, logger *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-c.send:
			// select may pick this case even when ctx is already done (e.g. the connection was evicted on reconnect with a frame still
			// buffered); re-check so an evicted/closed connection never delivers a buffered command, which would duplicate delivery
			// across the old and new streams for a non-idempotent command like kill_process.
			if ctx.Err() != nil {
				return
			}
			if err := stream.Send(frame); err != nil {
				// A dead outbound means this connection can no longer deliver commands. Tear the whole connection down (not just this
				// goroutine) so it is unregistered and the agent reconnects, rather than lingering "online" with delivery silently broken.
				logger.DebugContext(ctx, "control gateway send", attrkeys.HostID, c.hostID, "err", err)
				c.close()
				return
			}
		}
	}
}

// recvLoop reads outcome frames and applies them through the unchanged UpdateStatus lifecycle. It returns when the stream ends. A
// client half-close surfaces as io.EOF, which is a normal end-of-stream: returning it from the handler would be converted to a non-OK
// gRPC status, so we map it to nil and let only real errors propagate.
func (g *Gateway) recvLoop(ctx context.Context, stream control.ControlChannel_ConnectServer, c *conn) error {
	for {
		frame, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		oc := frame.GetOutcome()
		if oc == nil {
			continue // unknown/future frame kind: ignore
		}
		g.applyOutcome(ctx, c, oc)
	}
}

// applyOutcome records a reported outcome via the response service. Once any outcome lands the command leaves the pending state, so we
// clear the in-flight mark. An invalid-transition error means a re-delivered, already-handled command: benign, logged at debug.
func (g *Gateway) applyOutcome(ctx context.Context, c *conn, oc *control.Outcome) {
	c.clearInflight(oc.Id)
	err := g.src.UpdateStatus(ctx, api.UpdateStatusRequest{
		HostID: c.hostID,
		ID:     oc.Id,
		Status: api.Status(oc.Status),
		Result: outcomeResult(oc.Result),
	})
	switch {
	case err == nil:
		return
	case errors.Is(err, api.ErrInvalidStatusTransition), errors.Is(err, api.ErrCommandNotFound):
		g.logger.DebugContext(ctx, "control gateway outcome already handled",
			attrkeys.HostID, c.hostID, "cmd_id", oc.Id, "status", oc.Status, "err", err)
	default:
		g.logger.ErrorContext(ctx, "control gateway apply outcome",
			attrkeys.HostID, c.hostID, "cmd_id", oc.Id, "err", err)
	}
}

// maintain runs the connection's periodic work: bump last-seen (so connection presence is liveness) and re-verify the token against the
// revocation snapshot, tearing the connection down if it is revoked or expired.
func (g *Gateway) maintain(ctx context.Context, c *conn) {
	liveness := time.NewTicker(g.livenessInterval)
	defer liveness.Stop()
	revcheck := time.NewTicker(g.revocationInterval)
	defer revcheck.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-liveness.C:
			g.bumpLastSeen(ctx, c.hostID)
		case <-revcheck.C:
			if _, err := g.verifier.VerifyToken(ctx, c.token); err != nil {
				if ctx.Err() != nil {
					return // connection already closing (shutdown/disconnect): the verify error is just the cancelled context, not a revocation
				}
				g.logger.InfoContext(ctx, "control gateway closing connection: token no longer valid",
					attrkeys.HostID, c.hostID, "err", err)
				c.close()
				return
			}
		}
	}
}

func (g *Gateway) bumpLastSeen(ctx context.Context, hostID string) {
	if g.heartbeat == nil {
		return
	}
	if err := g.heartbeat(ctx, hostID, time.Now()); err != nil {
		g.logger.WarnContext(ctx, "control gateway heartbeat", attrkeys.HostID, hostID, "err", err)
	}
}

// authInterceptor verifies the host token from connect metadata once per connection, pins the host id and token into the stream
// context, and rejects otherwise. ErrInvalidToken (unknown/revoked/expired/malformed) maps to Unauthenticated; any other verify error
// maps to Unavailable, matching the HTTP middleware's 401-vs-503 split (a revocation-snapshot blip is retryable, not a deauth).
func (g *Gateway) authInterceptor(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx := ss.Context()
	token, ok := bearerFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing bearer token")
	}
	hostID, err := g.verifier.VerifyToken(ctx, token)
	if err != nil {
		if errors.Is(err, endpointapi.ErrInvalidToken) {
			return status.Error(codes.Unauthenticated, "invalid host token")
		}
		g.logger.ErrorContext(ctx, "control gateway token verify", "err", err)
		return status.Error(codes.Unavailable, "host token verification unavailable")
	}
	ctx = endpointapi.WithHostID(ctx, hostID)
	ctx = withToken(ctx, token)
	return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
}

// bearerFromContext extracts the token from the gRPC "authorization" metadata, accepting a case-insensitive "Bearer" scheme. It splits
// on runs of whitespace (strings.Fields) rather than a single space so a header with extra spaces or a tab between scheme and token is
// still parsed; the token itself never contains whitespace (it is base64url).
func bearerFromContext(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return "", false
	}
	parts := strings.Fields(vals[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", false
	}
	return parts[1], true
}

// outcomeResult normalizes an empty result to nil so the JSON column stays NULL rather than an empty blob.
func outcomeResult(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// wrappedStream overrides Context so downstream handlers see the host-id-and-token-enriched context.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

type ctxKey int

const tokenKey ctxKey = 0

func withToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey, token)
}

func tokenFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(tokenKey).(string)
	return v, ok
}
