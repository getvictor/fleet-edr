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
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	"github.com/fleetdm/edr/internal/control"
	"github.com/fleetdm/edr/server/attrkeys"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/response/api"
)

// Fixed operational intervals, compiled constants rather than operator knobs (server-configuration spec): the cross-replica command
// watch, the connection-presence last-seen bump, and the per-connection token revocation re-check.
const (
	defaultWatchInterval = 1 * time.Second
	// A command is offered again this long after it was acknowledged with no outcome, and no longer than this after it.
	defaultUnreportedGrace  = 60 * time.Second
	defaultUnreportedWindow = 7 * 24 * time.Hour
	defaultLivenessInterval = 30 * time.Second
	// lastSeenWriteTimeout bounds the per-tick last-seen write so a slow database cannot hold the connection's maintenance loop, and
	// therefore cannot stop that host's heartbeats. Well under the agent's silence deadline by design.
	lastSeenWriteTimeout      = 5 * time.Second
	defaultRevocationInterval = 5 * time.Second

	// notifyBuffer bounds the fast-path signal queue. A full buffer is harmless: the 1s watch is the backstop, so a dropped notify just
	// means the command waits up to one watch interval instead of arriving immediately.
	notifyBuffer = 256
)

// CommandSource is the slice of the response service the gateway needs: list a connected host's pending commands (to push) and apply an
// outcome reported over the stream (reusing the unchanged status-transition rules). Satisfied by the response service.
type CommandSource interface {
	ListDeliverableForHosts(ctx context.Context, hostIDs []string, ackedAfter, ackedBefore time.Time) ([]api.Command, error)
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
	// Stats is the telemetry handler the gRPC server reports to; nil takes the OTel one, which is what production uses. New wraps
	// whatever it is given so the connection's span carries the gateway's verdict (issue #1124), which is what lets a test see the
	// events the real server produces without reaching for a global tracer provider.
	Stats stats.Handler
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

	watchInterval time.Duration
	// unreportedGrace is how long after an acknowledgement a missing outcome counts as lost rather than as a command still running.
	// Longer than any command takes: set_network_containment waits up to 15 seconds for the extension to confirm.
	unreportedGrace time.Duration
	// unreportedWindow is how far back an unreported command is still offered. Shorter than the agent's ledger retention, since an
	// agent that has pruned a command's outcome repeats its side effect rather than replaying it.
	unreportedWindow time.Duration
	// now is the clock, injected so a test can place an acknowledgement inside or outside the bounds without waiting.
	now                func() time.Time
	livenessInterval   time.Duration
	revocationInterval time.Duration

	// closing is set by Stop so a connection accepted during shutdown is rejected rather than stranding http.Server.Shutdown on a
	// long-lived stream. Per-replica ephemeral flag.
	closing atomic.Bool
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
	telemetry := deps.Stats
	if telemetry == nil {
		telemetry = otelgrpc.NewServerHandler()
	}
	g := &Gateway{
		src:                deps.Source,
		verifier:           deps.Verifier,
		heartbeat:          deps.Heartbeat,
		logger:             logger,
		reg:                newRegistry(),
		notifyCh:           make(chan string, notifyBuffer),
		watchInterval:      defaultWatchInterval,
		unreportedGrace:    defaultUnreportedGrace,
		unreportedWindow:   defaultUnreportedWindow,
		now:                time.Now,
		livenessInterval:   defaultLivenessInterval,
		revocationInterval: defaultRevocationInterval,
	}
	opts := []grpc.ServerOption{
		grpc.StatsHandler(handlerVerdictStats{Handler: telemetry}),
		grpc.StreamInterceptor(g.authInterceptor),
	}
	// No grpc.Creds and no keepalive enforcement: the gateway is served via grpc.Server.ServeHTTP behind the shared HTTPS listener
	// (cmd/main multiplexes it with the REST/UI surface), so it rides net/http's HTTP/2 server. Transport-level options do not apply
	// there: TLS is terminated once at that listener (or the front proxy), and net/http answers the agent's keep-alive PINGs itself
	// without gRPC's strict ping-flood GOAWAY. ServeHTTP honors the stream interceptor (host-token auth) and the stats handler (OTel),
	// which is all the gateway needs.
	g.grpc = grpc.NewServer(opts...)
	control.RegisterControlChannelServer(g.grpc, g)
	return g
}

// GRPCServer returns the configured gRPC server. Exposed for tests that serve it over an in-memory listener.
func (g *Gateway) GRPCServer() *grpc.Server { return g.grpc }

// ServeHTTP serves the control channel as a gRPC-over-HTTP/2 handler. cmd/main mounts it on the shared HTTPS listener so the control
// gateway and the REST/UI surface share one port (issue #477): the front handler dispatches application/grpc requests here. TLS is
// terminated upstream, so this rides net/http's HTTP/2 server with no transport credentials of its own; auth is the per-stream
// host-token interceptor.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.grpc.ServeHTTP(w, r) }

// Stop tears down every live control stream so the shared HTTP server's shutdown can complete. Because the gateway is served via
// grpc.Server.ServeHTTP (riding net/http's HTTP/2 server), grpc.Server.GracefulStop is unusable here (it panics: the ServeHTTP
// transport has no Drain). Instead we mark the gateway closing (so a connection accepted mid-shutdown is rejected) and cancel every
// registered connection's context, which makes its Connect handler return promptly; the caller's http.Server.Shutdown then drains the
// now-finished requests. Agents reconnect (and fall back to polling) against a peer replica rather than hanging the shutdown.
func (g *Gateway) Stop() {
	g.closing.Store(true)
	g.reg.closeAll()
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

// deliverPending queries the commands the given hosts are owed and pushes each to its connection, skipping commands already in
// flight. That is their pending backlog, and the ones they acknowledged and never reported an outcome for: an outcome written to a
// connection that was already dead is lost, and offering the command again is how the agent's ledger gets to replay it (issue #1062).
func (g *Gateway) deliverPending(ctx context.Context, hostIDs []string) {
	if len(hostIDs) == 0 {
		return
	}
	now := g.now()
	cmds, err := g.src.ListDeliverableForHosts(ctx, hostIDs, now.Add(-g.unreportedWindow), now.Add(-g.unreportedGrace))
	if err != nil {
		g.logger.WarnContext(ctx, "control gateway list deliverable", "err", err)
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
//
// The verdict is recorded for the connection's span before returning, because nothing else can reach it: when a client disappears,
// gRPC ends the RPC with the transport's own error whatever this handler returns, and the span would be coloured by that (issue
// #1124). See spanVerdict.
func (g *Gateway) Connect(stream control.ControlChannel_ConnectServer) error {
	err := g.connect(stream)
	recordSpanVerdict(stream.Context(), err)
	return err
}

func (g *Gateway) connect(stream control.ControlChannel_ConnectServer) error {
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
		// At most one connection per host: tear down the prior one so it cannot leak or receive a duplicate push.
		evicted.close(reasonReplaced)
		g.logger.InfoContext(ctx, "control gateway replaced existing connection", attrkeys.HostID, hostID)
	}
	defer g.reg.remove(hostID, c)
	// If Stop raced ahead of this registration, close immediately so a connection accepted during shutdown can't strand
	// http.Server.Shutdown waiting on a long-lived stream. Checked after add so closeAll cannot miss us.
	if g.closing.Load() {
		c.close(reasonShuttingDown)
		return status.Error(codes.Unavailable, "control gateway shutting down")
	}

	g.bumpLastSeen(connCtx, hostID)
	go c.writeLoop(connCtx, stream, g.logger)
	go g.maintain(connCtx, c)
	g.deliverPending(connCtx, []string{hostID}) // push any backlog immediately on connect

	recvErr := make(chan error, 1)
	go func() { recvErr <- g.recvLoop(connCtx, stream, c) }()

	// Whichever of the two ends the connection, the status returned here is what otelgrpc's stats handler records as the span's
	// status, so each case decides it from whether the client is still there to receive one (issue #1124).
	select {
	case <-connCtx.Done():
		// Returning ends the RPC, which closes the stream and unblocks recvLoop.
		return endAfterTeardown(ctx, c)
	case err := <-recvErr:
		return endAfterReceive(ctx, err)
	}
}

// endAfterTeardown is the status the RPC ends with when the connection's context was cancelled.
//
// ctx is the RPC's own context. Its being done means the client is already gone: an agent restart, a suspended host, a dropped link.
// There is nobody left to return a status to, so the RPC ends cleanly and the connection is recorded as successful. That is how a
// long-lived control connection ordinarily ends, and recording every one of them as a fault left the operation permanently
// error-coloured, which hid the faults that were real (issue #1124).
//
// Otherwise the server tore the connection down while the client was still attached, and this retryable status is what tells it to
// reconnect. Those stay errors, carrying which teardown it was, because a connection the server ended is the one an operator wants.
func endAfterTeardown(ctx context.Context, c *conn) error {
	if ctx.Err() != nil {
		return nil
	}
	return status.Errorf(codes.Unavailable, "control connection closed: %s", c.closedBecause())
}

// endAfterReceive is the status the RPC ends with when it was the receive loop that ended, carrying its result: nil for a client
// half-close, which is an ordinary end of stream, or the failure that ended it.
//
// Two things say the client is gone rather than at fault, and BOTH are needed because they arrive in either order.
//
// The context is the definitive one: a client going away cancels it. It is not sufficient on its own, though, because gRPC fails the
// pending receive and cancels the stream context as two steps, and the receive loses that race often enough to matter. Measured on
// edr-dev: with only the context test, restarting the agent still produced an error span, reading `transport is closing`.
//
// So the error itself is read too. A server-side receive fails for exactly two kinds of reason, and gRPC spells them differently. A
// frame this server could not read (a malformed message, one over the size limit) comes back as a gRPC STATUS, because the server is
// rejecting it with a code. The transport ending under the stream comes back as a bare transport error carrying no status at all,
// which is what `transport is closing` is. That is a connection ending, not a connection failing, so it ends the RPC cleanly; a
// status error is a fault and keeps its error span.
//
// Reading the shape of the error rather than its text is deliberate: the message is grpc-go's to change, and a server that decided
// what to report by matching on a dependency's prose would break silently on an upgrade. The bufconn test below kills a real client
// transport and asserts the verdict, so a grpc-go release that changed this shape fails that test rather than quietly recolouring
// every disconnect on a fleet.
func endAfterReceive(ctx context.Context, recvErr error) error {
	if recvErr == nil || ctx.Err() != nil {
		return nil
	}
	if _, isStatus := status.FromError(recvErr); !isStatus {
		return nil
	}
	return recvErr
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
				c.close(reasonSendFailed)
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
	// Only a terminal outcome frees the command to be offered again. An acknowledgement says the agent is running it, which is the
	// one state where a second offer is certainly wrong, and for a command already acknowledged it moves nothing: the server refuses
	// acked -> acked, so clearing the mark on it would leave the row eligible for the very next watch tick, a second apart, while the
	// outcome that ends it is still on its way (issue #1062). The mark is per connection, so a host that drops mid-execution loses it
	// with the connection and is offered the command again on its next one.
	if api.Status(oc.Status) != api.StatusAcked {
		c.clearInflight(oc.Id)
	}
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
			// Heartbeat FIRST, and never behind the database. Now that an agent tears its stream down when frames stop arriving, a
			// stalled bumpLastSeen would hold this loop, stop heartbeats for every connected host, and turn a database incident into
			// a fleet-wide reconnect storm against the very server that is already struggling. The heartbeat asserts that this
			// replica still holds the connection, which is true whether or not the database is answering, so it must not depend on
			// one.
			//
			// Tell the agent this stream is still registered for delivery. Nothing else does: the gateway runs over the shared HTTPS
			// listener where net/http answers HTTP/2 keepalive PINGs itself, so a passing ping proves the transport is alive and not
			// that this connection still exists here. Without a frame arriving on a cadence, an agent holding a stream this replica
			// has forgotten cannot tell the difference, and it stops asking for work (issue #711).
			//
			// Dropped when the buffer is full, deliberately. A full buffer means frames are already flowing to this agent, which is
			// the very thing the heartbeat exists to demonstrate, and a heartbeat must never displace a command.
			if !c.push(&control.ServerFrame{Frame: &control.ServerFrame_Heartbeat{Heartbeat: &control.Heartbeat{}}}) {
				g.logger.DebugContext(ctx, "control gateway heartbeat skipped: send buffer full", attrkeys.HostID, c.hostID)
			}
			g.bumpLastSeen(ctx, c.hostID)
		case <-revcheck.C:
			if _, err := g.verifier.VerifyToken(ctx, c.token); err != nil {
				if ctx.Err() != nil {
					return // connection already closing (shutdown/disconnect): the verify error is just the cancelled context, not a revocation
				}
				g.logger.InfoContext(ctx, "control gateway closing connection: token no longer valid",
					attrkeys.HostID, c.hostID, "err", err)
				c.close(reasonTokenInvalid)
				return
			}
		}
	}
}

func (g *Gateway) bumpLastSeen(ctx context.Context, hostID string) {
	if g.heartbeat == nil {
		return
	}
	// Bounded, because this is a database write on a stream context that lives as long as the connection does. Left unbounded, one
	// stalled write holds the maintenance loop for that whole lifetime, which now also means no heartbeats for this host. The bound is
	// far below the agent's silence deadline, so even a database that stalls on every tick cannot push a host into reconnecting.
	ctx, cancel := context.WithTimeout(ctx, lastSeenWriteTimeout)
	defer cancel()
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
