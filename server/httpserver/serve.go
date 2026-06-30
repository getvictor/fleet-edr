package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// ShutdownTimeout is the upper bound on how long a graceful shutdown is allowed
// to wait for in-flight requests before we give up and let the process exit.
const ShutdownTimeout = 15 * time.Second

// DrainState carries the graceful-shutdown readiness signal between the readiness probe and the shutdown path. On SIGTERM the
// server begins draining: /readyz reports not-ready (503) so a load balancer removes this replica from rotation before the listener
// closes, while in-flight and new requests keep being served for the drain window. The zero value is ready (not draining); safe for
// concurrent use. One instance per process is wired in cmd/main and shared with the readiness handler.
type DrainState struct {
	draining atomic.Bool
}

// BeginDrain marks the server as draining. Idempotent.
func (d *DrainState) BeginDrain() { d.draining.Store(true) }

// IsDraining reports whether graceful-shutdown draining has begun.
func (d *DrainState) IsDraining() bool { return d.draining.Load() }

// ControlMux is the agent control-channel gateway as RunAndShutdown consumes it: an HTTP/2 handler (the gateway's gRPC server exposed
// via grpc.Server.ServeHTTP) plus a bounded graceful stop. It is an interface so httpserver does not depend on the response context's
// concrete gateway type. A nil ControlMux serves HTTP only (the ingest binary and tests).
type ControlMux interface {
	http.Handler
	Stop()
}

// RunAndShutdown starts srv in a background goroutine, blocks until ctx is cancelled or the server returns a fatal error, then
// performs a graceful shutdown. It serves TLS when srv.TLSConfig is populated (ConfigureTLS ran, the default), and plaintext HTTP
// when it is nil. The server terminates TLS itself by default (issue #140); the nil-TLSConfig plaintext path is reached only when
// the operator opts into EDR_TLS_TERMINATED_BY_PROXY, i.e. a TLS-terminating proxy is in front (callers skip ConfigureTLS then).
//
// When control is non-nil, the agent control-channel gRPC gateway shares the SAME listener and port as the REST/UI surface (issue
// #477): one native HTTP/2 server dispatches each request by content-type, sending application/grpc to the gateway (gRPC over HTTP/2)
// and everything else to the REST/UI handler. This keeps the whole product on one port with one firewall rule and no separate control
// address to configure, without byte-sniffing the connection (which corrupts persistent HTTP/2). Over TLS, HTTP/2 is negotiated via
// ALPN by ListenAndServeTLS; in the plaintext proxy-terminated mode, cleartext HTTP/2 (h2c) is enabled so the front proxy can forward
// gRPC. A nil control serves HTTP only.
//
// Returns the server-side error on abnormal exit, or nil on a ctx-driven graceful shutdown (which also logs "shutdown complete"
// on the way out).
//
// On ctx cancellation (SIGTERM) the server enters a drain phase before closing the listener: drain.BeginDrain() flips /readyz to
// 503 so a load balancer stops routing new requests here, then the server stays up for drainDelay so the LB observes that and
// removes the replica from rotation. In-flight and new requests are served throughout the drain window; only after it do the control
// gateway's bounded graceful stop and srv.Shutdown close the listener and wait (up to ShutdownTimeout) for in-flight work to finish. A
// nil drain or a zero drainDelay skips the drain phase (the single-process and test paths). The binary exits within drainDelay +
// ShutdownTimeout.
func RunAndShutdown(
	ctx context.Context,
	srv *http.Server,
	control ControlMux,
	logger *slog.Logger,
	drain *DrainState,
	drainDelay time.Duration,
) error {
	if control != nil {
		mountControlChannel(srv, control)
	}

	serverErr := make(chan error, 1)
	go func() {
		var serveErr error
		if srv.TLSConfig != nil {
			// ConfigureTLS owns the cert source via GetCertificate; pass empty strings. ListenAndServeTLS negotiates HTTP/2 via ALPN, so
			// the gRPC dispatch handler sees application/grpc requests over HTTP/2.
			serveErr = srv.ListenAndServeTLS("", "")
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErr <- serveErr
		}
		close(serverErr)
	}()

	select {
	case <-ctx.Done():
		// slog doesn't honour ctx.Done()/cancellation; it just reads the ctx for trace-id correlation. Logging through
		// the cancelled ctx here is fine and keeps the shutdown log on the same trace as the request that triggered it.
		logger.InfoContext(ctx, "shutdown starting", "reason", ctx.Err(), "drain", drainDelay)
		if drain != nil {
			drain.BeginDrain()
		}
		// Stay up for the drain window so the LB sees /readyz flip to 503 and drains this replica before the listener closes;
		// in-flight and new requests keep being served meanwhile. The bounded drain + ShutdownTimeout deadline guarantees the
		// process exits. NOTE: a second SIGTERM is NOT a faster escape hatch. signal.NotifyContext keeps relaying the signal
		// until its stop func runs (deferred in cmd/main to after this returns), so a second SIGTERM is swallowed rather than
		// delivered to the default handler. An operator who needs an immediate stop sends SIGKILL, which cannot be intercepted.
		if drainDelay > 0 {
			drainTimer := time.NewTimer(drainDelay)
			defer drainTimer.Stop()
			<-drainTimer.C
		}
	case err := <-serverErr:
		if err != nil {
			logger.ErrorContext(ctx, "server error", "err", err)
			return err
		}
	}

	// Stop the control gateway first: its bounded GracefulStop drains in-flight RPCs and force-closes the long-lived control streams
	// after the grace window, so they can't hold shutdown open. Then drain HTTP.
	if control != nil {
		control.Stop()
	}
	// Derive the shutdown deadline context from ctx via WithoutCancel so it inherits ctx's values (trace-id, logger attrs) but NOT ctx's
	// cancellation: otherwise srv.Shutdown would return immediately because ctx is already Done. http.Server.Shutdown uses its context
	// purely to decide when to give up on in-flight connections, so a fresh, timeout-bounded, values-inherited context is the correct
	// shape.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.WithoutCancel(ctx), ShutdownTimeout)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.ErrorContext(shutdownCtx, "shutdown error", "err", err)
	}
	logger.InfoContext(shutdownCtx, "shutdown complete")
	return nil
}

// mountControlChannel wraps srv.Handler so application/grpc HTTP/2 requests are dispatched to the control gateway and all other
// requests to the original REST/UI handler. In the plaintext (proxy-terminated) mode it also enables cleartext HTTP/2 so the front
// proxy can forward gRPC; over TLS, HTTP/2 comes from ALPN.
func mountControlChannel(srv *http.Server, control ControlMux) {
	base := srv.Handler
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			control.ServeHTTP(w, r)
			return
		}
		base.ServeHTTP(w, r)
	})
	if srv.TLSConfig == nil {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		srv.Protocols = protocols
	}
}
