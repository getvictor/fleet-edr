package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
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

// RunAndShutdown starts srv on TLS in a background goroutine, blocks until ctx is cancelled or the server returns a fatal error,
// then performs a graceful shutdown. ConfigureTLS must have populated srv.TLSConfig beforehand so the empty-string cert/key
// arguments are correct. The plaintext-HTTP path was removed in issue #140; production binaries can only serve TLS.
//
// Returns the server-side error on abnormal exit, or nil on a ctx-driven graceful shutdown (which also logs "shutdown complete"
// on the way out).
//
// On ctx cancellation (SIGTERM) the server enters a drain phase before closing the listener: drain.BeginDrain() flips /readyz to
// 503 so a load balancer stops routing new requests here, then the server stays up for drainDelay so the LB observes that and
// removes the replica from rotation. In-flight and new requests are served throughout the drain window; only after it does
// srv.Shutdown close the listener and wait (up to ShutdownTimeout) for in-flight requests to finish. A nil drain or a zero
// drainDelay skips the drain phase (the single-process and test paths). The binary exits within drainDelay + ShutdownTimeout.
func RunAndShutdown(ctx context.Context, srv *http.Server, logger *slog.Logger, drain *DrainState, drainDelay time.Duration) error {
	serverErr := make(chan error, 1)
	go func() {
		// srv.TLSConfig is populated by ConfigureTLS when the server terminates TLS itself. When it's nil the operator opted into
		// EDR_TLS_TERMINATED_BY_PROXY (a TLS-terminating proxy is in front), so we serve plaintext HTTP. Branching on TLSConfig
		// keeps the proxy-mode plumbing out of this function's signature and its two callers.
		var serveErr error
		if srv.TLSConfig != nil {
			// ConfigureTLS owns the cert source via GetCertificate; pass empty strings.
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
