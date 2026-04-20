package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// ShutdownTimeout is the upper bound on how long a graceful shutdown is allowed
// to wait for in-flight requests before we give up and let the process exit.
const ShutdownTimeout = 15 * time.Second

// RunAndShutdown starts srv in a background goroutine, blocks until ctx is
// cancelled or the server returns a fatal error, then performs a graceful
// shutdown. tlsEnabled selects ListenAndServeTLS vs ListenAndServe; when true,
// ConfigureTLS must have populated srv.TLSConfig beforehand so the empty-string
// cert/key arguments are correct.
//
// Returns the server-side error on abnormal exit, or nil on a ctx-driven
// graceful shutdown (which also logs "shutdown complete" on the way out).
func RunAndShutdown(ctx context.Context, srv *http.Server, tlsEnabled bool, logger *slog.Logger) error {
	serverErr := make(chan error, 1)
	go func() {
		var serveErr error
		if tlsEnabled {
			// ConfigureTLS owns the cert source via GetCertificate; pass empty.
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
		// slog doesn't honour ctx.Done()/cancellation — it just reads the ctx
		// for trace-id correlation — so logging through the cancelled ctx here
		// is fine and keeps the shutdown log on the same trace as the request
		// that triggered it.
		logger.InfoContext(ctx, "shutdown starting", "reason", ctx.Err())
	case err := <-serverErr:
		if err != nil {
			logger.ErrorContext(ctx, "server error", "err", err)
			return err
		}
	}

	// Derive the shutdown deadline context from ctx via WithoutCancel so it
	// inherits ctx's values (trace-id, logger attrs) but NOT ctx's cancellation
	// — otherwise srv.Shutdown would return immediately because ctx is already
	// Done. http.Server.Shutdown uses its context purely to decide when to give
	// up on in-flight connections, so a fresh, timeout-bounded, values-inherited
	// context is the correct shape.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.WithoutCancel(ctx), ShutdownTimeout)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.ErrorContext(shutdownCtx, "shutdown error", "err", err)
	}
	logger.InfoContext(shutdownCtx, "shutdown complete")
	return nil
}
