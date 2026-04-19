// fleet-edr-server is the main EDR server that handles event processing,
// serves the API and UI. Event ingestion can be handled by this server or
// by a separate fleet-edr-ingest instance.
//
// Configuration is loaded from environment variables; see server/config for the full list.
// Start it with EDR_DSN, EDR_ENROLL_SECRET, TLS cert files (or
// EDR_ALLOW_INSECURE_HTTP=1 for dev), and optionally the OTEL_* vars that route traces and
// logs to a collector (SigNoz, Tempo, Datadog, ...).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fleetdm/edr/server/admin"
	"github.com/fleetdm/edr/server/api"
	"github.com/fleetdm/edr/server/authn"
	"github.com/fleetdm/edr/server/config"
	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/detection/rules"
	"github.com/fleetdm/edr/server/enrollment"
	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/ingest"
	"github.com/fleetdm/edr/server/logging"
	"github.com/fleetdm/edr/server/observability"
	"github.com/fleetdm/edr/server/policy"
	"github.com/fleetdm/edr/server/processor"
	"github.com/fleetdm/edr/server/seed"
	"github.com/fleetdm/edr/server/session"
	"github.com/fleetdm/edr/server/sessions"
	"github.com/fleetdm/edr/server/store"
	"github.com/fleetdm/edr/server/ui"
	"github.com/fleetdm/edr/server/users"
)

// Build info injected via -ldflags at build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = ""
)

const serviceName = "fleet-edr-server"

func main() {
	if err := run(); err != nil {
		// At this point the structured logger may not be initialised (e.g. config load failure);
		// write the final message to stderr directly so the operator sees it.
		_, _ = os.Stderr.WriteString("fatal: " + err.Error() + "\n")
		os.Exit(2)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	shutdownOTel, err := observability.Init(ctx, observability.Options{
		ServiceName:    serviceName,
		ServiceVersion: version,
	})
	if err != nil {
		return err
	}
	defer func() {
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer flushCancel()
		if err := shutdownOTel(flushCtx); err != nil {
			slog.Default().WarnContext(flushCtx, "otel shutdown", "err", err)
		}
	}()

	logger, err := logging.New(os.Stderr, logging.Options{
		Level:               cfg.LogLevel,
		Format:              cfg.LogFormat,
		InstrumentationName: serviceName,
	})
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	logger.InfoContext(ctx, "fleet-edr-server starting",
		"addr", cfg.ListenAddr,
		"version", version,
		"commit", commit,
		"build_time", buildTime,
		"tls", cfg.TLSEnabled(),
		"tls12_allowed", cfg.AllowTLS12,
	)
	if !cfg.TLSEnabled() {
		logger.WarnContext(ctx, "EDR_ALLOW_INSECURE_HTTP=1 set; TLS disabled — do not run in production")
	}

	s, err := store.New(ctx, cfg.DSN)
	if err != nil {
		logger.ErrorContext(ctx, "open store", "err", err)
		return err
	}
	defer func() { _ = s.Close() }()

	build := ingest.BuildInfo{Version: version, Commit: commit, BuildTime: buildTime}
	ingestHandler := ingest.New(s, logger, build)
	builder := graph.NewBuilder(s, logger)
	det := detection.NewEngine(s, logger)
	det.Register(&rules.SuspiciousExec{})
	det.Register(&rules.PersistenceLaunchAgent{AllowedPlists: cfg.LaunchAgentAllowlist})
	det.Register(&rules.DyldInsert{})
	det.Register(&rules.ShellFromOffice{})
	det.Register(&rules.OsascriptNetworkExec{})
	proc := processor.New(s, builder, det, logger, cfg.ProcessInterval, cfg.ProcessBatch)

	q := graph.NewQuery(s)
	apiHandler := api.New(q, s, logger)

	enrollStore := enrollment.NewStore(s.DB())
	policyStore := policy.New(s.DB())
	userStore := users.New(s.DB())
	sessionStore := sessions.New(s.DB(), sessions.Options{})

	// Phase 3: seed the first admin before we bind the HTTP listener. If the operator
	// is watching, they capture the printed password at boot; if they miss it they can
	// restart and re-seed by deleting the admin row. Never fatal — a seed failure is
	// logged but the server still boots (operator can run migrations by hand).
	if _, _, err := seed.Admin(ctx, userStore, logger, os.Stderr); err != nil {
		logger.ErrorContext(ctx, "admin seed failed", "err", err)
	}

	enrollHandler := enrollment.NewHandler(enrollStore, enrollment.Options{
		EnrollSecret:  cfg.EnrollSecret,
		RatePerMinute: cfg.EnrollRatePerMin,
		Logger:        logger,
		PolicyStore:   policyStore,
		CommandStore:  s,
	})
	adminHandler := admin.New(enrollStore, policyStore, s, logger)
	sessionHandler := session.New(userStore, sessionStore, session.Options{
		RatePerMinute: cfg.LoginRatePerMin,
		CookieSecure:  cfg.TLSEnabled(),
		Logger:        logger,
	})

	// Build the mux as a composition of three authorization domains:
	//   - public:  /livez, /readyz, /health, POST /api/v1/enroll, POST /api/v1/session
	//   - host:    POST /api/v1/events, GET /api/v1/commands, PUT /api/v1/commands/{id}
	//             (wrapped in authn.HostToken — the agent polls for + reports on its own commands)
	//   - session: everything under /api/v1/{hosts,alerts,admin}, POST /api/v1/commands,
	//             GET /api/v1/commands/{id}, GET/DELETE /api/v1/session (wrapped in
	//             authn.Session; unsafe methods additionally gated by authn.CSRF)
	//
	// Middleware is applied per-handler at registration time so a single mux serves the whole
	// surface and we don't have to route through multiple servers.
	hostTokenMW := authn.HostToken(enrollStore, logger)
	sessionMW := authn.Session(sessionStore, logger)
	csrfMW := authn.CSRF(logger)

	mux := http.NewServeMux()
	ingestHandler.RegisterHealthRoutes(mux)
	enrollHandler.RegisterRoutes(mux)
	// POST /api/v1/session is public — there is no session yet. The session handler
	// does its own rate-limit + audit log so we don't need to wrap it.
	sessionHandler.RegisterPublicRoutes(mux)

	// Host-token protected agent endpoints. We wrap a dedicated sub-mux so the api.Handler
	// routes (GET/PUT commands) share scoping logic with the ingest handler.
	hostMux := http.NewServeMux()
	hostMux.Handle("POST /api/v1/events", ingestHandler.IngestHandler())
	hostMux.HandleFunc("GET /api/v1/commands", apiHandler.ListCommands)
	hostMux.HandleFunc("PUT /api/v1/commands/{id}", apiHandler.UpdateCommandStatus)
	hostProtected := hostTokenMW(hostMux)
	for _, p := range []string{
		"POST /api/v1/events",
		"GET /api/v1/commands",
		"PUT /api/v1/commands/{id}",
	} {
		mux.Handle(p, hostProtected)
	}

	// Session-protected admin APIs. api.Handler.RegisterRoutes registers onto a dedicated
	// sub-mux so we can wrap that whole sub-mux in the session middleware. GET /commands and
	// PUT /commands/{id} are deliberately host-token-only — those paths are the agent-facing
	// command protocol. Admin UI command management (POST, GET /{id}) goes here. The
	// session + CSRF middleware pair lives here: Session first (reads cookie, pins user
	// + session on ctx), CSRF second (reads session off ctx, validates X-CSRF-Token on
	// unsafe methods). GET + DELETE /api/v1/session live under the same stack; login POST
	// is public (above).
	apiMux := http.NewServeMux()
	apiHandler.RegisterRoutes(apiMux)
	adminHandler.RegisterRoutes(apiMux)
	sessionHandler.RegisterAuthedRoutes(apiMux)
	sessionProtected := sessionMW(csrfMW(apiMux))
	for _, p := range []string{
		"GET /api/v1/hosts", "GET /api/v1/hosts/{host_id}/tree", "GET /api/v1/hosts/{host_id}/processes/{pid}",
		"GET /api/v1/alerts", "GET /api/v1/alerts/{id}", "PUT /api/v1/alerts/{id}",
		"GET /api/v1/commands/{id}", "POST /api/v1/commands",
		"GET /api/v1/admin/enrollments", "POST /api/v1/admin/enrollments/{host_id}/revoke",
		"GET /api/v1/admin/policy", "PUT /api/v1/admin/policy",
		"GET /api/v1/session",
	} {
		mux.Handle(p, sessionProtected)
	}
	registerUIRoutes(mux, logger)

	// Phase 3: periodic cleanup of expired session rows. Every 5 minutes; the exact
	// interval doesn't matter much — 12h-TTL rows that linger for a few extra minutes
	// are harmless because Session middleware already rejects expired rows via the
	// `expires_at > NOW()` filter.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n, err := sessionStore.CleanupExpired(ctx)
				if err != nil {
					logger.WarnContext(ctx, "session cleanup", "err", err)
					continue
				}
				if n > 0 {
					logger.InfoContext(ctx, "session cleanup removed rows", "count", n)
				}
			}
		}
	}()

	// Start the background event processor.
	go func() {
		if err := proc.Run(ctx); err != nil && ctx.Err() == nil {
			logger.ErrorContext(ctx, "processor", "err", err)
		}
	}()

	handler := httpserver.Build(mux, httpserver.Options{
		Logger:      logger,
		ServiceName: serviceName,
		TLSEnabled:  cfg.TLSEnabled(),
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	var certHolder atomic.Pointer[tls.Certificate]
	if cfg.TLSEnabled() {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			logger.ErrorContext(ctx, "load tls cert", "err", err)
			return err
		}
		certHolder.Store(&cert)
		minVer := uint16(tls.VersionTLS13)
		if cfg.AllowTLS12 {
			minVer = tls.VersionTLS12
			logger.WarnContext(ctx, "EDR_TLS_ALLOW_TLS12=1 set; TLS 1.2 enabled for legacy pilot")
		}
		//nolint:gosec // MinVersion may be TLS12 only when the operator explicitly opts in via EDR_TLS_ALLOW_TLS12=1.
		srv.TLSConfig = &tls.Config{
			MinVersion: minVer,
			// TLS 1.2 cipher list restricted to forward-secrecy AEADs. TLS 1.3 has its own
			// fixed list, so this only applies when AllowTLS12 is on.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			},
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				// atomic.Pointer.Load is cheap; the pointer is swapped by the SIGHUP handler.
				return certHolder.Load(), nil
			},
		}

		// Start a SIGHUP watcher that atomically swaps the cert + key from disk. Existing
		// connections are not dropped; only new handshakes see the new cert.
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for range sighup {
				logger.InfoContext(ctx, "tls reload: reloading cert + key from disk")
				cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
				if err != nil {
					logger.ErrorContext(ctx, "tls reload failed", "err", err)
					continue
				}
				certHolder.Store(&cert)
				logger.InfoContext(ctx, "tls reload", "cert_file", cfg.TLSCertFile)
			}
		}()
	}

	serverErr := make(chan error, 1)
	go func() {
		var serveErr error
		if cfg.TLSEnabled() {
			// Pass empty strings because GetCertificate owns the cert source.
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
		logger.InfoContext(context.Background(), "shutdown starting", "reason", ctx.Err())
	case err := <-serverErr:
		if err != nil {
			logger.ErrorContext(ctx, "server error", "err", err)
			return err
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.ErrorContext(shutdownCtx, "shutdown error", "err", err)
	}
	logger.InfoContext(shutdownCtx, "shutdown complete")
	return nil
}

// registerUIRoutes serves the embedded React UI at /ui/ and redirects / to /ui/. The bundle
// itself is intentionally unauthenticated: the React app's Login screen is what collects the
// email + password via POST /api/v1/session. The server replies with a HttpOnly session
// cookie and a CSRF token the JS stores in memory. Every subsequent state-changing call
// carries both the cookie (automatic, HttpOnly) and an X-CSRF-Token header. Gating /ui/
// itself behind the Session middleware would make the login page unreachable (chicken/egg).
// The privileged surface is /api/v1/*, which IS session-gated.
func registerUIRoutes(mux *http.ServeMux, logger *slog.Logger) {
	uiDist, err := fs.Sub(ui.DistFS, "dist")
	if err != nil {
		logger.ErrorContext(context.Background(), "embed ui", "err", err)
		mux.HandleFunc("/ui/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "UI bundle missing; run `npm run build` in ui/ and rebuild the server", http.StatusServiceUnavailable)
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/", http.StatusFound)
		})
		return
	}
	fileServer := http.FileServer(http.FS(uiDist))
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/ui/"):]
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(uiDist, path); err != nil {
			r.URL.Path = "/ui/"
		}
		http.StripPrefix("/ui/", fileServer).ServeHTTP(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
}
