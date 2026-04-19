// fleet-edr-server is the main EDR server that handles event processing,
// serves the API and UI. Event ingestion can be handled by this server or
// by a separate fleet-edr-ingest instance.
//
// Configuration is loaded from environment variables; see server/config for the full list.
// Start it with EDR_DSN, EDR_ENROLL_SECRET, EDR_ADMIN_TOKEN, TLS cert files (or
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
	"github.com/fleetdm/edr/server/store"
	"github.com/fleetdm/edr/server/ui"
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
	enrollHandler := enrollment.NewHandler(enrollStore, enrollment.Options{
		EnrollSecret:  cfg.EnrollSecret,
		RatePerMinute: cfg.EnrollRatePerMin,
		Logger:        logger,
		PolicyStore:   policyStore,
		CommandStore:  s,
	})
	adminHandler := admin.New(enrollStore, policyStore, s, logger)

	// Build the mux as a composition of three authorization domains:
	//   - public:  /livez, /readyz, /health, POST /api/v1/enroll
	//   - host:    POST /api/v1/events, GET /api/v1/commands, PUT /api/v1/commands/{id}
	//             (wrapped in authn.HostToken — the agent polls for + reports on its own commands)
	//   - admin:   everything under /api/v1/{hosts,alerts,admin}, POST /api/v1/commands,
	//             GET /api/v1/commands/{id}, and /ui/* (wrapped in authn.AdminToken)
	//
	// Middleware is applied per-handler at registration time so a single mux serves the whole
	// surface and we don't have to route through multiple servers.
	hostTokenMW := authn.HostToken(enrollStore, logger)
	adminTokenMW := authn.AdminToken(cfg.AdminToken, logger)

	mux := http.NewServeMux()
	ingestHandler.RegisterHealthRoutes(mux)
	enrollHandler.RegisterRoutes(mux)

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

	// Admin-token protected admin APIs. api.Handler.RegisterRoutes registers onto a dedicated
	// sub-mux so we can wrap that whole sub-mux in the admin middleware. GET /commands and
	// PUT /commands/{id} are deliberately host-token-only — those paths are the agent-facing
	// command protocol. Admin UI command management (POST, GET /{id}) goes here.
	apiMux := http.NewServeMux()
	apiHandler.RegisterRoutes(apiMux)
	adminHandler.RegisterRoutes(apiMux)
	adminProtected := adminTokenMW(apiMux)
	for _, p := range []string{
		"GET /api/v1/hosts", "GET /api/v1/hosts/{host_id}/tree", "GET /api/v1/hosts/{host_id}/processes/{pid}",
		"GET /api/v1/alerts", "GET /api/v1/alerts/{id}", "PUT /api/v1/alerts/{id}",
		"GET /api/v1/commands/{id}", "POST /api/v1/commands",
		"GET /api/v1/admin/enrollments", "POST /api/v1/admin/enrollments/{host_id}/revoke",
		"GET /api/v1/admin/policy", "PUT /api/v1/admin/policy",
	} {
		mux.Handle(p, adminProtected)
	}
	registerUIRoutes(mux, logger)

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
// itself is intentionally unauthenticated: the React app's login screen is what collects the
// admin token and stores it in sessionStorage, from which every subsequent API call reads it
// into an `Authorization: Bearer` header. Gating /ui/ behind AdminToken would make the login
// page unreachable (chicken/egg). The privileged surface is /api/v1/*, which IS gated.
// Phase 3 replaces this with a server-rendered login endpoint + session cookies.
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
