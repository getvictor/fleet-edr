//go:build integration

// Package integration holds cross-context integration tests that exercise
// scenarios spanning multiple bounded contexts — enroll a host via
// endpoint, ingest events via detection, see an alert, issue a command via
// response, agent acks. Tests live behind the //go:build integration tag.
//
// This package may import any context's bootstrap/ and api/ packages —
// it sits at the same level as cmd/main, conceptually, just for tests.
// It cannot import any context's internal/... because Go's internal/ rule
// blocks the import structurally (test/integration/ lives outside the
// server/<context>/ subtree).
//
// setup.go is the canonical layer-3 fixture: Setup(t) wires every context
// the way cmd/fleet-edr-server's main.go does, returns the composed
// http.Handler + service handles. Tests call HTTP via httptest.NewServer
// and/or call service methods directly, depending on what surface they're
// exercising.
package integration

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	detectionbootstrap "github.com/fleetdm/edr/server/detection/bootstrap"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	identitybootstrap "github.com/fleetdm/edr/server/identity/bootstrap"
	responseapi "github.com/fleetdm/edr/server/response/api"
	responsebootstrap "github.com/fleetdm/edr/server/response/bootstrap"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// EnrollSecret is the value Setup wires through endpoint.New. Tests use it
// to construct enroll requests.
const EnrollSecret = "integration-test-enroll-secret"

// Stack is the result of Setup: an httptest server hosting the agent + admin
// HTTP surfaces, plus the per-context handles tests reach for when calling
// service methods directly.
type Stack struct {
	Server    *httptest.Server
	Identity  *identitybootstrap.Identity
	Endpoint  *endpointbootstrap.Endpoint
	Rules     *rulesbootstrap.Rules
	Response  *responsebootstrap.Response
	Detection *detectionbootstrap.Detection
	DB        *sqlx.DB
}

// IdentityService / EndpointService / etc. expose each context's public
// api.Service so tests can call methods (e.g. response.Service.Insert to
// queue a command) without going through HTTP.
func (s *Stack) IdentityService() identityapi.Service   { return s.Identity.Service() }
func (s *Stack) EndpointService() endpointapi.Service   { return s.Endpoint.Service() }
func (s *Stack) RulesService() rulesapi.PolicyService   { return s.Rules.PolicyService() }
func (s *Stack) ResponseService() responseapi.Service   { return s.Response.Service() }
func (s *Stack) DetectionService() detectionapi.Service { return s.Detection.Service() }

// Setup composes the five contexts the same way cmd/fleet-edr-server's
// main.go does, against an isolated MySQL test database with every schema
// pre-applied. Background goroutines (detection processor + retention,
// identity session-cleanup) start; t.Cleanup stops them.
//
// The returned httptest.Server hosts the same mux production runs (host-
// token gated /api/events, /api/commands; session-gated /api/* operator
// routes; public /api/enroll + /api/session). Tests issue real HTTP calls
// against it so the wiring is exercised end-to-end.
//
// Test-friendly knobs vs. production:
//   - ProcessInterval = 20ms so the processor materialises events fast
//     enough that Eventually loops finish in < 1s rather than minutes.
//   - StaleProcessTTL = 0 (default; disables forced reconciliation, which
//     would invent exit events for fixture processes).
//   - RetentionDays = 0 (disabled; tests are short-lived; nothing to GC).
//   - LoginRatePerMin = 1000 so per-test login bursts don't trip the
//     rate limiter.
//   - CookieSecure = false because httptest is plain HTTP.
func Setup(t *testing.T) *Stack {
	t.Helper()

	db := full.Open(t)
	logger := slog.Default()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	identityCtx, err := identitybootstrap.New(ctx, identitybootstrap.Deps{
		DB:              db,
		Logger:          logger,
		LoginRatePerMin: 1000,
		CookieSecure:    false,
	})
	require.NoError(t, err, "open identity")

	detectionCtx, err := detectionbootstrap.New(detectionbootstrap.Deps{
		DB:              db,
		Logger:          logger,
		Mode:            detectionbootstrap.ModeFull,
		ProcessInterval: 20 * time.Millisecond,
		ProcessBatch:    100,
		UserExists:      identityCtx.Service().UserExists,
	})
	require.NoError(t, err, "open detection")

	responseCtx, err := responsebootstrap.New(responsebootstrap.Deps{
		DB:        db,
		Logger:    logger,
		Heartbeat: detectionCtx.Service().RecordHostSeen,
	})
	require.NoError(t, err, "open response")

	// rules.New takes ActiveHostsLister + CommandInserter together (or
	// both nil). Endpoint isn't built yet, so use a forward closure that
	// captures endpointCtx after it's assigned. cmd/main does the same.
	var endpointCtx *endpointbootstrap.Endpoint
	activeHostsLister := func(ctx context.Context) ([]string, error) {
		if endpointCtx == nil {
			return nil, errors.New("setup: endpoint context not yet initialised")
		}
		return endpointCtx.Service().ActiveHostIDs(ctx)
	}
	rulesCtx, err := rulesbootstrap.New(rulesbootstrap.Deps{
		DB:                db,
		Logger:            logger,
		ActiveHostsLister: activeHostsLister,
		CommandInserter:   responseCtx.Service().Insert,
	})
	require.NoError(t, err, "open rules")

	detectionCtx.LoadActive(rulesCtx.ContentService())

	endpointCtx, err = endpointbootstrap.New(endpointbootstrap.Deps{
		DB:                  db,
		Logger:              logger,
		EnrollSecret:        EnrollSecret,
		EnrollRatePerMinute: 1000,
		PolicyProvider:      rulesCtx.PolicyService(),
		CommandInserter:     responseCtx.Service().Insert,
	})
	require.NoError(t, err, "open endpoint")

	mux := buildMux(detectionCtx, endpointCtx, identityCtx, rulesCtx, responseCtx, logger)

	// Background loops. Cancelling the context stops them; t.Cleanup
	// drives that. Errors from the run loop are surfaced via t.Errorf
	// so a crash in the processor or the session-cleanup loop fails
	// the test loudly instead of silently letting Eventually timeouts
	// be the only diagnostic signal.
	go func() {
		if err := detectionCtx.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("detection.Run failed: %v", err)
		}
	}()
	go func() {
		if err := identityCtx.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("identity.Run failed: %v", err)
		}
	}()

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Stack{
		Server:    srv,
		Identity:  identityCtx,
		Endpoint:  endpointCtx,
		Rules:     rulesCtx,
		Response:  responseCtx,
		Detection: detectionCtx,
		DB:        db,
	}
}

// buildMux mirrors cmd/fleet-edr-server's mux composition for the routes
// the cross-context tests exercise. Operator routes that require an
// authenticated admin session are wired the same way as production
// (Session + CSRF middleware), but tests typically skip the HTTP path
// for those and call Service methods directly via the Stack handles —
// session minting + CSRF-token plumbing belongs in dedicated identity
// tests, not in every cross-context smoke.
func buildMux(
	detectionCtx *detectionbootstrap.Detection,
	endpointCtx *endpointbootstrap.Endpoint,
	identityCtx *identitybootstrap.Identity,
	rulesCtx *rulesbootstrap.Rules,
	responseCtx *responsebootstrap.Response,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()

	// Public routes (rate-limited at the handler).
	endpointCtx.RegisterPublicRoutes(mux)
	identityCtx.RegisterPublicRoutes(mux)

	// Detection's intake route (POST /api/events) is gated by endpoint's
	// host-token middleware in production. Here we register it the same
	// way: a sub-mux for host-token routes, wrapped with the middleware.
	hostMW := endpointCtx.HostTokenMiddleware()
	hostMux := http.NewServeMux()
	hostMux.Handle("POST /api/events", detectionCtx.Service().IngestHandler())
	responseCtx.RegisterAgentRoutes(hostMux)
	hostProtected := hostMW(hostMux)
	for _, p := range []string{
		"POST /api/events",
		"GET /api/commands",
		"PUT /api/commands/{id}",
	} {
		mux.Handle(p, hostProtected)
	}

	// Detection's health probes are public (livez/readyz).
	detectionCtx.RegisterHealthRoutes(mux)

	// Operator routes (session+CSRF gated). Tests that need admin paths
	// use the Stack's per-context Service methods rather than HTTP, so
	// we don't bother stitching login + cookie jar here.
	_ = rulesCtx
	_ = logger

	return mux
}
