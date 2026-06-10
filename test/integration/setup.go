//go:build integration

// Package integration holds cross-context integration tests that exercise
// scenarios spanning multiple bounded contexts: enroll a host via
// endpoint, ingest events via detection, see an alert, issue a command via
// response, agent acks. Tests live behind the //go:build integration tag.
//
// This package may import any context's bootstrap/ and api/ packages -
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
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// EnrollSecret is the value Setup wires through endpoint.New. Tests use it
// to construct enroll requests.
const EnrollSecret = "integration-test-enroll-secret"

// Stack is the result of Setup: an httptest server hosting the agent + admin HTTP surfaces, plus the per-context handles tests reach
// for when calling service methods directly.
type Stack struct {
	Server    *httptest.Server
	Identity  *identitybootstrap.Identity
	Endpoint  *endpointbootstrap.Endpoint
	Rules     *rulesbootstrap.Rules
	Response  *responsebootstrap.Response
	Detection *detectionbootstrap.Detection
	DB        *sqlx.DB
}

// IdentityService / EndpointService / etc. expose each context's public api.Service so tests can call methods (e.g.
// response.Service.Insert to queue a command) without going through HTTP.
func (s *Stack) IdentityService() identityapi.Service   { return s.Identity.Service() }
func (s *Stack) EndpointService() endpointapi.Service   { return s.Endpoint.Service() }
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
//   - CookieSecure = false because httptest is plain HTTP.
func Setup(t *testing.T) *Stack {
	t.Helper()
	return setupReplica(t, full.Open(t))
}

// setupReplica wires one full stack against an already-open database. Setup calls it with a fresh per-test DB; the multi-replica
// test calls it twice with the SAME *sqlx.DB so two independent stacks (two sets of bootstrap contexts, two muxes, two httptest
// servers) share one MySQL. That models two replicas: separate in-process state, one shared store. The signing key is identical
// across calls, which is what lets a session minted against one stack validate on the other.
func setupReplica(t *testing.T, db *sqlx.DB) *Stack {
	t.Helper()

	logger := slog.Default()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	signingKey := make([]byte, 32)
	for i := range signingKey {
		signingKey[i] = byte(i + 1)
	}
	identityCtx, err := identitybootstrap.New(ctx, identitybootstrap.Deps{
		DB:                db,
		Logger:            logger,
		CookieSecure:      false,
		SessionSigningKey: signingKey,
	})
	require.NoError(t, err, "open identity")

	detectionCtx, err := detectionbootstrap.New(detectionbootstrap.Deps{
		DB:              db,
		Logger:          logger,
		Mode:            detectionbootstrap.ModeFull,
		ProcessInterval: 20 * time.Millisecond,
		ProcessBatch:    100,
		UserExists:      identityCtx.Service().UserExists,
		AuthZ:           identityCtx.AuthZ(),
	})
	require.NoError(t, err, "open detection")

	responseCtx, err := responsebootstrap.New(responsebootstrap.Deps{
		DB:        db,
		Logger:    logger,
		Heartbeat: detectionCtx.Service().RecordHostSeen,
		AuthZ:     identityCtx.AuthZ(),
	})
	require.NoError(t, err, "open response")

	rulesCtx, err := rulesbootstrap.New(rulesbootstrap.Deps{
		DB:              db,
		Logger:          logger,
		AuthZ:           identityCtx.AuthZ(),
		Audit:           identityCtx.AuditRecorder(),
		CommandInserter: responseCtx.Service().Insert,
		HostLister: func(ctx context.Context) ([]string, error) {
			hosts, err := detectionCtx.Service().ListHosts(ctx)
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(hosts))
			for _, h := range hosts {
				out = append(out, h.HostID)
			}
			return out, nil
		},
	})
	require.NoError(t, err, "open rules")
	// rules-context ApplySchema seeds the Default application_control policy on top of testdb/full's DDL pass. full.Open only applies the
	// DDL (testkit.ApplySchema is a thin wrapper over bootstrap.ApplySchema's package form which doesn't know about the seed); calling
	// rulesCtx.ApplySchema here brings the seed online so the cross-context REST tests have a Default policy to POST against.
	require.NoError(t, rulesCtx.ApplySchema(ctx), "seed rules default policy")

	detectionCtx.LoadActive(rulesCtx.ContentService())

	endpointCtx, err := endpointbootstrap.New(endpointbootstrap.Deps{
		DB:                  db,
		Logger:              logger,
		EnrollSecret:        EnrollSecret,
		EnrollRatePerMinute: 1000,
		CommandInserter:     responseCtx.Service().Insert,
		AuthZ:               identityCtx.AuthZ(),
	})
	require.NoError(t, err, "open endpoint")

	mux := buildMux(detectionCtx, endpointCtx, identityCtx, rulesCtx, responseCtx, logger)

	// Background loops. Cancelling the context stops them; t.Cleanup drives that. Errors from the run loop are surfaced via t.Errorf so a
	// crash in the processor or the session-cleanup loop fails the test loudly instead of silently letting Eventually timeouts be the only
	// diagnostic signal.
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

// buildMux mirrors cmd/fleet-edr-server's mux composition for the routes the cross-context tests exercise. Operator routes that
// require an authenticated admin session are wired the same way as production (Session + CSRF middleware), but tests typically skip
// the HTTP path for those and call Service methods directly via the Stack handles: session minting + CSRF-token plumbing belongs in
// dedicated identity tests, not in every cross-context smoke.
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

	// Detection's intake route (POST /api/events) is gated by endpoint's host-token middleware in production. Here we register it the same
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

	// Operator routes (session+CSRF gated). The cross-context authz journey test in authz_journey_test.go drives these via real HTTP with
	// seeded session cookies, so the chokepoint + audit pipeline are exercised end-to-end. Tests that don't care about the admin path
	// simply ignore them; the routes wire onto the same mux but the session middleware shorts-circuits anonymous callers with a 401 before
	// any handler runs.
	sessionMW := identityCtx.SessionMiddleware()
	csrfMW := identityCtx.CSRFMiddleware()
	apiMux := http.NewServeMux()
	detectionCtx.RegisterAuthedRoutes(apiMux)
	rulesCtx.RegisterAuthedRoutes(apiMux)
	endpointCtx.RegisterAuthedRoutes(apiMux)
	responseCtx.RegisterAuthedRoutes(apiMux)
	identityCtx.RegisterAuthedRoutes(apiMux)
	sessionProtected := sessionMW(csrfMW(apiMux))
	for _, p := range []string{
		"POST /api/commands",
		"GET /api/audit-events",
		"GET /api/v1/app-control/policies",
		"GET /api/v1/app-control/policies/{id}",
		"POST /api/v1/app-control/policies/{id}/rules",
	} {
		mux.Handle(p, sessionProtected)
	}
	_ = logger

	return mux
}
