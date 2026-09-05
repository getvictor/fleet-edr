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
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	endpointbootstrap "github.com/fleetdm/edr/server/endpoint/bootstrap"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	identitybootstrap "github.com/fleetdm/edr/server/identity/bootstrap"
	responseapi "github.com/fleetdm/edr/server/response/api"
	responsebootstrap "github.com/fleetdm/edr/server/response/bootstrap"
	rulecontentbootstrap "github.com/fleetdm/edr/server/rulecontent/bootstrap"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
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
func Setup(t *testing.T, opts ...Option) *Stack {
	t.Helper()
	return setupReplica(t, full.Open(t), opts...)
}

// Option customises the stack Setup builds. Defaults reproduce the historical Setup behaviour (a single processor worker, the
// detection bootstrap default), so existing callers are unaffected; the scale gate passes WithProcessConcurrency to exercise the
// production multi-worker processor (issue #535 / #544).
type Option func(*setupConfig)

type setupConfig struct {
	processConcurrency int
}

// WithProcessConcurrency runs the detection processor with n in-process workers, matching the production fan-out. Zero (the default
// when the option is omitted) leaves the bootstrap default, which clamps to a single worker.
func WithProcessConcurrency(n int) Option {
	return func(c *setupConfig) { c.processConcurrency = n }
}

// setupReplica wires one full stack against an already-open database. Setup calls it with a fresh per-test DB; the multi-replica
// test calls it twice with the SAME *sqlx.DB so two independent stacks (two sets of bootstrap contexts, two muxes, two httptest
// servers) share one MySQL. That models two replicas: separate in-process state, one shared store. The signing key is identical
// across calls, which is what lets a session minted against one stack validate on the other.
func setupReplica(t *testing.T, db *sqlx.DB, opts ...Option) *Stack {
	t.Helper()

	var cfg setupConfig
	for _, opt := range opts {
		if opt == nil { // tolerate a nil from the conditional-option idiom (var o Option; if cond { o = WithX() }; Setup(t, o))
			continue
		}
		opt(&cfg)
	}

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

	// Visibility (ADR-0015): the real MySQL EventLog queue (event_queue is in the full schema) plus an in-memory EventArchive. Intake
	// fans out to both; the processor claims from the queue. The cross-context tests assert detection outcomes (alerts, process graph),
	// not the durable archive's storage engine, so MemArchive stands in for ClickHouse here.
	visibilityCtx, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db, Logger: logger})
	require.NoError(t, err, "open visibility")

	detectionCtx, err := detectionbootstrap.New(detectionbootstrap.Deps{
		DB:                 db,
		Logger:             logger,
		Mode:               detectionbootstrap.ModeFull,
		ProcessInterval:    20 * time.Millisecond,
		ProcessBatch:       100,
		ProcessConcurrency: cfg.processConcurrency,
		UserExists:         identityCtx.Service().UserExists,
		AuthZ:              identityCtx.AuthZ(),
		EventLog:           visibilityCtx.EventLog(),
		EventArchive:       detectiontestkit.NewMemArchive(),
	})
	require.NoError(t, err, "open detection")

	responseCtx, err := responsebootstrap.New(responsebootstrap.Deps{
		DB:        db,
		Logger:    logger,
		Heartbeat: detectionCtx.Service().RecordHostSeen,
		AuthZ:     identityCtx.AuthZ(),
	})
	require.NoError(t, err, "open response")

	// rulecontent before rules, wired exactly as cmd/main does it (ADR-0021). Without this the stack would build Rules with no
	// corpus supplier, loadCorpus would silently fall back to the embedded corpus, and the cross-context tests could not detect a
	// break in the production persisted-corpus wiring or its schema: the very thing they exist to catch.
	require.NoError(t, rulecontentbootstrap.ApplySchema(t.Context(), db), "apply rulecontent schema")
	ruleContentCtx, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db, Logger: logger})
	require.NoError(t, err, "open rulecontent")
	_, err = ruleContentCtx.SeedFrom(t.Context(), rulesbootstrap.EmbeddedCorpusFS(), rulesbootstrap.EmbeddedCorpusRoot,
		rulesbootstrap.EmbeddedCorpusIncludes)
	require.NoError(t, err, "seed rule corpus")

	rulesCtx, err := rulesbootstrap.New(t.Context(), rulesbootstrap.Deps{
		DB:                   db,
		Logger:               logger,
		Corpus:               ruleContentCtx.Corpus(),
		AuthZ:                identityCtx.AuthZ(),
		Audit:                identityCtx.AuditRecorder(),
		CommandBatchInserter: responseCtx.Service().InsertBatch,
		// Fast so the cross-context statistics test does not wait out the production interval (issue #837).
		EvalStatsFlushInterval: 20 * time.Millisecond,
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
	// Mirrors cmd/main: the engine holds its own compiled copy of the rule set, so an install has to tell it to rebuild or it keeps
	// evaluating the previous one.
	//
	// This wires the notification. The stack DOES start rules' loops now (below, alongside detection and identity), which it did
	// not when this comment was written: issue #837 made one of them load-bearing, because per-rule statistics are written by a
	// flush rather than on the drain path and the cross-context test that checks the recorder is wired would otherwise read an
	// empty table. So the corpus refresh polls here too, at the interval Deps sets, and the observer no longer fires only when a
	// test installs a rule set itself. A test wanting deterministic control over a runtime publish still drives it directly, as
	// rule_corpus_reload_test.go does.
	rulesCtx.SetRuleSetObserver(func() { detectionCtx.LoadActive(rulesCtx.ContentService()) })
	// Wire the mode resolver and the monitor-match recorder, exactly as cmd/main does. Without them the engine has no resolver
	// and every rule runs at its DECLARED default, so a per-rule setting written to the database has no effect on an integration
	// test at all. That silently limited what these stacks could exercise: since issue #764 put sixty-six of seventy-eight rules
	// in monitor, any test wanting a monitor-default rule to alert had no way to ask for it, and the L6 efficacy corpus could
	// only ever cover the twelve that default to alert.
	//
	// Behaviour-preserving for existing tests: with no rows in detection_rule_settings the resolver returns the same declared
	// default the engine was already falling back to.
	detectionCtx.SetModeResolver(rulesCtx.DetectionConfigModeResolver())
	detectionCtx.SetMonitorMatchRecorder(rulesCtx.MonitorMatchRecorder())
	detectionCtx.SetRuleEvalStatsRecorder(rulesCtx.RuleEvalStatsRecorder())

	endpointCtx, err := endpointbootstrap.New(endpointbootstrap.Deps{
		DB:                  db,
		Logger:              logger,
		EnrollSecret:        EnrollSecret,
		EnrollRatePerMinute: 1000,
		AuthZ:               identityCtx.AuthZ(),
		HostTokenSigningKey: signingKey, // any fixed >=32-byte key; the cross-context tests only need enroll/verify to round-trip
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
	// The rules context's loops were never started here, which went unnoticed while nothing in this suite depended on them.
	// Issue #837 made one of them load-bearing: per-rule evaluation statistics are now written by a flush rather than on the
	// drain path, so without Run the cross-context statistics test sees an empty table. Run returns no error, unlike the two
	// above, so there is nothing to surface.
	go rulesCtx.Run(ctx)

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
