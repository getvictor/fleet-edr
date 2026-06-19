//go:build integration

// Per-context integration tests for the endpoint bounded context.
// Exercise the full bootstrap.New -> ApplySchema -> Service stack
// against a real MySQL. Skips when EDR_TEST_DSN isn't set, matching the
// project's other DB-using test files.
//
// Per docs/adr/0004-modular-monolith-bounded-contexts.md.

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/bootstrap"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/testdb/full"
)

// allowAllAuthZ stubs identityapi.AuthZ for endpoint integration tests. Per-action role coverage is exercised in
// server/identity/internal/authz/engine_test.go.
type allowAllAuthZ struct{}

func (allowAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: true, Reason: "granted"}, nil
}

const (
	testEnrollSecret = "endpoint-integration-secret"
	testHardwareUUID = "12345678-1234-1234-1234-123456789012"
	// testHostTokenSigningKey is the fixed >=32-byte HMAC key the endpoint bootstrap requires for signing self-validating host tokens.
	testHostTokenSigningKey = "endpoint-integration-host-token-signing-key0"
)

// recordingCommandInserter captures every CommandInserter call so tests can assert on the host_id targeting and the command type.
// The CommandInserter closure shape (endpoint/bootstrap.CommandInserter) is satisfied by the Insert method's method-value.
type recordingCommandInserter struct {
	mu     sync.Mutex
	calls  []recordedCommand
	nextID int64
}

type recordedCommand struct {
	HostID      string
	CommandType string
	Payload     json.RawMessage
}

func (r *recordingCommandInserter) Insert(_ context.Context, hostID, commandType string, payload []byte) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	r.calls = append(r.calls, recordedCommand{HostID: hostID, CommandType: commandType, Payload: append(json.RawMessage(nil), payload...)})
	return r.nextID, nil
}

func (r *recordingCommandInserter) snapshot() []recordedCommand {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedCommand, len(r.calls))
	copy(out, r.calls)
	return out
}

// newEndpoint wires endpoint.bootstrap.New against a fresh test DB. Returns the *Endpoint handle so tests can hit Service() directly
// or register routes onto a test mux. Tests that need direct DB access (e.g. rotation_test.go's ageToken) reach for newEndpointWithDB.
func newEndpoint(t *testing.T, opts ...func(*bootstrap.Deps)) *bootstrap.Endpoint {
	t.Helper()
	ep, _ := newEndpointWithDB(t, opts...)
	return ep
}

// newEndpointWithDB exposes the underlying *sqlx.DB alongside the Endpoint so tests that need to manipulate row state directly (e.g.
// backdating host_token_issued_at to forge a stale token without waiting an hour) can do so without leaking through the public
// bootstrap.Endpoint surface.
func newEndpointWithDB(t *testing.T, opts ...func(*bootstrap.Deps)) (*bootstrap.Endpoint, *sqlx.DB) {
	t.Helper()
	s := full.Open(t)
	deps := bootstrap.Deps{
		DB:                  s,
		Logger:              slog.Default(),
		EnrollSecret:        testEnrollSecret,
		EnrollRatePerMinute: 600,
		AuthZ:               allowAllAuthZ{},
		HostTokenSigningKey: []byte(testHostTokenSigningKey),
	}
	for _, opt := range opts {
		opt(&deps)
	}
	ep, err := bootstrap.New(deps)
	require.NoError(t, err)
	require.NoError(t, ep.ApplySchema(t.Context()))
	return ep, s
}

// spec:server-admin-surface/list-enrollments/operator-lists-enrolled-hosts
// spec:server-admin-surface/revoke-a-host-enrollment/revoke-a-known-host
// spec:agent-enrollment/per-host-token-scoping/revoking-a-host-invalidates-its-token
//
// Three scenarios share this test. The List() call after Enroll proves the admin list endpoint
// surfaces every enrolled row with HostID and the enrollment audit fields the Enrollment API surfaces
// today (HostID, EnrolledAt, ExpiresAt, RevokedAt; see server/endpoint/api/types.go). The spec
// scenario also calls for a last-seen timestamp; that field is sourced from the host_seen hook tested
// elsewhere and is not part of the Enrollment row this query returns. The Revoke() call followed by
// VerifyToken returning ErrInvalidToken pins both the admin-surface clause "the next request that
// agent makes with that token receives 401" AND the agent-enrollment clause "revoking a host
// invalidates its token": the SERVER-side enforcement is the load-bearing half (VerifyToken returns
// ErrInvalidToken which the HostToken middleware translates to 401), and the agent's "re-enroll path
// engages on the next request" half is already pinned in agent/enrollment/enrollment_test.go's
// TestOnUnauthorized_Throttles.
//
// TestEnrollVerifyListRevoke walks the full operator + agent flow: agent enrolls, the host token verifies, the operator list shows the
// row, the operator revokes, the same token now fails verification, and the listing reflects the revocation.
func TestEnrollVerifyListRevoke(t *testing.T) {
	t.Parallel()
	ep := newEndpoint(t)
	ctx := t.Context()

	res, err := ep.Service().Enroll(ctx, api.EnrollRequest{
		EnrollSecret: testEnrollSecret,
		HardwareUUID: testHardwareUUID,
		Hostname:     "h",
		OSVersion:    "macOS 13",
		AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.NoError(t, err)
	assert.Equal(t, testHardwareUUID, res.HostID)
	require.NotEmpty(t, res.HostToken)
	assert.False(t, res.EnrolledAt.IsZero())

	hostID, err := ep.Service().VerifyToken(ctx, res.HostToken)
	require.NoError(t, err)
	assert.Equal(t, testHardwareUUID, hostID)

	rows, err := ep.Service().List(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, testHardwareUUID, rows[0].HostID)
	assert.Nil(t, rows[0].RevokedAt, "fresh enrollment must not be revoked")

	count, err := ep.Service().CountActive(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	active, err := ep.Service().ActiveHostIDs(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{testHardwareUUID}, active)

	require.NoError(t, ep.Service().Revoke(ctx, testHardwareUUID, "qa cleanup", "operator@example.com"))

	// Revocation is enforced via the per-replica snapshot (a server refreshes it on a ticker bounded by
	// DefaultRevocationRefreshInterval). Refresh it synchronously here so the assertion is deterministic.
	require.NoError(t, ep.RevocationSnapshot().Refresh(ctx))

	_, err = ep.Service().VerifyToken(ctx, res.HostToken)
	require.ErrorIs(t, err, api.ErrInvalidToken)

	rows, err = ep.Service().List(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.NotNil(t, rows[0].RevokedAt)
	require.NotNil(t, rows[0].RevokeReason)
	assert.Equal(t, "qa cleanup", *rows[0].RevokeReason)

	count, err = ep.Service().CountActive(ctx)
	require.NoError(t, err)
	assert.Zero(t, count)
}

// TestEnroll_BadSecretMaps401 covers the secret-mismatch branch through
// the public Service surface.
func TestEnroll_BadSecretMaps401(t *testing.T) {
	t.Parallel()
	ep := newEndpoint(t)
	_, err := ep.Service().Enroll(t.Context(), api.EnrollRequest{
		EnrollSecret: "wrong",
		HardwareUUID: testHardwareUUID,
		Hostname:     "h",
		OSVersion:    "x",
		AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.ErrorIs(t, err, api.ErrInvalidSecret)
}

// spec:agent-enrollment/first-boot-enrollment-exchange/hardware-uuid-is-malformed
//
// Pins the server-side half of the malformed-UUID scenario: a non-canonical hardware_uuid is rejected
// at the service layer with api.ErrInvalidHardwareUUID before any enrollment row is persisted. The
// HTTP-layer 400 response is downstream (covered by TestEnroll_InvalidUUID in enroll/handler_test.go),
// and the agent-side "does not persist any token file" clause is the agent's behavior on observing a
// 4xx from this endpoint (covered by enrollment.go's success-path-only persist call).
//
// TestEnroll_InvalidHardwareUUID covers the UUID-validation branch.
func TestEnroll_InvalidHardwareUUID(t *testing.T) {
	t.Parallel()
	ep := newEndpoint(t)
	_, err := ep.Service().Enroll(t.Context(), api.EnrollRequest{
		EnrollSecret: testEnrollSecret,
		HardwareUUID: "not-a-uuid",
		Hostname:     "h",
		OSVersion:    "x",
		AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.ErrorIs(t, err, api.ErrInvalidHardwareUUID)
}

// spec:server-admin-surface/revoke-a-host-enrollment/revoke-a-host-that-does-not-exist
//
// Service-level pin: Revoke against a host id that has no enrollment row returns api.ErrNotFound, which
// the HTTP layer (TestRegisterAuthedRoutes_OperatorListAndRevoke below) translates into a 404 response.
// Multi-test demonstrator: both layers pinned independently so a regression on either side surfaces.
func TestRevoke_NotFound(t *testing.T) {
	t.Parallel()
	ep := newEndpoint(t)
	err := ep.Service().Revoke(t.Context(), "00000000-0000-0000-0000-000000000000", "x", "y")
	require.ErrorIs(t, err, api.ErrNotFound)
}

// TestVerifyToken_UnknownToken returns ErrInvalidToken; tokens that do not parse must not be distinguishable from tokens that fail the
// hash check.
func TestVerifyToken_UnknownToken(t *testing.T) {
	t.Parallel()
	ep := newEndpoint(t)
	for _, token := range []string{"garbage", "00000000000000000000000000000000.00000000000000000000000000000000"} {
		_, err := ep.Service().VerifyToken(t.Context(), token)
		require.ErrorIs(t, err, api.ErrInvalidToken)
	}
}

// TestHostTokenMiddleware_PinsHostID enrolls an agent and verifies the HostToken middleware extracts the bearer token, calls
// VerifyToken, and pins the host_id on the request context.
func TestHostTokenMiddleware_PinsHostID(t *testing.T) {
	t.Parallel()
	ep := newEndpoint(t)
	ctx := t.Context()

	res, err := ep.Service().Enroll(ctx, api.EnrollRequest{
		EnrollSecret: testEnrollSecret,
		HardwareUUID: testHardwareUUID,
		Hostname:     "h",
		OSVersion:    "x",
		AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.NoError(t, err)

	pinned := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostID, ok := api.HostIDFromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprint(w, hostID)
	})
	srv := httptest.NewServer(ep.HostTokenMiddleware()(pinned))
	t.Cleanup(srv.Close)

	t.Run("valid token pins host_id", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+res.HostToken)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body bytes.Buffer
		_, err = body.ReadFrom(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, testHardwareUUID, body.String())
	})

	t.Run("missing bearer rejected", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		require.NoError(t, err)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("invalid token rejected", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer not-a-real-token")
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	require.NoError(t, ep.Service().Revoke(ctx, testHardwareUUID, "qa", "op"))
	require.NoError(t, ep.RevocationSnapshot().Refresh(ctx))

	t.Run("revoked token rejected", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+res.HostToken)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// TestRegisterPublicRoutes_EnrollEndToEnd hits POST /api/enroll through
// the registered mux, asserting the wire shape the agent depends on.
func TestRegisterPublicRoutes_EnrollEndToEnd(t *testing.T) {
	t.Parallel()
	ep := newEndpoint(t)
	ctx := t.Context()

	mux := http.NewServeMux()
	ep.RegisterPublicRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := strings.NewReader(`{
        "enroll_secret":"` + testEnrollSecret + `",
        "hardware_uuid":"` + testHardwareUUID + `",
        "hostname":"h",
        "os_version":"macOS 13",
        "agent_version":"0.1.0"
    }`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/enroll", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got api.EnrollResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, testHardwareUUID, got.HostID)
	assert.NotEmpty(t, got.HostToken)
	assert.False(t, got.EnrolledAt.IsZero())
}

// spec:server-admin-surface/authenticated-admin-boundary/authenticated-admin-request-proceeds
// spec:server-admin-surface/list-enrollments/operator-lists-enrolled-hosts
// spec:server-admin-surface/revoke-a-host-enrollment/revoke-a-known-host
// spec:server-admin-surface/revoke-a-host-enrollment/revoke-a-host-that-does-not-exist
//
// Four scenarios share this test. RegisterAuthedRoutes wires every admin endpoint behind the session
// middleware in production; this test mounts the routes WITHOUT a session middleware so the
// happy-path handler dispatch is exercised directly (the authenticated-admin-request-proceeds clause).
// The GET /api/enrollments path pins operator-lists-enrolled-hosts at the HTTP layer
// (TestEnrollVerifyListRevoke pins it at the service layer). The POST /api/enrollments/{host_id}/revoke
// path pins both revoke scenarios: the known-host 204 NoContent and the missing-host 404 NotFound, with
// the latter complementing TestRevoke_NotFound's service-layer demonstration.
func TestRegisterAuthedRoutes_OperatorListAndRevoke(t *testing.T) {
	t.Parallel()
	ep := newEndpoint(t)
	ctx := t.Context()

	_, err := ep.Service().Enroll(ctx, api.EnrollRequest{
		EnrollSecret: testEnrollSecret,
		HardwareUUID: testHardwareUUID,
		Hostname:     "h",
		OSVersion:    "macOS 13",
		AgentVersion: "0.1.0",
	}, "192.0.2.1")
	require.NoError(t, err)

	mux := http.NewServeMux()
	ep.RegisterAuthedRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// GET /api/enrollments
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/enrollments", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var rows []api.Enrollment
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rows))
	require.Len(t, rows, 1)
	assert.Equal(t, testHardwareUUID, rows[0].HostID)

	// POST /api/enrollments/{host_id}/revoke
	revokeBody := strings.NewReader(`{"reason":"integration","actor":"operator@example.com"}`)
	revReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		srv.URL+"/api/enrollments/"+testHardwareUUID+"/revoke", revokeBody)
	require.NoError(t, err)
	revReq.Header.Set("Content-Type", "application/json")
	revResp, err := srv.Client().Do(revReq)
	require.NoError(t, err)
	revResp.Body.Close()
	assert.Equal(t, http.StatusNoContent, revResp.StatusCode)

	// Revoke again on a missing host_id -> 404.
	missingBody := strings.NewReader(`{"reason":"x","actor":"y"}`)
	missingReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		srv.URL+"/api/enrollments/00000000-0000-0000-0000-000000000000/revoke", missingBody)
	require.NoError(t, err)
	missingReq.Header.Set("Content-Type", "application/json")
	missingResp, err := srv.Client().Do(missingReq)
	require.NoError(t, err)
	missingResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, missingResp.StatusCode)
}

// TestBootstrap_MissingDeps surfaces required-field errors.
func TestBootstrap_MissingDeps(t *testing.T) {
	t.Parallel()
	t.Run("nil DB", func(t *testing.T) {
		_, err := bootstrap.New(bootstrap.Deps{EnrollSecret: testEnrollSecret})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DB")
	})
	t.Run("missing secret", func(t *testing.T) {
		s := full.Open(t)
		_, err := bootstrap.New(bootstrap.Deps{DB: s})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EnrollSecret")
	})
}
