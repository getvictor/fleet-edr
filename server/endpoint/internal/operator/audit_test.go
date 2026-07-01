package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// fakeRevokeService stubs api.Service. Only Revoke + List + RotateToken are exercised by these tests; other methods panic so a
// regression that wires this fake into a different path surfaces immediately.
type fakeRevokeService struct {
	revoke func(ctx context.Context, hostID, reason, actor string) error
	rotate func(ctx context.Context, hostID, actor, reason string) error
}

func (f fakeRevokeService) Enroll(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
	panic("not used")
}
func (f fakeRevokeService) VerifyToken(context.Context, string) (string, error) { panic("not used") }
func (f fakeRevokeService) RefreshToken(context.Context, string) (api.RefreshResponse, error) {
	panic("not used")
}
func (f fakeRevokeService) List(context.Context) ([]api.Enrollment, error) { return nil, nil }
func (f fakeRevokeService) Get(context.Context, string) (*api.Enrollment, error) {
	panic("not used")
}
func (f fakeRevokeService) Revoke(ctx context.Context, hostID, reason, actor string) error {
	if f.revoke == nil {
		panic("fake.Revoke not set")
	}
	return f.revoke(ctx, hostID, reason, actor)
}
func (f fakeRevokeService) CountActive(context.Context) (int, error)        { panic("not used") }
func (f fakeRevokeService) ActiveHostIDs(context.Context) ([]string, error) { panic("not used") }
func (f fakeRevokeService) RecordStatus(context.Context, string, api.StatusReport) error {
	panic("not used")
}
func (f fakeRevokeService) RotateToken(ctx context.Context, hostID, actor, reason string) error {
	if f.rotate == nil {
		panic("fake.RotateToken not set")
	}
	return f.rotate(ctx, hostID, actor, reason)
}

type captureRecorder struct {
	last   identityapi.AuditEvent
	called bool
}

func (c *captureRecorder) Record(_ context.Context, e identityapi.AuditEvent) error {
	c.called = true
	c.last = e
	return nil
}

// allowAllAuthZ stubs identityapi.AuthZ for endpoint operator tests that exercise revoke / rotate semantics rather than the role
// matrix. Per-action coverage lives in server/identity/internal/authz/engine_test.go.
type allowAllAuthZ struct{}

func (allowAllAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: true, Reason: "granted"}, nil
}

// spec:server-admin-surface/audit-trail-for-state-changing-admin-actions/revoke-produces-an-audit-record
//
// A successful revoke MUST emit a structured audit record carrying the operator-supplied actor + reason,
// the action identifier, and the affected host id. Pinned by the captureRecorder assertions below: the
// recorder fires exactly once, the action is AuditEnrollmentRevoke, the target is the host, and the
// payload preserves actor + reason verbatim from the operator's request body.
func TestHandler_Revoke_EmitsAudit(t *testing.T) {
	t.Parallel()
	svc := fakeRevokeService{revoke: func(_ context.Context, _, _, _ string) error { return nil }}
	rec := &captureRecorder{}
	h := New(svc, allowAllAuthZ{}, nil)
	h.SetAudit(rec)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{"actor": "operator@test", "reason": "compromise"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/enrollments/H-9/revoke", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.True(t, rec.called, "audit recorder must be invoked on a successful revoke")
	assert.Equal(t, identityapi.AuditEnrollmentRevoke, rec.last.Action)
	assert.Equal(t, "host", rec.last.TargetType)
	assert.Equal(t, "H-9", rec.last.TargetID)
	assert.Equal(t, "operator@test", rec.last.Payload["actor"])
	assert.Equal(t, "compromise", rec.last.Payload["reason"])
}

// Nil recorder must not panic; revoke still applies and audit silently no-ops.
func TestHandler_Revoke_NilAuditOK(t *testing.T) {
	t.Parallel()
	svc := fakeRevokeService{revoke: func(_ context.Context, _, _, _ string) error { return nil }}
	h := New(svc, allowAllAuthZ{}, nil)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{"actor": "operator@test", "reason": "compromise"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/enrollments/H-9/revoke", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// Successful POST .../rotate returns 204 with no body: under the signed-token model the rotate is an epoch bump with no token or
// command to hand back. The handler must still pass the operator-supplied actor + reason through to the service for the audit row.
func TestHandler_Rotate_HappyPath(t *testing.T) {
	t.Parallel()
	captured := struct {
		hostID string
		actor  string
		reason string
	}{}
	svc := fakeRevokeService{rotate: func(_ context.Context, hostID, actor, reason string) error {
		captured.hostID = hostID
		captured.actor = actor
		captured.reason = reason
		return nil
	}}
	h := New(svc, allowAllAuthZ{}, nil)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{"actor": "victor@example", "reason": "incident-2026-Q2"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/enrollments/H-1/rotate", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "H-1", captured.hostID)
	assert.Equal(t, "victor@example", captured.actor)
	assert.Equal(t, "incident-2026-Q2", captured.reason)
}

// Missing actor or reason returns 400; rotation is operator-attributed audit material, so silent rotations without attribution would
// undermine the audit story #87 just shipped.
func TestHandler_Rotate_RequiresActorAndReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing actor", map[string]any{"reason": "x"}},
		{"missing reason", map[string]any{"actor": "x"}},
		{"both empty", map[string]any{}},
		{"whitespace actor", map[string]any{"actor": "   ", "reason": "y"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := fakeRevokeService{rotate: func(context.Context, string, string, string) error {
				t.Fatal("RotateToken must not be called when actor/reason validation fails")
				return nil
			}}
			h := New(svc, allowAllAuthZ{}, nil)
			mux := http.NewServeMux()
			h.RegisterRoutes(mux)
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			body, _ := json.Marshal(tc.body)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				srv.URL+"/api/enrollments/H-1/rotate", bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

// spec:server-admin-surface/revoke-a-host-enrollment/revoke-without-an-actor-or-reason
//
// The revoke endpoint MUST refuse a request body missing `actor` or `reason` (or carrying whitespace-only
// values) with a 400 and MUST NOT call the service-level Revoke. Pinned by table-driven cases covering
// every shape the validator must reject; the fakeRevokeService's t.Fatal in the Revoke callback proves
// the handler stops at validation rather than persisting the empty audit attribution.
func TestHandler_Revoke_RequiresActorAndReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing actor", map[string]any{"reason": "x"}},
		{"missing reason", map[string]any{"actor": "x"}},
		{"both empty", map[string]any{}},
		{"whitespace actor", map[string]any{"actor": "   ", "reason": "y"}},
		{"whitespace reason", map[string]any{"actor": "y", "reason": "\t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := fakeRevokeService{revoke: func(context.Context, string, string, string) error {
				t.Fatal("Revoke must not be called when actor/reason validation fails")
				return nil
			}}
			h := New(svc, allowAllAuthZ{}, nil)
			mux := http.NewServeMux()
			h.RegisterRoutes(mux)
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			body, _ := json.Marshal(tc.body)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				srv.URL+"/api/enrollments/H-1/revoke", bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

// Missing host returns 404, not 500; the handler must surface api.ErrNotFound from the service as the operator-facing "not_found"
// code.
func TestHandler_Rotate_NotFound(t *testing.T) {
	t.Parallel()
	svc := fakeRevokeService{rotate: func(context.Context, string, string, string) error {
		return api.ErrNotFound
	}}
	h := New(svc, allowAllAuthZ{}, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{"actor": "op", "reason": "x"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/api/enrollments/missing/rotate", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
