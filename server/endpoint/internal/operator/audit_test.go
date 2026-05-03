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

// fakeRevokeService stubs api.Service. Only Revoke + List are exercised
// by these tests; other methods panic so a regression that wires this
// fake into a different path surfaces immediately.
type fakeRevokeService struct {
	revoke func(ctx context.Context, hostID, reason, actor string) error
}

func (f fakeRevokeService) Enroll(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
	panic("not used")
}
func (f fakeRevokeService) VerifyToken(context.Context, string) (string, error) { panic("not used") }
func (f fakeRevokeService) List(context.Context) ([]api.Enrollment, error)      { return nil, nil }
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

type captureRecorder struct {
	last   identityapi.AuditEvent
	called bool
}

func (c *captureRecorder) Record(_ context.Context, e identityapi.AuditEvent) error {
	c.called = true
	c.last = e
	return nil
}

func TestHandler_Revoke_EmitsAudit(t *testing.T) {
	svc := fakeRevokeService{revoke: func(_ context.Context, _, _, _ string) error { return nil }}
	rec := &captureRecorder{}
	h := New(svc, nil)
	h.SetAudit(rec)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{"actor": "operator@test", "reason": "compromise"})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/enrollments/H-9/revoke", bytes.NewReader(body))
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
	svc := fakeRevokeService{revoke: func(_ context.Context, _, _, _ string) error { return nil }}
	h := New(svc, nil)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{"actor": "operator@test", "reason": "compromise"})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/enrollments/H-9/revoke", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}
