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

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
)

// captureRecorder is a minimal identityapi.AuditRecorder for handler tests:
// captures the last Event and returns a configurable error so each test
// can assert "this is exactly the row I expect for this action" without
// touching MySQL.
type captureRecorder struct {
	last   identityapi.AuditEvent
	called bool
	err    error
}

func (c *captureRecorder) Record(_ context.Context, e identityapi.AuditEvent) error {
	c.called = true
	c.last = e
	return c.err
}

// Successful command issuance MUST emit one audit row carrying the new
// command_id + command_type in the payload, the issuing user_id pulled
// from ctx by the handler, and the host as the target. Without this
// row a customer asking "who issued kill_process for host X on
// 2026-Q2" has no record.
func TestHandler_CommandIssue_EmitsAudit(t *testing.T) {
	svc := fakeService{insert: func(_ context.Context, _ string, _ string, _ []byte) (int64, error) {
		return 99, nil
	}}
	rec := &captureRecorder{}
	h := New(svc, nil)
	h.SetAudit(rec)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{
		"host_id":      "H-1",
		"command_type": "kill_process",
		"payload":      map[string]any{"pid": 1234},
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/commands", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	require.True(t, rec.called, "audit recorder must be invoked on a successful command issuance")
	assert.Equal(t, identityapi.AuditCommandIssue, rec.last.Action)
	assert.Equal(t, "host", rec.last.TargetType)
	assert.Equal(t, "H-1", rec.last.TargetID)
	assert.Equal(t, "kill_process", rec.last.Payload["command_type"])
	assert.EqualValues(t, 99, rec.last.Payload["command_id"])
}

// A nil recorder is the documented "audit-disabled" mode (e.g. unit tests
// that don't care about audit). The handler must still process the
// request and return 201 without panicking.
func TestHandler_CommandIssue_NilAuditOK(t *testing.T) {
	svc := fakeService{insert: func(_ context.Context, _ string, _ string, _ []byte) (int64, error) {
		return 100, nil
	}}
	h := New(svc, nil) // SetAudit deliberately not called.

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{"host_id": "H-1", "command_type": "isolate"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/commands", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// Insert errors on the underlying service must NOT emit an audit row;
// audit records "what happened", not "what was attempted." A failed
// insert flows through the existing error response path; the recorder
// should remain untouched.
func TestHandler_CommandIssue_InsertErrorSkipsAudit(t *testing.T) {
	svc := fakeService{insert: func(_ context.Context, _ string, _ string, _ []byte) (int64, error) {
		return 0, api.ErrInvalidInsertRequest
	}}
	rec := &captureRecorder{}
	h := New(svc, nil)
	h.SetAudit(rec)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]any{"host_id": "H-1", "command_type": "isolate"})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/commands", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.False(t, rec.called, "audit must not record actions that failed to commit")
}
