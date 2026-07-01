package status_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/internal/status"
)

// recordStatusFn lets each test drive Service.RecordStatus; every other api.Service method panics because the status handler must never
// call them (a regression that did would surface loudly rather than silently no-op).
type fakeStatusService struct {
	record func(ctx context.Context, hostID string, report api.StatusReport) error
}

func (f fakeStatusService) RecordStatus(ctx context.Context, hostID string, report api.StatusReport) error {
	return f.record(ctx, hostID, report)
}
func (fakeStatusService) Enroll(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
	panic("not used")
}
func (fakeStatusService) VerifyToken(context.Context, string) (string, error) { panic("not used") }
func (fakeStatusService) RefreshToken(context.Context, string) (api.RefreshResponse, error) {
	panic("not used")
}
func (fakeStatusService) List(context.Context) ([]api.Enrollment, error)       { panic("not used") }
func (fakeStatusService) Get(context.Context, string) (*api.Enrollment, error) { panic("not used") }
func (fakeStatusService) Revoke(context.Context, string, string, string) error { panic("not used") }
func (fakeStatusService) CountActive(context.Context) (int, error)             { panic("not used") }
func (fakeStatusService) ActiveHostIDs(context.Context) ([]string, error)      { panic("not used") }
func (fakeStatusService) RotateToken(context.Context, string, string, string) error {
	panic("not used")
}

// serve drives the handler with hostID pinned on the context exactly as the host-token middleware would (or absent when hostID == "").
func serve(t *testing.T, svc api.Service, hostID, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := status.New(svc, nil)
	ctx := context.Background()
	if hostID != "" {
		ctx = api.WithHostID(ctx, hostID)
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/status", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const validBody = `{"agent_version":"0.4.0","reported_at_ns":7,"components":[{"type":"network_extension","status":"healthy","last_transition_ns":3}]}`

func TestServeHTTP_Success(t *testing.T) {
	t.Parallel()
	var gotHost string
	var gotReport api.StatusReport
	svc := fakeStatusService{record: func(_ context.Context, hostID string, report api.StatusReport) error {
		gotHost = hostID
		gotReport = report
		return nil
	}}

	rec := serve(t, svc, "host-1", validBody)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "host-1", gotHost)
	assert.Equal(t, "0.4.0", gotReport.AgentVersion)
	require.Len(t, gotReport.Components, 1)
	assert.Equal(t, api.ComponentNetworkExtension, gotReport.Components[0].Type)
}

func TestServeHTTP_MissingHostIDIsUnauthorized(t *testing.T) {
	t.Parallel()
	svc := fakeStatusService{record: func(context.Context, string, api.StatusReport) error {
		t.Fatal("RecordStatus must not be called without an authenticated host")
		return nil
	}}

	rec := serve(t, svc, "", validBody)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestServeHTTP_BadJSON(t *testing.T) {
	t.Parallel()
	svc := fakeStatusService{record: func(context.Context, string, api.StatusReport) error {
		t.Fatal("RecordStatus must not be called on an unparseable body")
		return nil
	}}

	rec := serve(t, svc, "host-1", `{not json`)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_json")
}

func TestServeHTTP_InvalidStatusMaps400(t *testing.T) {
	t.Parallel()
	svc := fakeStatusService{record: func(context.Context, string, api.StatusReport) error {
		return api.ErrInvalidStatusReport
	}}

	rec := serve(t, svc, "host-1", validBody)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_status")
}

func TestServeHTTP_ServiceErrorMaps500(t *testing.T) {
	t.Parallel()
	svc := fakeStatusService{record: func(context.Context, string, api.StatusReport) error {
		return assert.AnError
	}}

	rec := serve(t, svc, "host-1", validBody)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "internal")
}

func TestNew_NilServicePanics(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { status.New(nil, nil) })
}
