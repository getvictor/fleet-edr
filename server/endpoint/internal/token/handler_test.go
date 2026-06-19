package token

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
)

// fakeRefreshService implements api.Service; only RefreshToken is exercised by the handler. The rest panic so an unexpected call
// surfaces immediately.
type fakeRefreshService struct {
	resp api.RefreshResponse
	err  error
}

func (f fakeRefreshService) RefreshToken(context.Context, string) (api.RefreshResponse, error) {
	return f.resp, f.err
}
func (f fakeRefreshService) Enroll(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
	panic("not used")
}
func (f fakeRefreshService) VerifyToken(context.Context, string) (string, error)  { panic("not used") }
func (f fakeRefreshService) List(context.Context) ([]api.Enrollment, error)       { panic("not used") }
func (f fakeRefreshService) Get(context.Context, string) (*api.Enrollment, error) { panic("not used") }
func (f fakeRefreshService) Revoke(context.Context, string, string, string) error { panic("not used") }
func (f fakeRefreshService) CountActive(context.Context) (int, error)             { panic("not used") }
func (f fakeRefreshService) ActiveHostIDs(context.Context) ([]string, error)      { panic("not used") }
func (f fakeRefreshService) RotateToken(context.Context, string, api.RotationTrigger, string, string) (api.RotateResult, error) {
	panic("not used")
}

func serve(t *testing.T, svc api.Service) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/token/refresh", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	New(svc, nil).ServeHTTP(rec, req)
	return rec
}

func TestHandler_Success(t *testing.T) {
	t.Parallel()
	rec := serve(t, fakeRefreshService{resp: api.RefreshResponse{HostID: "host-1", HostToken: "v1.a.b"}})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "v1.a.b")
	assert.Contains(t, rec.Body.String(), "host-1")
}

func TestHandler_InvalidToken_401(t *testing.T) {
	t.Parallel()
	rec := serve(t, fakeRefreshService{err: api.ErrInvalidToken})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandler_InternalError_500(t *testing.T) {
	t.Parallel()
	rec := serve(t, fakeRefreshService{err: errors.New("store unavailable")})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestNew_NilService_Panics(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { New(nil, nil) })
}
