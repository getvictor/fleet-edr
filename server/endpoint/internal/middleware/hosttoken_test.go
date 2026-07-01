package middleware_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/endpoint/internal/middleware"
)

// fakeService is a minimal api.Service stub that lets us drive HostToken middleware tests without a DB. Only VerifyToken is
// implemented; the other methods panic so an accidental call surfaces immediately.
type fakeService struct {
	verifyToken func(ctx context.Context, token string) (string, error)
}

func (f fakeService) Enroll(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
	panic("not implemented in fakeService")
}
func (f fakeService) VerifyToken(ctx context.Context, token string) (string, error) {
	return f.verifyToken(ctx, token)
}
func (f fakeService) RecordStatus(context.Context, string, api.StatusReport) error {
	panic("not implemented in fakeService")
}
func (f fakeService) List(context.Context) ([]api.Enrollment, error) {
	panic("not implemented in fakeService")
}
func (f fakeService) Get(context.Context, string) (*api.Enrollment, error) {
	panic("not implemented in fakeService")
}
func (f fakeService) Revoke(context.Context, string, string, string) error {
	panic("not implemented in fakeService")
}
func (f fakeService) CountActive(context.Context) (int, error) {
	panic("not implemented in fakeService")
}
func (f fakeService) ActiveHostIDs(context.Context) ([]string, error) {
	panic("not implemented in fakeService")
}
func (f fakeService) RotateToken(context.Context, string, string, string) error {
	panic("not implemented in fakeService")
}
func (f fakeService) RefreshToken(context.Context, string) (api.RefreshResponse, error) {
	panic("not implemented in fakeService")
}

const testHostID = "93DFC6F5-763D-5075-B305-8AC145D12F96"
const testToken = "abcdefghijklmnopqrstuvwxyz0123456789012345_"

func downstream(t *testing.T, wantHostID string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostID, ok := api.HostIDFromContext(r.Context())
		if !ok {
			t.Errorf("downstream: host_id not pinned on context")
		}
		if wantHostID != "" {
			assert.Equal(t, wantHostID, hostID)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestHostToken_ValidToken(t *testing.T) {
	t.Parallel()
	svc := fakeService{
		verifyToken: func(_ context.Context, token string) (string, error) {
			assert.Equal(t, testToken, token)
			return testHostID, nil
		},
	}
	mw := middleware.HostToken(svc, slog.Default())
	mux := http.NewServeMux()
	mux.Handle("POST /ingest", mw(downstream(t, testHostID)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/ingest", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestHostToken_MissingBearer(t *testing.T) {
	t.Parallel()
	svc := fakeService{verifyToken: func(context.Context, string) (string, error) {
		t.Fatal("VerifyToken must not be called when bearer is missing")
		return "", nil
	}}
	mw := middleware.HostToken(svc, slog.Default())
	mux := http.NewServeMux()
	mux.Handle("POST /ingest", mw(downstream(t, "")))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/ingest", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`)

	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]string
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, "missing_bearer", parsed["error"])
}

func TestHostToken_EmptyBearerSuffixRejected(t *testing.T) {
	t.Parallel()
	svc := fakeService{verifyToken: func(context.Context, string) (string, error) {
		t.Fatal("VerifyToken must not be called when bearer suffix is empty")
		return "", nil
	}}
	mw := middleware.HostToken(svc, slog.Default())
	mux := http.NewServeMux()
	mux.Handle("POST /ingest", mw(downstream(t, "")))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/ingest", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer ")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// spec:server-event-ingestion/authenticated-batch-event-submission/a-request-without-a-host-token-is-rejected
//
// The spec scenario covers two cases: "omits or supplies an unrecognized bearer token". The omit case is
// covered by TestHostToken_MissingBearer above (this same file); the unrecognized-token case is below. One
// marker per scenario is enough to satisfy the gate, and "unrecognized" is the meatier case so the marker
// lands here. The middleware is what the spec's "system MUST reject" clause materialises as; the detection
// IngestHandler runs only after this middleware has resolved the bearer to a host_id.
func TestHostToken_InvalidToken(t *testing.T) {
	t.Parallel()
	svc := fakeService{
		verifyToken: func(context.Context, string) (string, error) {
			return "", api.ErrInvalidToken
		},
	}
	mw := middleware.HostToken(svc, slog.Default())
	mux := http.NewServeMux()
	mux.Handle("POST /ingest", mw(downstream(t, "")))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/ingest", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]string
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, "invalid_token", parsed["error"])
}

// TestHostToken_VerifierUnavailable covers the 503 path: any non-ErrInvalidToken error from the service surfaces as
// verifier_unavailable so the agent doesn't burn its re-enroll throttle on a transient DB blip.
func TestHostToken_VerifierUnavailable(t *testing.T) {
	t.Parallel()
	svc := fakeService{
		verifyToken: func(context.Context, string) (string, error) {
			return "", errors.New("db is down")
		},
	}
	mw := middleware.HostToken(svc, slog.Default())
	mux := http.NewServeMux()
	mux.Handle("POST /ingest", mw(downstream(t, "")))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/ingest", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	// 503 must NOT carry WWW-Authenticate.
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]string
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, "verifier_unavailable", parsed["error"])
}

func TestHostToken_PanicsOnNilService(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { _ = middleware.HostToken(nil, slog.Default()) })
}
