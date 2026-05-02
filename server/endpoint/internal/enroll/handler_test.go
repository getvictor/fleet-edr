package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/endpoint/api"
)

const testUUID = "93DFC6F5-763D-5075-B305-8AC145D12F96"

// fakeService is a minimal api.Service stub. Only Enroll is implemented;
// other methods panic so an accidental call surfaces immediately.
type fakeService struct {
	enroll func(ctx context.Context, req api.EnrollRequest, sourceIP string) (api.EnrollResponse, error)
}

func (f fakeService) Enroll(ctx context.Context, req api.EnrollRequest, sourceIP string) (api.EnrollResponse, error) {
	return f.enroll(ctx, req, sourceIP)
}
func (f fakeService) VerifyToken(context.Context, string) (string, error) {
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

func newServer(t *testing.T, svc api.Service, ratePerMinute int) *httptest.Server {
	t.Helper()
	h := New(svc, Options{RatePerMinute: ratePerMinute, Logger: slog.Default()})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func postEnroll(t *testing.T, srv *httptest.Server, body any) *http.Response {
	t.Helper()
	buf := new(bytes.Buffer)
	require.NoError(t, json.NewEncoder(buf).Encode(body))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/enroll", buf)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func TestEnroll_HappyPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	svc := fakeService{
		enroll: func(_ context.Context, req api.EnrollRequest, _ string) (api.EnrollResponse, error) {
			assert.Equal(t, testUUID, req.HardwareUUID)
			assert.Equal(t, "qa-host", req.Hostname)
			return api.EnrollResponse{
				HostID: req.HardwareUUID,
				// #nosec G101 -- test fixture: not a real credential.
				HostToken:  "token-bytes-43-chars-long-for-the-fake-svc",
				EnrolledAt: now,
			}, nil
		},
	}
	srv := newServer(t, svc, 30)
	resp := postEnroll(t, srv, map[string]string{
		"enroll_secret": "some-secret",
		"hardware_uuid": testUUID,
		"hostname":      "qa-host",
		"os_version":    "macOS 15.3",
		"agent_version": "0.0.1-dev",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out enrollResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, testUUID, out.HostID)
	assert.NotEmpty(t, out.HostToken)
}

func TestEnroll_SecretMismatch(t *testing.T) {
	svc := fakeService{
		enroll: func(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
			return api.EnrollResponse{}, api.ErrInvalidSecret
		},
	}
	srv := newServer(t, svc, 30)
	resp := postEnroll(t, srv, map[string]string{
		"enroll_secret": "wrong",
		"hardware_uuid": testUUID,
		"hostname":      "h", "os_version": "o", "agent_version": "v",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	var body errBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "secret_mismatch", body.Error)
}

func TestEnroll_InvalidUUID(t *testing.T) {
	svc := fakeService{
		enroll: func(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
			return api.EnrollResponse{}, api.ErrInvalidHardwareUUID
		},
	}
	srv := newServer(t, svc, 30)
	resp := postEnroll(t, srv, map[string]string{
		"enroll_secret": "s", "hardware_uuid": "not-a-uuid",
		"hostname": "h", "os_version": "o", "agent_version": "v",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body errBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "hardware_uuid_invalid", body.Error)
}

func TestEnroll_BadBody_MissingFields(t *testing.T) {
	svc := fakeService{
		enroll: func(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
			t.Fatal("Enroll must not be called when fields are missing")
			return api.EnrollResponse{}, nil
		},
	}
	srv := newServer(t, svc, 30)
	resp := postEnroll(t, srv, map[string]string{
		"enroll_secret": "s",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestEnroll_BadBody_NotJSON(t *testing.T) {
	svc := fakeService{
		enroll: func(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
			t.Fatal("Enroll must not be called on bad body")
			return api.EnrollResponse{}, nil
		},
	}
	srv := newServer(t, svc, 30)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/enroll",
		strings.NewReader("not-json{"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestEnroll_RateLimit(t *testing.T) {
	svc := fakeService{
		enroll: func(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
			return api.EnrollResponse{}, api.ErrInvalidSecret
		},
	}
	srv := newServer(t, svc, 2) // burst of 2 then 429

	body := map[string]string{
		"enroll_secret": "wrong", "hardware_uuid": testUUID,
		"hostname": "h", "os_version": "o", "agent_version": "v",
	}
	for range 2 {
		resp := postEnroll(t, srv, body)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}
	resp := postEnroll(t, srv, body)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "60", resp.Header.Get("Retry-After"))
}

func TestEnroll_PanicsOnNilService(t *testing.T) {
	assert.Panics(t, func() { _ = New(nil, Options{}) })
}

func TestEnrollRequest_StringRedactsSecret(t *testing.T) {
	req := enrollRequest{EnrollSecret: "hunter2", HardwareUUID: testUUID}
	s := req.String()
	assert.NotContains(t, s, "hunter2")
	assert.Contains(t, s, "REDACTED")
}

// TestEnroll_SecretNeverLogged drives a real HTTP request through the
// handler with a known-bad secret and asserts the secret string never
// appears in the captured slog output. Lock-in for the redaction guard.
func TestEnroll_SecretNeverLogged(t *testing.T) {
	const secret = "my-super-secret-not-in-logs"
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc := fakeService{
		enroll: func(context.Context, api.EnrollRequest, string) (api.EnrollResponse, error) {
			return api.EnrollResponse{}, api.ErrInvalidSecret
		},
	}
	h := New(svc, Options{Logger: logger, RatePerMinute: 30})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp := postEnroll(t, srv, map[string]string{
		"enroll_secret": secret, "hardware_uuid": testUUID,
		"hostname": "h", "os_version": "o", "agent_version": "v",
	})
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	assert.NotContains(t, buf.String(), secret, "audit log must never contain the enroll secret")
}
