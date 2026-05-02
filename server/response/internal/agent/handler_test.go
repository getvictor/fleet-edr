package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/response/api"
)

// fakeService is a minimal api.Service stub. Each method delegates to a
// closure so each test can inject the exact behavior it needs; unset
// closures panic so an accidental call surfaces immediately.
type fakeService struct {
	insert       func(ctx context.Context, hostID, commandType string, payload []byte) (int64, error)
	get          func(ctx context.Context, id int64) (api.Command, error)
	listForHost  func(ctx context.Context, hostID string, status api.Status) ([]api.Command, error)
	updateStatus func(ctx context.Context, req api.UpdateStatusRequest) error
	countPending func(ctx context.Context) (int, error)
}

func (f fakeService) Insert(ctx context.Context, hostID, commandType string, payload []byte) (int64, error) {
	if f.insert == nil {
		panic("fakeService.Insert not set")
	}
	return f.insert(ctx, hostID, commandType, payload)
}

func (f fakeService) Get(ctx context.Context, id int64) (api.Command, error) {
	if f.get == nil {
		panic("fakeService.Get not set")
	}
	return f.get(ctx, id)
}

func (f fakeService) ListForHost(ctx context.Context, hostID string, status api.Status) ([]api.Command, error) {
	if f.listForHost == nil {
		panic("fakeService.ListForHost not set")
	}
	return f.listForHost(ctx, hostID, status)
}

func (f fakeService) UpdateStatus(ctx context.Context, req api.UpdateStatusRequest) error {
	if f.updateStatus == nil {
		panic("fakeService.UpdateStatus not set")
	}
	return f.updateStatus(ctx, req)
}

func (f fakeService) CountPending(ctx context.Context) (int, error) {
	if f.countPending == nil {
		panic("fakeService.CountPending not set")
	}
	return f.countPending(ctx)
}

// withHostID pins host_id on the request context the way the real
// endpoint.HostToken middleware does.
func withHostID(next http.Handler, hostID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := endpointapi.WithHostIDForTest(r.Context(), hostID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newAgentServer(t *testing.T, svc api.Service, hostID string) *httptest.Server {
	t.Helper()
	h := New(svc, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	var handler http.Handler = mux
	if hostID != "" {
		handler = withHostID(mux, hostID)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestNew_NilServicePanics(t *testing.T) {
	assert.PanicsWithValue(t, "response agent.New: api.Service must not be nil", func() {
		New(nil, slog.Default())
	})
}

func TestNew_NilLoggerFallsBackToDefault(t *testing.T) {
	h := New(fakeService{}, nil)
	require.NotNil(t, h)
	assert.NotNil(t, h.logger)
}

func TestHandleList_MissingHostContext(t *testing.T) {
	srv := newAgentServer(t, fakeService{}, "")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/commands", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "host_context_missing")
}

func TestHandleList_StatusFilter(t *testing.T) {
	cases := []struct {
		name       string
		query      string
		wantStatus api.Status
	}{
		{
			// Bare GET /api/commands must default to pending so the agent
			// poller never receives terminal rows (completed / failed).
			// Re-delivering an already-handled command would either
			// double-execute or produce a confused log line in the
			// agent's commander.
			name:       "no query defaults to pending",
			query:      "",
			wantStatus: api.StatusPending,
		},
		{
			name:       "explicit status is honored",
			query:      "?status=acked",
			wantStatus: api.StatusAcked,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var capturedStatus api.Status
			svc := fakeService{
				listForHost: func(_ context.Context, _ string, status api.Status) ([]api.Command, error) {
					capturedStatus = status
					return []api.Command{}, nil
				},
			}
			srv := newAgentServer(t, svc, "host-a")

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/commands"+tc.query, nil)
			require.NoError(t, err)
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tc.wantStatus, capturedStatus)
		})
	}
}

func TestHandleList_ServiceError(t *testing.T) {
	svc := fakeService{
		listForHost: func(context.Context, string, api.Status) ([]api.Command, error) {
			return nil, errors.New("db down")
		},
	}
	srv := newAgentServer(t, svc, "host-a")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/commands", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestHandleUpdate(t *testing.T) {
	cases := []struct {
		name       string
		hostID     string
		path       string
		body       string
		updateErr  error
		wantStatus int
		wantBody   string
	}{
		{
			name:       "invalid command id",
			hostID:     "host-a",
			path:       "/api/commands/abc",
			body:       `{"status":"acked"}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid_command_id",
		},
		{
			name:       "missing host context",
			hostID:     "",
			path:       "/api/commands/1",
			body:       `{"status":"acked"}`,
			wantStatus: http.StatusUnauthorized,
			wantBody:   "host_context_missing",
		},
		{
			name:       "bad json body",
			hostID:     "host-a",
			path:       "/api/commands/1",
			body:       `{not json`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "bad_body",
		},
		{
			name:       "command not found",
			hostID:     "host-a",
			path:       "/api/commands/1",
			body:       `{"status":"acked"}`,
			updateErr:  api.ErrCommandNotFound,
			wantStatus: http.StatusNotFound,
			wantBody:   "not_found",
		},
		{
			name:       "invalid status transition",
			hostID:     "host-a",
			path:       "/api/commands/1",
			body:       `{"status":"completed"}`,
			updateErr:  api.ErrInvalidStatusTransition,
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid_status",
		},
		{
			name:       "generic backend error",
			hostID:     "host-a",
			path:       "/api/commands/1",
			body:       `{"status":"acked"}`,
			updateErr:  errors.New("db error"),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "internal",
		},
		{
			name:       "happy path returns 204",
			hostID:     "host-a",
			path:       "/api/commands/1",
			body:       `{"status":"acked"}`,
			updateErr:  nil,
			wantStatus: http.StatusNoContent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := fakeService{
				updateStatus: func(_ context.Context, _ api.UpdateStatusRequest) error {
					return tc.updateErr
				},
			}
			srv := newAgentServer(t, svc, tc.hostID)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, srv.URL+tc.path, strings.NewReader(tc.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			if tc.wantBody != "" {
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Contains(t, string(body), tc.wantBody)
			}
		})
	}
}

func TestHandleUpdate_BodyCap(t *testing.T) {
	// A body just over 64 KiB should be rejected by MaxBytesReader.
	svc := fakeService{
		updateStatus: func(context.Context, api.UpdateStatusRequest) error {
			t.Fatal("service should not be called when body decode fails")
			return nil
		},
	}
	srv := newAgentServer(t, svc, "host-a")

	bigPayload, err := json.Marshal(map[string]string{
		"status": "completed",
		"result": strings.Repeat("x", updateBodyCap+1),
	})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut,
		srv.URL+"/api/commands/1", strings.NewReader(string(bigPayload)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
