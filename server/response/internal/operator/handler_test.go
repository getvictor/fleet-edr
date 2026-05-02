package operator

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

func newOperatorServer(t *testing.T, svc api.Service) *httptest.Server {
	t.Helper()
	h := New(svc, slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestNew_NilServicePanics(t *testing.T) {
	assert.PanicsWithValue(t, "response operator.New: api.Service must not be nil", func() {
		New(nil, slog.Default())
	})
}

func TestNew_NilLoggerFallsBackToDefault(t *testing.T) {
	h := New(fakeService{}, nil)
	require.NotNil(t, h)
	assert.NotNil(t, h.logger)
}

func TestHandleCreate(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		insertID   int64
		insertErr  error
		wantStatus int
		wantBody   string
	}{
		{
			name:       "bad json",
			body:       `{not valid`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "bad_body",
		},
		{
			name:       "validation error",
			body:       `{"host_id":"","command_type":"kill_process","payload":{}}`,
			insertErr:  api.ErrInvalidInsertRequest,
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid_request",
		},
		{
			name:       "generic backend error",
			body:       `{"host_id":"host-a","command_type":"kill_process","payload":{}}`,
			insertErr:  errors.New("db down"),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "internal",
		},
		{
			name:       "happy path returns 201 with id",
			body:       `{"host_id":"host-a","command_type":"kill_process","payload":{"pid":1}}`,
			insertID:   42,
			wantStatus: http.StatusCreated,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := fakeService{
				insert: func(context.Context, string, string, []byte) (int64, error) {
					return tc.insertID, tc.insertErr
				},
			}
			srv := newOperatorServer(t, svc)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				srv.URL+"/api/commands", strings.NewReader(tc.body))
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
			if tc.wantStatus == http.StatusCreated {
				var got map[string]int64
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
				assert.Equal(t, tc.insertID, got["id"])
			}
		})
	}
}

func TestHandleCreate_BodyCap(t *testing.T) {
	svc := fakeService{
		insert: func(context.Context, string, string, []byte) (int64, error) {
			t.Fatal("service should not be called when body decode fails")
			return 0, nil
		},
	}
	srv := newOperatorServer(t, svc)

	bigPayload := `{"host_id":"host-a","command_type":"kill_process","payload":"` +
		strings.Repeat("x", createBodyCap+1) + `"}`

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		srv.URL+"/api/commands", strings.NewReader(bigPayload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleGet(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		getCmd     api.Command
		getErr     error
		wantStatus int
		wantBody   string
	}{
		{
			name:       "invalid command id",
			path:       "/api/commands/abc",
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid_command_id",
		},
		{
			name:       "not found",
			path:       "/api/commands/99999",
			getErr:     api.ErrCommandNotFound,
			wantStatus: http.StatusNotFound,
			wantBody:   "not_found",
		},
		{
			name:       "generic backend error",
			path:       "/api/commands/1",
			getErr:     errors.New("db down"),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "internal",
		},
		{
			name:       "happy path returns command",
			path:       "/api/commands/7",
			getCmd:     api.Command{ID: 7, HostID: "host-a", CommandType: "kill_process", Status: api.StatusPending},
			wantStatus: http.StatusOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := fakeService{
				get: func(context.Context, int64) (api.Command, error) {
					return tc.getCmd, tc.getErr
				},
			}
			srv := newOperatorServer(t, svc)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+tc.path, nil)
			require.NoError(t, err)
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			if tc.wantBody != "" {
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Contains(t, string(body), tc.wantBody)
			}
			if tc.wantStatus == http.StatusOK {
				var got api.Command
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
				assert.Equal(t, tc.getCmd.ID, got.ID)
			}
		})
	}
}
