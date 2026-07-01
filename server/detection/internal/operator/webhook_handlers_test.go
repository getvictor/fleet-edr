package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/internal/webhook"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// fakeWebhookAdmin is a closure-driven operator.WebhookAdmin stub. An unset closure returns zero values + nil error, so each test pins
// only the branch it exercises. It lets the handler's error paths (which need the store to fail) run without a real MySQL.
type fakeWebhookAdmin struct {
	create     func(context.Context, api.WebhookDestinationInput) (int64, error)
	list       func(context.Context) ([]api.WebhookDestination, error)
	get        func(context.Context, int64) (api.WebhookDestination, error)
	update     func(context.Context, int64, api.WebhookDestinationInput) error
	del        func(context.Context, int64) error
	deliveries func(context.Context, int64, int) ([]api.WebhookDelivery, error)
	load       func(context.Context, int64) (string, []byte, error)
}

func (f fakeWebhookAdmin) CreateWebhookDestination(ctx context.Context, in api.WebhookDestinationInput) (int64, error) {
	if f.create == nil {
		return 1, nil
	}
	return f.create(ctx, in)
}

func (f fakeWebhookAdmin) ListWebhookDestinations(ctx context.Context) ([]api.WebhookDestination, error) {
	if f.list == nil {
		return nil, nil
	}
	return f.list(ctx)
}

func (f fakeWebhookAdmin) GetWebhookDestination(ctx context.Context, id int64) (api.WebhookDestination, error) {
	if f.get == nil {
		return api.WebhookDestination{ID: id, Name: "sink"}, nil
	}
	return f.get(ctx, id)
}

func (f fakeWebhookAdmin) UpdateWebhookDestination(ctx context.Context, id int64, in api.WebhookDestinationInput) error {
	if f.update == nil {
		return nil
	}
	return f.update(ctx, id, in)
}

func (f fakeWebhookAdmin) DeleteWebhookDestination(ctx context.Context, id int64) error {
	if f.del == nil {
		return nil
	}
	return f.del(ctx, id)
}

func (f fakeWebhookAdmin) ListWebhookDeliveries(ctx context.Context, id int64, limit int) ([]api.WebhookDelivery, error) {
	if f.deliveries == nil {
		return nil, nil
	}
	return f.deliveries(ctx, id, limit)
}

func (f fakeWebhookAdmin) LoadWebhookDestinationForDelivery(ctx context.Context, id int64) (string, []byte, error) {
	if f.load == nil {
		return "https://198.51.100.10/hook", []byte("sealed"), nil
	}
	return f.load(ctx, id)
}

// fakeWebhookTester returns a pinned status + error so the handler's outcome mapping (ok, status_code, sanitized reason) is exercised
// without real HTTP.
type fakeWebhookTester struct {
	code int
	err  error
}

func (f fakeWebhookTester) SendTest(context.Context, string, []byte) (int, error) {
	return f.code, f.err
}

func webhookTestLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// serveWebhookHandler builds the operator handler and serves its routes. A nil admin/tester is left unwired so the not-configured
// (503) branches can be reached; dereferencing a non-nil pointer to the value avoids a typed-nil interface satisfying the != nil check.
func serveWebhookHandler(t *testing.T, az identityapi.AuthZ, admin *fakeWebhookAdmin, tester *fakeWebhookTester) *httptest.Server {
	t.Helper()
	h := New(fakeService{}, az, webhookTestLogger())
	if admin != nil {
		h.SetWebhookAdmin(*admin)
	}
	if tester != nil {
		h.SetWebhookTester(*tester)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// webhookDo issues one request and returns the status + full body, closing the body in-function so the caller has nothing to clean up.
func webhookDo(t *testing.T, srv *httptest.Server, method, path, body string) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, rdr)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, b
}

func webhookErrCode(t *testing.T, body []byte) string {
	t.Helper()
	var m map[string]string
	require.NoError(t, json.Unmarshal(body, &m))
	return m["error"]
}

func webhookJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m))
	return m
}

// timeoutErr is a net.Error whose Timeout() is true, standing in for the http.Client per-request timeout so testSendReason's timeout
// branch is exercised without a real slow server.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "dial tcp 203.0.113.9:443: i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

func TestHandleTestWebhook(t *testing.T) {
	t.Parallel()

	t.Run("denied without webhook.manage", func(t *testing.T) {
		t.Parallel()
		srv := serveWebhookHandler(t, denyAllAuthZ{}, &fakeWebhookAdmin{}, &fakeWebhookTester{code: 200})
		status, _ := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks/1/test", "")
		assert.Equal(t, http.StatusForbidden, status)
	})

	t.Run("503 when tester is not configured", func(t *testing.T) {
		t.Parallel()
		srv := serveWebhookHandler(t, allowAllAuthZ{}, &fakeWebhookAdmin{}, nil)
		status, body := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks/1/test", "")
		assert.Equal(t, http.StatusServiceUnavailable, status)
		assert.Equal(t, errWebhookNotConfigured, webhookErrCode(t, body))
	})

	t.Run("invalid id", func(t *testing.T) {
		t.Parallel()
		srv := serveWebhookHandler(t, allowAllAuthZ{}, &fakeWebhookAdmin{}, &fakeWebhookTester{code: 200})
		status, body := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks/0/test", "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, errInvalidWebhookID, webhookErrCode(t, body))
	})

	t.Run("not found maps to 404", func(t *testing.T) {
		t.Parallel()
		admin := &fakeWebhookAdmin{load: func(context.Context, int64) (string, []byte, error) {
			return "", nil, mysql.ErrWebhookNotFound
		}}
		srv := serveWebhookHandler(t, allowAllAuthZ{}, admin, &fakeWebhookTester{code: 200})
		status, _ := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks/9/test", "")
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("2xx reports ok with status code", func(t *testing.T) {
		t.Parallel()
		srv := serveWebhookHandler(t, allowAllAuthZ{}, &fakeWebhookAdmin{}, &fakeWebhookTester{code: 202})
		status, body := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks/1/test", "")
		assert.Equal(t, http.StatusOK, status)
		m := webhookJSON(t, body)
		assert.Equal(t, true, m["ok"])
		assert.EqualValues(t, 202, m["status_code"])
		assert.NotContains(t, m, "error")
	})

	t.Run("non-2xx reports not-ok with status code and no error", func(t *testing.T) {
		t.Parallel()
		srv := serveWebhookHandler(t, allowAllAuthZ{}, &fakeWebhookAdmin{}, &fakeWebhookTester{code: 500})
		_, body := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks/1/test", "")
		m := webhookJSON(t, body)
		assert.Equal(t, false, m["ok"])
		assert.EqualValues(t, 500, m["status_code"])
		assert.NotContains(t, m, "error")
	})

	// The raw send error must never reach the client: the blocked-address error names the resolved internal IP, so the response
	// carries only the sanitized reason.
	t.Run("blocked address is sanitized, not echoed", func(t *testing.T) {
		t.Parallel()
		leaky := fmt.Errorf("post webhook: %w: refusing to connect to blocked address 10.1.2.3", webhook.ErrBlockedURL)
		srv := serveWebhookHandler(t, allowAllAuthZ{}, &fakeWebhookAdmin{}, &fakeWebhookTester{err: leaky})
		_, body := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks/1/test", "")
		m := webhookJSON(t, body)
		assert.Equal(t, false, m["ok"])
		assert.Equal(t, "destination address is not allowed", m["error"])
		assert.NotContains(t, string(body), "10.1.2.3", "the resolved internal IP must not leak into the response")
	})
}

func TestTestSendReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"blocked address", fmt.Errorf("wrap: %w", webhook.ErrBlockedURL), "destination address is not allowed"},
		{"timeout", timeoutErr{}, "request timed out"},
		{"generic transport", errors.New("connection refused"), "delivery failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, testSendReason(tc.err))
		})
	}
}

// TestWebhookAdminErrorBranches exercises the CRUD/deliveries error paths that only fire when the store fails, which the happy-path
// integration test does not reach.
func TestWebhookAdminErrorBranches(t *testing.T) {
	t.Parallel()
	boom := errors.New("store exploded")

	t.Run("list store error is 500", func(t *testing.T) {
		t.Parallel()
		admin := &fakeWebhookAdmin{list: func(context.Context) ([]api.WebhookDestination, error) { return nil, boom }}
		srv := serveWebhookHandler(t, allowAllAuthZ{}, admin, nil)
		status, _ := webhookDo(t, srv, http.MethodGet, "/api/settings/webhooks", "")
		assert.Equal(t, http.StatusInternalServerError, status)
	})

	t.Run("create invalid JSON is 400", func(t *testing.T) {
		t.Parallel()
		srv := serveWebhookHandler(t, allowAllAuthZ{}, &fakeWebhookAdmin{}, nil)
		status, body := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks", "{not json")
		assert.Equal(t, http.StatusBadRequest, status)
		// errInvalidJSONBody is a stable error-code string, not a JSON document, so assert.JSONEq does not apply here.
		assert.Equal(t, errInvalidJSONBody, webhookErrCode(t, body)) //nolint:testifylint // stable error code, not JSON
	})

	t.Run("create validation error is 400", func(t *testing.T) {
		t.Parallel()
		admin := &fakeWebhookAdmin{create: func(context.Context, api.WebhookDestinationInput) (int64, error) {
			return 0, mysql.ErrWebhookName
		}}
		srv := serveWebhookHandler(t, allowAllAuthZ{}, admin, nil)
		status, body := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks", `{"name":""}`)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, errWebhookInvalid, webhookErrCode(t, body))
	})

	t.Run("create sealer-unset is 503", func(t *testing.T) {
		t.Parallel()
		admin := &fakeWebhookAdmin{create: func(context.Context, api.WebhookDestinationInput) (int64, error) {
			return 0, mysql.ErrWebhookSealerUnset
		}}
		srv := serveWebhookHandler(t, allowAllAuthZ{}, admin, nil)
		status, _ := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks", `{"name":"x"}`)
		assert.Equal(t, http.StatusServiceUnavailable, status)
	})

	t.Run("create read-back error is 500", func(t *testing.T) {
		t.Parallel()
		admin := &fakeWebhookAdmin{get: func(context.Context, int64) (api.WebhookDestination, error) {
			return api.WebhookDestination{}, boom
		}}
		srv := serveWebhookHandler(t, allowAllAuthZ{}, admin, nil)
		status, _ := webhookDo(t, srv, http.MethodPost, "/api/settings/webhooks", `{"name":"x"}`)
		assert.Equal(t, http.StatusInternalServerError, status)
	})

	t.Run("update not-found is 404", func(t *testing.T) {
		t.Parallel()
		admin := &fakeWebhookAdmin{update: func(context.Context, int64, api.WebhookDestinationInput) error {
			return mysql.ErrWebhookNotFound
		}}
		srv := serveWebhookHandler(t, allowAllAuthZ{}, admin, nil)
		status, _ := webhookDo(t, srv, http.MethodPut, "/api/settings/webhooks/7", `{"name":"x"}`)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("update read-back error is surfaced", func(t *testing.T) {
		t.Parallel()
		admin := &fakeWebhookAdmin{get: func(context.Context, int64) (api.WebhookDestination, error) {
			return api.WebhookDestination{}, mysql.ErrWebhookNotFound
		}}
		srv := serveWebhookHandler(t, allowAllAuthZ{}, admin, nil)
		status, _ := webhookDo(t, srv, http.MethodPut, "/api/settings/webhooks/7", `{"name":"x"}`)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("delete non-numeric id is 400", func(t *testing.T) {
		t.Parallel()
		srv := serveWebhookHandler(t, allowAllAuthZ{}, &fakeWebhookAdmin{}, nil)
		status, body := webhookDo(t, srv, http.MethodDelete, "/api/settings/webhooks/abc", "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, errInvalidWebhookID, webhookErrCode(t, body))
	})

	t.Run("delete store error is surfaced", func(t *testing.T) {
		t.Parallel()
		admin := &fakeWebhookAdmin{del: func(context.Context, int64) error { return boom }}
		srv := serveWebhookHandler(t, allowAllAuthZ{}, admin, nil)
		status, _ := webhookDo(t, srv, http.MethodDelete, "/api/settings/webhooks/7", "")
		assert.Equal(t, http.StatusInternalServerError, status)
	})

	t.Run("deliveries store error is 500", func(t *testing.T) {
		t.Parallel()
		admin := &fakeWebhookAdmin{deliveries: func(context.Context, int64, int) ([]api.WebhookDelivery, error) {
			return nil, boom
		}}
		srv := serveWebhookHandler(t, allowAllAuthZ{}, admin, nil)
		status, _ := webhookDo(t, srv, http.MethodGet, "/api/settings/webhooks/7/deliveries", "")
		assert.Equal(t, http.StatusInternalServerError, status)
	})

	t.Run("deliveries clamps limit and returns empty slice", func(t *testing.T) {
		t.Parallel()
		var gotLimit int
		admin := &fakeWebhookAdmin{deliveries: func(_ context.Context, _ int64, limit int) ([]api.WebhookDelivery, error) {
			gotLimit = limit
			return nil, nil
		}}
		srv := serveWebhookHandler(t, allowAllAuthZ{}, admin, nil)
		status, body := webhookDo(t, srv, http.MethodGet, "/api/settings/webhooks/7/deliveries?limit=99999", "")
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, webhookDeliveriesMaxLimit, gotLimit, "limit is clamped to the hard maximum")
		assert.Equal(t, "[]", strings.TrimSpace(string(body)), "a nil slice serializes as an empty array, not null")
	})
}
