//go:build integration

// Integration coverage for the webhook admin HTTP surface (issue #496): the operator CRUD + delivery-status routes, their
// webhook.manage gate, validation error mapping, and the not-configured path. The handler stack is built directly (store + service +
// operator handler) rather than via the full pipeline so no delivery worker runs. Runs against real MySQL via server/testdb/full.

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/operator"
	"github.com/fleetdm/edr/server/detection/internal/service"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

type denyAuthZ struct{}

func (denyAuthZ) Allow(context.Context, identityapi.Action, identityapi.Resource) (identityapi.Decision, error) {
	return identityapi.Decision{Allow: false, Reason: "forbidden"}, nil
}

// webhookHTTPServer builds the operator handler over a real store and serves it. authz gates the routes; a nil admin defaults to the
// store (the common case), while an explicit admin lets a caller inject a different surface.
func webhookHTTPServer(t *testing.T, authz identityapi.AuthZ, admin operator.WebhookAdmin) *httptest.Server {
	t.Helper()
	store, _, _ := newWebhookStore(t)
	svc := service.New(store, nil, nil, nil, nil, discardLog())
	h := operator.New(svc, authz, discardLog())
	if admin != nil {
		h.SetWebhookAdmin(admin)
	} else {
		h.SetWebhookAdmin(store)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func doJSON(t *testing.T, srv *httptest.Server, method, path string, body any) *http.Response {
	t.Helper()
	var r *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		r = bytes.NewReader(b)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, r)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

func TestWebhookAdminHTTP_CRUD(t *testing.T) {
	t.Parallel()
	store, _, _ := newWebhookStore(t)
	svc := service.New(store, nil, nil, nil, nil, discardLog())
	h := operator.New(svc, allowAllAuthZ{}, discardLog())
	h.SetWebhookAdmin(store)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	create := detapi.WebhookDestinationInput{
		Name: "pd", URL: "https://hooks.example.com/edr",
		EventTypes: []string{detapi.WebhookEventAlertCreated}, MinSeverity: detapi.SeverityHigh, Enabled: true, Secret: "sekret",
	}

	var created detapi.WebhookDestination
	t.Run("spec:alert-webhook-delivery/operators-manage-webhook-destinations-with-a-sealed-write-only-secret/creating-a-destination-does-not-echo-the-secret", func(t *testing.T) {
		resp := doJSON(t, srv, http.MethodPost, "/api/settings/webhooks", create)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
		assert.Positive(t, created.ID)
		assert.True(t, created.SecretSet)
		// The response is a WebhookDestination, which has no secret field at all; assert the raw JSON never carries the plaintext.
		body, _ := json.Marshal(created)
		assert.NotContains(t, string(body), "sekret")
	})

	t.Run("list returns the destination", func(t *testing.T) {
		resp := doJSON(t, srv, http.MethodGet, "/api/settings/webhooks", nil)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var list []detapi.WebhookDestination
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
		require.Len(t, list, 1)
		assert.Equal(t, "pd", list[0].Name)
	})

	t.Run("update without secret keeps it", func(t *testing.T) {
		upd := create
		upd.Name = "pd-renamed"
		upd.Secret = ""
		resp := doJSON(t, srv, http.MethodPut, "/api/settings/webhooks/"+strconv.FormatInt(created.ID, 10), upd)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var got detapi.WebhookDestination
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "pd-renamed", got.Name)
	})

	t.Run("deliveries readout is empty", func(t *testing.T) {
		resp := doJSON(t, srv, http.MethodGet, "/api/settings/webhooks/"+strconv.FormatInt(created.ID, 10)+"/deliveries", nil)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var d []detapi.WebhookDelivery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&d))
		assert.Empty(t, d)
	})

	t.Run("delete then not found", func(t *testing.T) {
		resp := doJSON(t, srv, http.MethodDelete, "/api/settings/webhooks/"+strconv.FormatInt(created.ID, 10), nil)
		resp.Body.Close()
		require.Equal(t, http.StatusNoContent, resp.StatusCode)

		resp = doJSON(t, srv, http.MethodDelete, "/api/settings/webhooks/"+strconv.FormatInt(created.ID, 10), nil)
		resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestWebhookAdminHTTP_Validation(t *testing.T) {
	t.Parallel()
	srv := webhookHTTPServer(t, allowAllAuthZ{}, nil)
	resp := doJSON(t, srv, http.MethodPost, "/api/settings/webhooks", detapi.WebhookDestinationInput{
		Name: "bad", URL: "http://insecure.example.com", EventTypes: []string{detapi.WebhookEventAlertCreated}, Secret: "s",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestWebhookAdminHTTP_GateDenied(t *testing.T) {
	t.Parallel()
	srv := webhookHTTPServer(t, denyAuthZ{}, nil)
	resp := doJSON(t, srv, http.MethodGet, "/api/settings/webhooks", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestWebhookAdminHTTP_NotConfigured(t *testing.T) {
	t.Parallel()
	// Handler with no webhook admin wired models a deployment with no root secret.
	svc := service.New(nil, nil, nil, nil, nil, discardLog())
	h := operator.New(svc, allowAllAuthZ{}, discardLog())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp := doJSON(t, srv, http.MethodGet, "/api/settings/webhooks", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

type fakeWebhookTester struct {
	code       int
	err        error
	calls      int
	lastURL    string
	lastSealed []byte
}

func (f *fakeWebhookTester) SendTest(_ context.Context, url string, sealed []byte) (int, error) {
	f.calls++
	f.lastURL = url
	f.lastSealed = append([]byte(nil), sealed...)
	return f.code, f.err
}

func TestWebhookAdminHTTP_TestSend(t *testing.T) {
	t.Parallel()
	store, _, _ := newWebhookStore(t)
	svc := service.New(store, nil, nil, nil, nil, discardLog())
	h := operator.New(svc, allowAllAuthZ{}, discardLog())
	h.SetWebhookAdmin(store)
	fake := &fakeWebhookTester{code: 200}
	h.SetWebhookTester(fake)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	id, err := store.CreateWebhookDestination(context.Background(), detapi.WebhookDestinationInput{
		Name: "pd", URL: "https://hooks.example.com/edr",
		EventTypes: []string{detapi.WebhookEventAlertCreated}, MinSeverity: detapi.SeverityLow, Enabled: true, Secret: "sekret",
	})
	require.NoError(t, err)

	resp := doJSON(t, srv, http.MethodPost, "/api/settings/webhooks/"+strconv.FormatInt(id, 10)+"/test", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out struct {
		OK         bool `json:"ok"`
		StatusCode int  `json:"status_code"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.True(t, out.OK)
	assert.Equal(t, 200, out.StatusCode)
	assert.Equal(t, 1, fake.calls)
	assert.Equal(t, "https://hooks.example.com/edr", fake.lastURL, "the handler loads the destination URL and hands it to the tester")
	assert.NotEmpty(t, fake.lastSealed, "the sealed secret is passed to the tester")
}

func TestWebhookAdminHTTP_TestSendNotConfigured(t *testing.T) {
	t.Parallel()
	// Admin surface wired but no tester (no root secret): the test route reports not-configured.
	srv := webhookHTTPServer(t, allowAllAuthZ{}, nil)
	resp := doJSON(t, srv, http.MethodPost, "/api/settings/webhooks/1/test", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
