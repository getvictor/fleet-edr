package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

func TestListHostsEmpty(t *testing.T) {
	s := store.OpenTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, s, testAPIToken, slog.Default())

	mux := testMux(h)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/hosts", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var hosts []store.HostSummary
	err := json.NewDecoder(w.Body).Decode(&hosts)
	require.NoError(t, err)
	assert.Empty(t, hosts)
}

func TestProcessTreeEmpty(t *testing.T) {
	s := store.OpenTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, s, testAPIToken, slog.Default())

	mux := testMux(h)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/hosts/nonexistent/tree?from=0&to=999999999999999999", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]json.RawMessage
	err := json.NewDecoder(w.Body).Decode(&body)
	require.NoError(t, err)

	var roots []json.RawMessage
	err = json.Unmarshal(body["roots"], &roots)
	require.NoError(t, err)
	assert.Empty(t, roots)
}

func TestProcessDetailNotFound(t *testing.T) {
	s := store.OpenTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, s, testAPIToken, slog.Default())

	mux := testMux(h)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/hosts/nonexistent/processes/999?at=1000", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthRequired(t *testing.T) {
	s := store.OpenTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, s, "secret-key", slog.Default())

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	t.Run("no auth header", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/hosts", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("valid auth", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/hosts", nil)
		req.Header.Set("Authorization", "Bearer secret-key")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestAuthWrongPrefix(t *testing.T) {
	s := store.OpenTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, s, "secret-key", slog.Default())

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// "Token" prefix instead of "Bearer" should be rejected.
	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Token secret-key")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// "Basic" prefix should also be rejected.
	req = httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Basic secret-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
