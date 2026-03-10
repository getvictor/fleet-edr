package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

func TestListHostsEmpty(t *testing.T) {
	s := openTestStore(t)
	// Truncate tables to ensure no stale data from other test runs.
	_, truncErr := s.DB().ExecContext(t.Context(), "TRUNCATE TABLE processes")
	require.NoError(t, truncErr)
	_, truncErr = s.DB().ExecContext(t.Context(), "TRUNCATE TABLE events")
	require.NoError(t, truncErr)

	q := graph.NewQuery(s)
	h := New(q, "", slog.Default())

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

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
	s := openTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, "", slog.Default())

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

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
	s := openTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, "", slog.Default())

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/hosts/nonexistent/processes/999?at=1000", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthRequired(t *testing.T) {
	s := openTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, "secret-key", slog.Default())

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
	s := openTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, "secret-key", slog.Default())

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

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("EDR_TEST_DSN")
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping MySQL tests")
	}
	s, err := store.New(t.Context(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
