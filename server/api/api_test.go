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
	h := New(q, s, slog.Default())

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
	h := New(q, s, slog.Default())

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
	h := New(q, s, slog.Default())

	mux := testMux(h)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/hosts/nonexistent/processes/999?at=1000", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// Historical TestAuthRequired / TestAuthWrongPrefix tests were removed in Phase 1 — the api
// package no longer enforces auth on its own; server/authn/authn_test.go covers the
// middleware path. Integration with middleware is exercised through the main binary's smoke
// tests (server/cmd/fleet-edr-server).
