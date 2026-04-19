package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/authn"
	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

func setupAlertTestHandler(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	s := store.OpenTestStore(t)
	q := graph.NewQuery(s)
	h := New(q, s, slog.Default())
	return testMux(h), s
}

func TestListAlertsEmpty(t *testing.T) {
	mux, _ := setupAlertTestHandler(t)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/alerts", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var alerts []store.Alert
	err := json.NewDecoder(w.Body).Decode(&alerts)
	require.NoError(t, err)
	assert.Empty(t, alerts)
}

func TestListAlertsWithFilters(t *testing.T) {
	mux, s := setupAlertTestHandler(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, store.Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/bin/sh", ForkTimeNs: 1000})
	require.NoError(t, err)

	_, _, err = s.InsertAlert(ctx, store.Alert{
		HostID: "host-a", RuleID: "r1", Severity: "high", Title: "High alert", ProcessID: procID,
	}, nil)
	require.NoError(t, err)

	t.Run("filter by severity", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/alerts?severity=high", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var alerts []store.Alert
		require.NoError(t, json.NewDecoder(w.Body).Decode(&alerts))
		assert.Len(t, alerts, 1)
	})

	t.Run("filter by severity no match", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/alerts?severity=low", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var alerts []store.Alert
		require.NoError(t, json.NewDecoder(w.Body).Decode(&alerts))
		assert.Empty(t, alerts)
	})
}

func TestGetAlertDetail(t *testing.T) {
	mux, s := setupAlertTestHandler(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, store.Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/bin/sh", ForkTimeNs: 1000})
	require.NoError(t, err)
	err = s.InsertEvents(ctx, []store.Event{
		{EventID: "evt-1", HostID: "host-a", TimestampNs: 1000, EventType: "exec", Payload: json.RawMessage(`{"pid":100}`)},
	})
	require.NoError(t, err)

	alertID, _, err := s.InsertAlert(ctx, store.Alert{
		HostID: "host-a", RuleID: "r1", Severity: "high", Title: "Test alert", Description: "desc", ProcessID: procID,
	}, []string{"evt-1"})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), "GET", fmt.Sprintf("/api/v1/alerts/%d", alertID), nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var detail alertDetailResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&detail))
	assert.Equal(t, "Test alert", detail.Title)
	assert.Equal(t, []string{"evt-1"}, detail.EventIDs)
}

func TestGetAlertNotFoundAPI(t *testing.T) {
	mux, _ := setupAlertTestHandler(t)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/alerts/99999", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateAlertStatusAPI(t *testing.T) {
	mux, s := setupAlertTestHandler(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, store.Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/bin/sh", ForkTimeNs: 1000})
	require.NoError(t, err)

	alertID, _, err := s.InsertAlert(ctx, store.Alert{
		HostID: "host-a", RuleID: "r1", Severity: "high", Title: "Test", ProcessID: procID,
	}, nil)
	require.NoError(t, err)

	t.Run("acknowledge", func(t *testing.T) {
		body := `{"status":"acknowledged"}`
		req := httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/alerts/%d", alertID), strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)

		got, err := s.GetAlert(ctx, alertID)
		require.NoError(t, err)
		assert.Equal(t, "acknowledged", got.Status)
	})

	t.Run("invalid status", func(t *testing.T) {
		body := `{"status":"deleted"}`
		req := httptest.NewRequestWithContext(t.Context(), "PUT", fmt.Sprintf("/api/v1/alerts/%d", alertID), strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("not found", func(t *testing.T) {
		body := `{"status":"resolved"}`
		req := httptest.NewRequestWithContext(t.Context(), "PUT", "/api/v1/alerts/99999", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestUpdateAlertStatus_CapturesUserID locks in the Phase 3 audit contract: when the
// request context carries an authenticated user id (pinned by authn.Session), the
// updated_by column is set on the row. Without a session on ctx, updated_by stays
// NULL — this is the path admin-less direct calls (e.g. internal backfills) take.
func TestUpdateAlertStatus_CapturesUserID(t *testing.T) {
	mux, s := setupAlertTestHandler(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, store.Process{HostID: "host-a", PID: 100, PPID: 1, Path: "/bin/sh", ForkTimeNs: 1000})
	require.NoError(t, err)
	alertID, _, err := s.InsertAlert(ctx, store.Alert{
		HostID: "host-a", RuleID: "r1", Severity: "high", Title: "Test", ProcessID: procID,
	}, nil)
	require.NoError(t, err)

	body := `{"status":"resolved"}`
	req := httptest.NewRequestWithContext(t.Context(), "PUT",
		fmt.Sprintf("/api/v1/alerts/%d", alertID), strings.NewReader(body))
	req = req.WithContext(authn.WithUserIDForTest(req.Context(), 42))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)

	// Verify the updated_by column directly — Alert type doesn't expose it (SOC-only).
	var updatedBy *int64
	err = s.DB().GetContext(ctx, &updatedBy, "SELECT updated_by FROM alerts WHERE id = ?", alertID)
	require.NoError(t, err)
	require.NotNil(t, updatedBy)
	assert.Equal(t, int64(42), *updatedBy)
}
