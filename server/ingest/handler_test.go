package ingest

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/authn"
	"github.com/fleetdm/edr/server/store"
)

// withHostID returns a request whose context carries the pinned host_id the real authn
// middleware would set. Use this in tests that exercise handleIngest directly (i.e. bypass
// the mux + middleware chain that the main binary wires up).
func withHostID(req *http.Request, hostID string) *http.Request {
	ctx := authn.WithHostIDForTest(req.Context(), hostID)
	return req.WithContext(ctx)
}

func newHandler(t *testing.T) *Handler {
	t.Helper()
	return New(store.OpenTestStore(t), slog.Default(), BuildInfo{Version: "test", Commit: "deadbeef"})
}

func TestLivez(t *testing.T) {
	mux := http.NewServeMux()
	h := New(nil, slog.Default(), BuildInfo{Version: "test"})
	h.RegisterHealthRoutes(mux)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var body livezResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "ok", body.Status)
	assert.Equal(t, "test", body.Version)
}

func TestReadyz_DBUp(t *testing.T) {
	h := newHandler(t)
	mux := http.NewServeMux()
	h.RegisterHealthRoutes(mux)

	for _, path := range []string{"/readyz", "/health"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "path %s", path)
		var body readyzResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "ok", body.Status)
		assert.Equal(t, "ok", body.Checks["db"].Status)
	}
}

func TestReadyz_DBDown(t *testing.T) {
	s := store.OpenTestStore(t)
	require.NoError(t, s.Close())

	h := New(s, slog.Default(), BuildInfo{})
	mux := http.NewServeMux()
	h.RegisterHealthRoutes(mux)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var body readyzResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "degraded", body.Status)
	assert.Equal(t, "error", body.Checks["db"].Status)
	assert.Equal(t, "unavailable", body.Checks["db"].Error)
}

func TestReadyz_NilStore(t *testing.T) {
	mux := http.NewServeMux()
	h := New(nil, slog.Default(), BuildInfo{})
	h.RegisterHealthRoutes(mux)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var body readyzResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "degraded", body.Status)
	assert.Equal(t, "unavailable", body.Checks["db"].Error)
}

// serveIngest builds the handler wrapped in a mux that pins host_id on context before
// dispatching. Mirrors what the real authn.HostToken middleware does in production.
func serveIngest(t *testing.T, h *Handler, hostID string, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	// http.ServeMux doesn't interact with our pinning helper, so call the inner handler directly.
	h.IngestHandler().ServeHTTP(rec, withHostID(req, hostID))
	return rec
}

func TestIngest_RejectsMissingContext(t *testing.T) {
	// Direct-dispatch without pinning the host_id must 500 so the misconfiguration is loud.
	h := New(nil, slog.Default(), BuildInfo{})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", nil)
	rec := httptest.NewRecorder()
	h.IngestHandler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestIngest_InvalidJSON(t *testing.T) {
	h := newHandler(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBufferString("not json"))
	rec := serveIngest(t, h, "host-a", req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestIngest_MissingFields(t *testing.T) {
	h := newHandler(t)
	events := []store.Event{{EventID: "", HostID: "host-a", TimestampNs: 1, EventType: "exec", Payload: json.RawMessage(`{}`)}}
	body, err := json.Marshal(events)
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBuffer(body))
	rec := serveIngest(t, h, "host-a", req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestIngest_HostIDMismatchRejected(t *testing.T) {
	// The pinned host_id from the token is "host-a"; the event body claims "host-b". Must 400.
	h := newHandler(t)
	events := []store.Event{{
		EventID: "evt-1", HostID: "host-b", TimestampNs: 1, EventType: "exec", Payload: json.RawMessage(`{}`),
	}}
	body, err := json.Marshal(events)
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBuffer(body))
	rec := serveIngest(t, h, "host-a", req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "host_id_mismatch")
}

func TestIngest_LargeBatchNearLimit(t *testing.T) {
	s := store.OpenTestStore(t)
	h := New(s, slog.Default(), BuildInfo{})

	var events []store.Event
	bigPayload := json.RawMessage(`{"pid":1,"ppid":0,"path":"/bin/sh","args":[],"uid":0,"gid":0,"data":"` + strings.Repeat("x", 5000) + `"}`)
	for i := range 800 {
		events = append(events, store.Event{
			EventID:     "large-" + strings.Repeat("a", 10) + "-" + strings.Repeat("0", 4) + string(rune('a'+i%26)),
			HostID:      "host-large",
			TimestampNs: int64(i + 1),
			EventType:   "exec",
			Payload:     bigPayload,
		})
	}
	body, err := json.Marshal(events)
	require.NoError(t, err)
	require.Less(t, len(body), 10*1024*1024)
	require.Greater(t, len(body), 1*1024*1024)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBuffer(body))
	rec := serveIngest(t, h, "host-large", req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestIngest_DoesNotProcessEvents(t *testing.T) {
	s := store.OpenTestStore(t)
	h := New(s, slog.Default(), BuildInfo{})

	events := []store.Event{
		{
			EventID: "noproc-1", HostID: "host-noproc", TimestampNs: 1000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": 700, "parent_pid": 1}`),
		},
	}
	body, err := json.Marshal(events)
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBuffer(body))
	rec := serveIngest(t, h, "host-noproc", req)
	assert.Equal(t, http.StatusOK, rec.Code)

	count, err := s.CountUnprocessed(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "ingested events should remain unprocessed")
}
