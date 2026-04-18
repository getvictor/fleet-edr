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

	"github.com/fleetdm/edr/server/store"
)

const testToken = "test-bearer-token"

func newHandler(t *testing.T) *Handler {
	t.Helper()
	return New(store.OpenTestStore(t), testToken, slog.Default(), BuildInfo{Version: "test", Commit: "deadbeef"})
}

func TestLivez(t *testing.T) {
	mux := http.NewServeMux()
	// livez does not need the store.
	h := New(nil, testToken, slog.Default(), BuildInfo{Version: "test"})
	h.RegisterRoutes(mux)

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
	h.RegisterRoutes(mux)

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
	// Close the store so any Ping fails.
	require.NoError(t, s.Close())

	h := New(s, testToken, slog.Default(), BuildInfo{})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var body readyzResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "degraded", body.Status)
	assert.Equal(t, "error", body.Checks["db"].Status)
	// Readiness must NOT leak raw driver / topology details from err.Error(). We only accept the
	// generic "unavailable" marker.
	assert.Equal(t, "unavailable", body.Checks["db"].Error)
}

func TestReadyz_NilStore(t *testing.T) {
	// Guards against a future refactor / mis-construction where the Handler has no store. Must
	// respond with 503 "unavailable" instead of panicking on the nil deref.
	mux := http.NewServeMux()
	h := New(nil, testToken, slog.Default(), BuildInfo{})
	h.RegisterRoutes(mux)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var body readyzResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "degraded", body.Status)
	assert.Equal(t, "unavailable", body.Checks["db"].Error)
}

func TestNew_PanicsOnEmptyAPIKey(t *testing.T) {
	// An empty apiKey previously allowed "Authorization: Bearer " to pass the constant-time
	// compare. Make the invariant a hard panic at construction time so no production path can
	// silently ship the demo bypass.
	assert.PanicsWithValue(t, "ingest.New: apiKey must not be empty", func() {
		_ = New(nil, "", slog.Default(), BuildInfo{})
	})
}

func TestIngest_RejectsEmptyBearerSuffix(t *testing.T) {
	// Regression test for the "Bearer " → empty token bypass. Even if someone managed to land a
	// zero-value &Handler{} (bypassing New), the authorize() guard must still reject.
	h := &Handler{apiKey: "", logger: slog.Default()}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer ")
	assert.False(t, h.authorize(req))
}

func TestIngestUnauthorizedWithoutToken(t *testing.T) {
	mux := http.NewServeMux()
	h := New(nil, "secret-key", slog.Default(), BuildInfo{})
	h.RegisterRoutes(mux)

	body := `[{"event_id":"1","host_id":"h","timestamp_ns":1,"event_type":"exec","payload":{}}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestIngestUnauthorizedWithWrongToken(t *testing.T) {
	mux := http.NewServeMux()
	h := New(nil, "secret-key", slog.Default(), BuildInfo{})
	h.RegisterRoutes(mux)

	body := `[{"event_id":"1","host_id":"h","timestamp_ns":1,"event_type":"exec","payload":{}}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer not-the-right-one")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestIngestInvalidJSON(t *testing.T) {
	mux := http.NewServeMux()
	h := New(nil, testToken, slog.Default(), BuildInfo{})
	h.RegisterRoutes(mux)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBufferString("not json"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestIngestMissingFields(t *testing.T) {
	mux := http.NewServeMux()
	h := New(nil, testToken, slog.Default(), BuildInfo{})
	h.RegisterRoutes(mux)

	events := []store.Event{{EventID: "", HostID: "h", TimestampNs: 1, EventType: "exec", Payload: json.RawMessage(`{}`)}}
	body, err := json.Marshal(events)
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestIngestLargeBatchNearLimit(t *testing.T) {
	s := store.OpenTestStore(t)
	h := New(s, testToken, slog.Default(), BuildInfo{})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

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
	require.Less(t, len(body), 10*1024*1024, "test body should be under 10 MB")
	require.Greater(t, len(body), 1*1024*1024, "test body should be over 1 MB")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "large batch should be accepted")
}

func TestIngestDoesNotProcessEvents(t *testing.T) {
	s := store.OpenTestStore(t)
	h := New(s, testToken, slog.Default(), BuildInfo{})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

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
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	count, err := s.CountUnprocessed(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "ingested events should remain unprocessed")
}
