package ingest

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

func TestHealthEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	// Health doesn't need a store.
	h := &Handler{apiKey: "test"}
	h.RegisterRoutes(mux)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("expected 'ok', got %q", rec.Body.String())
	}
}

func TestIngestUnauthorized(t *testing.T) {
	mux := http.NewServeMux()
	h := &Handler{apiKey: "secret-key"}
	h.RegisterRoutes(mux)

	body := `[{"event_id":"1","host_id":"h","timestamp_ns":1,"event_type":"exec","payload":{}}]`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBufferString(body))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestIngestInvalidJSON(t *testing.T) {
	mux := http.NewServeMux()
	h := &Handler{apiKey: ""}
	h.RegisterRoutes(mux)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBufferString("not json"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestIngestMissingFields(t *testing.T) {
	mux := http.NewServeMux()
	h := &Handler{apiKey: ""}
	h.RegisterRoutes(mux)

	events := []store.Event{{EventID: "", HostID: "h", TimestampNs: 1, EventType: "exec", Payload: json.RawMessage(`{}`)}}
	body, _ := json.Marshal(events) //nolint:errcheck // test helper
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBuffer(body))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestIngestLargeBatchNearLimit(t *testing.T) {
	dsn := os.Getenv("EDR_TEST_DSN")
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping MySQL tests")
	}
	s, err := store.New(t.Context(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	h := New(s, "", slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Build a batch of events with large payloads (~5 MB total).
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
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "large batch should be accepted")
}

func TestIngestGraphBuilderErrorDoesNotFailIngest(t *testing.T) {
	dsn := os.Getenv("EDR_TEST_DSN")
	if dsn == "" {
		t.Skip("EDR_TEST_DSN not set; skipping MySQL tests")
	}
	s, err := store.New(t.Context(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	h := New(s, "", slog.Default())
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Send a batch with a valid event and one with a malformed fork payload.
	// The malformed event will cause graph builder to return an error, but
	// the HTTP response should still be 200 (events stored successfully).
	events := []store.Event{
		{
			EventID: "gb-good", HostID: "host-gb", TimestampNs: 1000,
			EventType: "exec",
			Payload:   json.RawMessage(`{"pid": 700, "ppid": 1, "path": "/bin/sh", "args": [], "uid": 0, "gid": 0}`),
		},
		{
			// Valid JSON that stores fine but fails when graph builder unmarshals into forkPayload.
			EventID: "gb-bad", HostID: "host-gb", TimestampNs: 2000,
			EventType: "fork",
			Payload:   json.RawMessage(`{"child_pid": "not_a_number"}`),
		},
	}
	body, _ := json.Marshal(events) //nolint:errcheck // test helper
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/events", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "ingest should succeed even if graph builder fails")

	// Verify events were stored.
	count, err := s.CountEvents(t.Context())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, int64(2))
}
