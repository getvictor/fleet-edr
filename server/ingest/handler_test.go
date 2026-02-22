package ingest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fleetdm/edr/server/store"
)

func TestHealthEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	// Health doesn't need a store.
	h := &Handler{apiKey: "test"}
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString(body))

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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString("not json"))

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
	body, _ := json.Marshal(events)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBuffer(body))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
