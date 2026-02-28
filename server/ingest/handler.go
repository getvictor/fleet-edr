// Package ingest provides HTTP handlers for the EDR event ingestion API.
package ingest

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

// Handler serves the event ingestion API.
type Handler struct {
	store   *store.Store
	builder *graph.Builder
	apiKey  string
	logger  *slog.Logger
}

// New creates an ingestion Handler. The graph builder processes fork/exec/exit
// events into the processes table after each batch insert.
func New(s *store.Store, apiKey string, logger *slog.Logger) *Handler {
	return &Handler{store: s, builder: graph.NewBuilder(s, logger), apiKey: apiKey, logger: logger}
}

// RegisterRoutes registers the API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/events", h.handleIngest)
	mux.HandleFunc("GET /health", h.handleHealth)
}

func (h *Handler) handleIngest(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10 MB limit
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var events []store.Event
	if err := json.Unmarshal(body, &events); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields.
	for i, e := range events {
		if e.EventID == "" || e.HostID == "" || e.EventType == "" || e.TimestampNs == 0 {
			http.Error(w, "event at index "+strconv.Itoa(i)+" missing required fields", http.StatusBadRequest)
			return
		}
	}

	if err := h.store.InsertEvents(events); err != nil {
		h.logger.Error("insert error", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Update the processes table from fork/exec/exit events.
	if err := h.builder.ProcessBatch(events); err != nil {
		h.logger.Error("graph builder error", "err", err)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]int{"accepted": len(events)})
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (h *Handler) authorize(r *http.Request) bool {
	if h.apiKey == "" {
		return true // No key configured — allow all.
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) < len(prefix) {
		return false
	}
	token := auth[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(token), []byte(h.apiKey)) == 1
}
