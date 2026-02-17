// Package ingest provides HTTP handlers for the EDR event ingestion API.
package ingest

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/fleetdm/edr/server/store"
)

// Handler serves the event ingestion API.
type Handler struct {
	store  *store.Store
	apiKey string
}

// New creates an ingestion Handler.
func New(s *store.Store, apiKey string) *Handler {
	return &Handler{store: s, apiKey: apiKey}
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
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields.
	for i, e := range events {
		if e.EventID == "" || e.HostID == "" || e.EventType == "" || e.TimestampNs == 0 {
			http.Error(w, "event at index "+itoa(i)+" missing required fields", http.StatusBadRequest)
			return
		}
	}

	if err := h.store.InsertEvents(events); err != nil {
		log.Printf("ingest: insert error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
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
	return strings.TrimPrefix(auth, "Bearer ") == h.apiKey
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
