// Package api provides JSON REST endpoints for the EDR web UI.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

// Handler serves the UI-facing API endpoints.
type Handler struct {
	query  *graph.Query
	apiKey string
	logger *slog.Logger
}

// New creates an API handler.
func New(q *graph.Query, apiKey string, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{query: q, apiKey: apiKey, logger: logger}
}

// RegisterRoutes registers the API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/hosts", h.handleListHosts)
	mux.HandleFunc("GET /api/v1/hosts/{host_id}/tree", h.handleProcessTree)
	mux.HandleFunc("GET /api/v1/hosts/{host_id}/processes/{pid}", h.handleProcessDetail)
}

func (h *Handler) handleListHosts(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	hosts, err := h.query.ListHosts(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "list hosts", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if hosts == nil {
		hosts = []store.HostSummary{}
	}

	h.writeJSON(w, r, hosts)
}

func (h *Handler) handleProcessTree(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	hostID := r.PathValue("host_id")
	if hostID == "" {
		http.Error(w, "host_id required", http.StatusBadRequest)
		return
	}

	tr := parseTimeRange(r)
	limit := parseIntParam(r, "limit", 500)

	ctx := r.Context()
	roots, err := h.query.BuildTree(ctx, hostID, tr, limit)
	if err != nil {
		h.logger.ErrorContext(ctx, "build tree", "host_id", hostID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if roots == nil {
		roots = []graph.ProcessNode{}
	}

	h.writeJSON(w, r, map[string]any{"roots": roots})
}

func (h *Handler) handleProcessDetail(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	hostID := r.PathValue("host_id")
	pidStr := r.PathValue("pid")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		http.Error(w, "invalid pid", http.StatusBadRequest)
		return
	}

	atTime := parseInt64Param(r, "at", time.Now().UnixNano())

	ctx := r.Context()
	detail, err := h.query.GetDetail(ctx, hostID, pid, atTime)
	if err != nil {
		h.logger.ErrorContext(ctx, "get process detail", "host_id", hostID, "pid", pid, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if detail == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	h.writeJSON(w, r, detail)
}

func (h *Handler) authorize(r *http.Request) bool {
	if h.apiKey == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	token := auth[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(token), []byte(h.apiKey)) == 1
}

func parseTimeRange(r *http.Request) store.TimeRange {
	now := time.Now().UnixNano()
	defaultFrom := now - int64(time.Hour)

	fromNs := parseInt64Param(r, "from", defaultFrom)
	toNs := parseInt64Param(r, "to", now)

	return store.TimeRange{FromNs: fromNs, ToNs: toNs}
}

func parseIntParam(r *http.Request, name string, defaultVal int) int {
	s := r.URL.Query().Get(name)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

func parseInt64Param(r *http.Request, name string, defaultVal int64) int64 {
	s := r.URL.Query().Get(name)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return defaultVal
	}
	return v
}

func (h *Handler) writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.ErrorContext(r.Context(), "writeJSON encode failed", "err", err)
	}
}
