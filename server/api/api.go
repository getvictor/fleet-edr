// Package api provides JSON REST endpoints for the EDR web UI.
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/graph"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/store"
)

var errNotFound = sql.ErrNoRows

const (
	msgInternalError   = "internal error"
	msgNotFound        = "not found"
	msgInvalidJSONBody = "invalid JSON body"
)

// alertDetailResponse extends Alert with linked event IDs for the detail endpoint.
type alertDetailResponse struct {
	store.Alert
	EventIDs []string `json:"event_ids"`
}

// Handler serves the UI-facing API endpoints.
type Handler struct {
	query  *graph.Query
	store  *store.Store
	logger *slog.Logger
}

// New creates an API handler. Authorization is NOT enforced in this package anymore; callers
// wrap the returned mux (or this handler's routes) in the operator-session middleware
// (authn.Session, then authn.CSRF on unsafe methods) at registration time. See buildMux in
// cmd/fleet-edr-server/main.go for the actual wiring.
func New(q *graph.Query, s *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{query: q, store: s, logger: logger}
}

// RegisterRoutes registers the API routes on the given mux. Phase 4
// of the modular-monolith migration moved /api/commands and
// /api/commands/{id} into the response bounded context (see
// server/response/bootstrap); cmd/main now mounts those routes via
// responseCtx.RegisterAgentRoutes / RegisterAuthedRoutes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/hosts", h.handleListHosts)
	mux.HandleFunc("GET /api/hosts/{host_id}/tree", h.handleProcessTree)
	mux.HandleFunc("GET /api/hosts/{host_id}/processes/{pid}", h.handleProcessDetail)

	mux.HandleFunc("GET /api/alerts", h.handleListAlerts)
	mux.HandleFunc("GET /api/alerts/{id}", h.handleGetAlert)
	mux.HandleFunc("PUT /api/alerts/{id}", h.handleUpdateAlertStatus)
}

func (h *Handler) handleListHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, err := h.query.ListHosts(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "list hosts", "err", err)
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}
	if hosts == nil {
		hosts = []store.HostSummary{}
	}

	h.writeJSON(w, r, hosts)
}

func (h *Handler) handleProcessTree(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("host_id")
	if hostID == "" {
		http.Error(w, "host_id required", http.StatusBadRequest)
		return
	}

	tr := parseTimeRange(r)
	limit := parseIntParam(r, "limit", 2000)
	if limit <= 0 {
		limit = 2000
	}
	if limit > 5000 {
		limit = 5000
	}

	ctx := r.Context()
	roots, err := h.query.BuildTree(ctx, hostID, tr, limit)
	if err != nil {
		h.logger.ErrorContext(ctx, "build tree", "host_id", hostID, "err", err)
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}
	if roots == nil {
		roots = []graph.ProcessNode{}
	}

	h.writeJSON(w, r, map[string]any{"roots": roots})
}

func (h *Handler) handleProcessDetail(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}
	if detail == nil {
		http.Error(w, msgNotFound, http.StatusNotFound)
		return
	}

	h.writeJSON(w, r, detail)
}

func (h *Handler) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	f := store.AlertFilter{
		HostID:    r.URL.Query().Get("host_id"),
		Status:    r.URL.Query().Get("status"),
		Severity:  r.URL.Query().Get("severity"),
		ProcessID: parseInt64Param(r, "process_id", 0),
		Limit:     parseIntParam(r, "limit", 100),
	}

	ctx := r.Context()
	alerts, err := h.store.ListAlerts(ctx, f)
	if err != nil {
		h.logger.ErrorContext(ctx, "list alerts", "err", err)
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}
	if alerts == nil {
		alerts = []store.Alert{}
	}

	h.writeJSON(w, r, alerts)
}

func (h *Handler) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid alert id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	alert, err := h.store.GetAlert(ctx, id)
	if err != nil {
		h.logger.ErrorContext(ctx, "get alert", "id", id, "err", err)
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}
	if alert == nil {
		http.Error(w, msgNotFound, http.StatusNotFound)
		return
	}

	eventIDs, err := h.store.GetAlertEventIDs(ctx, id)
	if err != nil {
		h.logger.ErrorContext(ctx, "get alert event ids", "id", id, "err", err)
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}
	if eventIDs == nil {
		eventIDs = []string{}
	}

	h.writeJSON(w, r, alertDetailResponse{Alert: *alert, EventIDs: eventIDs})
}

func (h *Handler) handleUpdateAlertStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid alert id", http.StatusBadRequest)
		return
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, msgInvalidJSONBody, http.StatusBadRequest)
		return
	}

	switch body.Status {
	case "open", "acknowledged", "resolved":
	default:
		http.Error(w, "invalid status: must be open, acknowledged, or resolved", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	// Phase 3: record the authenticated user id on the row so SOC forensics can tell
	// who resolved what. When the handler is invoked outside the session middleware
	// stack (e.g. direct test harness), UserIDFromContext returns false and we pass 0,
	// which UpdateAlertStatus treats as "leave updated_by alone".
	userID, _ := identityapi.UserIDFromContext(ctx)
	if err := h.store.UpdateAlertStatus(ctx, id, body.Status, userID); err != nil {
		if errors.Is(err, errNotFound) {
			http.Error(w, msgNotFound, http.StatusNotFound)
			return
		}
		h.logger.ErrorContext(ctx, "update alert status", "id", id, "err", err)
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}

	if userID > 0 {
		h.logger.InfoContext(ctx, "alert status updated",
			attrkeys.AdminAction, "alert_update",
			"edr.alert.id", id,
			"edr.alert.status", body.Status,
			attrkeys.UserID, userID,
		)
	}

	w.WriteHeader(http.StatusNoContent)
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
