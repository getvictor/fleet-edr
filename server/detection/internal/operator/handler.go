package operator

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

const (
	msgInternalError   = "internal error"
	msgNotFound        = "not found"
	msgInvalidJSONBody = "invalid JSON body"
)

// alertDetailResponse extends Alert with linked event IDs for the
// detail endpoint.
type alertDetailResponse struct {
	api.Alert
	EventIDs []string `json:"event_ids"`
}

// Handler serves the operator-facing detection routes.
type Handler struct {
	svc    api.Service
	logger *slog.Logger
}

// New creates a detection operator handler. Authorization is NOT
// enforced in this package; callers wrap the routes in the
// operator-session middleware (identity.Session, then identity.CSRF
// on unsafe methods) at registration time.
func New(svc api.Service, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{svc: svc, logger: logger}
}

// RegisterRoutes registers the operator routes on the given mux.
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
	hosts, err := h.svc.ListHosts(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "list hosts", "err", err)
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}
	if hosts == nil {
		hosts = []api.HostSummary{}
	}
	h.writeJSON(w, r, hosts)
}

func (h *Handler) handleProcessTree(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("host_id")
	if hostID == "" {
		http.Error(w, "host_id required", http.StatusBadRequest)
		return
	}

	tr := httpserver.ParseTimeRange(r)
	limit := httpserver.ParseIntParam(r, "limit", 2000)
	if limit <= 0 {
		limit = 2000
	}
	if limit > 5000 {
		limit = 5000
	}

	ctx := r.Context()
	roots, err := h.svc.BuildTree(ctx, hostID, tr, limit)
	if err != nil {
		h.logger.ErrorContext(ctx, "build tree", "host_id", hostID, "err", err)
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}
	if roots == nil {
		roots = []api.ProcessNode{}
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

	atTime := httpserver.ParseInt64Param(r, "at", time.Now().UnixNano())

	ctx := r.Context()
	detail, err := h.svc.GetProcessDetail(ctx, hostID, pid, atTime)
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
	f := api.AlertFilter{
		HostID:    r.URL.Query().Get("host_id"),
		Status:    api.AlertStatus(r.URL.Query().Get("status")),
		Severity:  r.URL.Query().Get("severity"),
		ProcessID: httpserver.ParseInt64Param(r, "process_id", 0),
		Limit:     httpserver.ParseIntParam(r, "limit", 100),
	}

	ctx := r.Context()
	alerts, err := h.svc.ListAlerts(ctx, f)
	if err != nil {
		h.logger.ErrorContext(ctx, "list alerts", "err", err)
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}
	if alerts == nil {
		alerts = []api.Alert{}
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
	alert, eventIDs, err := h.svc.GetAlert(ctx, id)
	if err != nil {
		if errors.Is(err, api.ErrAlertNotFound) {
			http.Error(w, msgNotFound, http.StatusNotFound)
			return
		}
		h.logger.ErrorContext(ctx, "get alert", "id", id, "err", err)
		http.Error(w, msgInternalError, http.StatusInternalServerError)
		return
	}
	if eventIDs == nil {
		eventIDs = []string{}
	}
	h.writeJSON(w, r, alertDetailResponse{Alert: alert, EventIDs: eventIDs})
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
	case string(api.AlertStatusOpen),
		string(api.AlertStatusAcknowledged),
		string(api.AlertStatusResolved):
	default:
		http.Error(w, "invalid status: must be open, acknowledged, or resolved", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	userID, _ := identityapi.UserIDFromContext(ctx)
	if _, err := h.svc.UpdateAlertStatus(ctx, id, api.AlertStatus(body.Status), userID); err != nil {
		switch {
		case errors.Is(err, api.ErrAlertNotFound):
			http.Error(w, msgNotFound, http.StatusNotFound)
			return
		case errors.Is(err, api.ErrInvalidAlertTransition):
			http.Error(w, "invalid status transition", http.StatusBadRequest)
			return
		case errors.Is(err, api.ErrInvalidUserUpdater):
			http.Error(w, "invalid user", http.StatusBadRequest)
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

func (h *Handler) writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.ErrorContext(r.Context(), "writeJSON encode failed", "err", err)
	}
}
