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

	"github.com/fleetdm/edr/server/authn"
	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

var errNotFound = sql.ErrNoRows

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
// wrap the returned mux (or this handler's routes) in the authn.AdminToken middleware (or,
// when Phase 3 lands, a session-cookie middleware) at registration time.
func New(q *graph.Query, s *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{query: q, store: s, logger: logger}
}

// RegisterRoutes registers the API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/hosts", h.handleListHosts)
	mux.HandleFunc("GET /api/v1/hosts/{host_id}/tree", h.handleProcessTree)
	mux.HandleFunc("GET /api/v1/hosts/{host_id}/processes/{pid}", h.handleProcessDetail)

	mux.HandleFunc("GET /api/v1/alerts", h.handleListAlerts)
	mux.HandleFunc("GET /api/v1/alerts/{id}", h.handleGetAlert)
	mux.HandleFunc("PUT /api/v1/alerts/{id}", h.handleUpdateAlertStatus)

	mux.HandleFunc("GET /api/v1/commands", h.ListCommands)
	mux.HandleFunc("GET /api/v1/commands/{id}", h.handleGetCommand)
	mux.HandleFunc("POST /api/v1/commands", h.handleCreateCommand)
	mux.HandleFunc("PUT /api/v1/commands/{id}", h.UpdateCommandStatus)
}

func (h *Handler) handleListHosts(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "internal error", http.StatusInternalServerError)
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
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if detail == nil {
		http.Error(w, "not found", http.StatusNotFound)
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
		http.Error(w, "internal error", http.StatusInternalServerError)
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
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if alert == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	eventIDs, err := h.store.GetAlertEventIDs(ctx, id)
	if err != nil {
		h.logger.ErrorContext(ctx, "get alert event ids", "id", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
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
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
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
	userID, _ := authn.UserIDFromContext(ctx)
	if err := h.store.UpdateAlertStatus(ctx, id, body.Status, userID); err != nil {
		if errors.Is(err, errNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		h.logger.ErrorContext(ctx, "update alert status", "id", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if userID > 0 {
		h.logger.InfoContext(ctx, "alert status updated",
			"edr.admin.action", "alert_update",
			"edr.alert.id", id,
			"edr.alert.status", body.Status,
			"edr.user.id", userID,
		)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleGetCommand(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid command id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	cmd, err := h.store.GetCommand(ctx, id)
	if err != nil {
		h.logger.ErrorContext(ctx, "get command", "id", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if cmd == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	h.writeJSON(w, r, cmd)
}

func (h *Handler) ListCommands(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// This handler is only wired under the host-token middleware (agents polling their own
	// queue). The host_id is always the authenticated host's id — any query parameter is
	// ignored so a valid token for host A cannot read commands queued for host B. Admin UI
	// command listing (Phase 3) will live under a separate /api/v1/hosts/{host_id}/commands
	// path so the two auth domains cannot collide on a single mux pattern.
	hostID, ok := authn.HostIDFromContext(ctx)
	if !ok {
		http.Error(w, "host context missing", http.StatusUnauthorized)
		return
	}

	status := r.URL.Query().Get("status")

	commands, err := h.store.ListCommands(ctx, hostID, status)
	if err != nil {
		h.logger.ErrorContext(ctx, "list commands", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if commands == nil {
		commands = []store.Command{}
	}

	h.writeJSON(w, r, commands)
}

func (h *Handler) handleCreateCommand(w http.ResponseWriter, r *http.Request) {
	var body struct {
		HostID      string          `json:"host_id"`
		CommandType string          `json:"command_type"`
		Payload     json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.HostID == "" || body.CommandType == "" {
		http.Error(w, "host_id and command_type required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	id, err := h.store.InsertCommand(ctx, store.Command{
		HostID:      body.HostID,
		CommandType: body.CommandType,
		Payload:     body.Payload,
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "create command", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]int64{"id": id}); err != nil {
		h.logger.ErrorContext(ctx, "writeJSON encode failed", "err", err)
	}
}

func (h *Handler) UpdateCommandStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid command id", http.StatusBadRequest)
		return
	}

	var body struct {
		Status string          `json:"status"`
		Result json.RawMessage `json:"result,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	switch body.Status {
	case "acked", "completed", "failed":
	default:
		http.Error(w, "invalid status: must be acked, completed, or failed", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	// Like ListCommands, this handler is host-token-only. Enforce that the command belongs
	// to the authenticated host so agent A cannot ack/complete/fail agent B's commands.
	ctxHostID, ok := authn.HostIDFromContext(ctx)
	if !ok {
		http.Error(w, "host context missing", http.StatusUnauthorized)
		return
	}
	existing, getErr := h.store.GetCommand(ctx, id)
	if getErr != nil {
		h.logger.ErrorContext(ctx, "update command lookup", "id", id, "err", getErr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if existing == nil || existing.HostID != ctxHostID {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := h.store.UpdateCommandStatus(ctx, id, body.Status, body.Result); err != nil {
		if errors.Is(err, errNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		h.logger.ErrorContext(ctx, "update command status", "id", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
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
