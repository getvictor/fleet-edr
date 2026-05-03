package audit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
)

// Handler serves GET /api/v1/audit. Cookie-auth gated by the identity
// Session middleware (caller wraps before mounting); no role gate yet
// because identity is single-admin in the MVP. When multi-user roles
// land the handler grows a `requireAdmin` step at the top of List.
type Handler struct {
	reader api.AuditReader
	logger *slog.Logger
}

// NewHandler builds a handler around the given AuditReader. Panics if
// reader is nil because a Handler that always 500s isn't useful.
func NewHandler(reader api.AuditReader, logger *slog.Logger) *Handler {
	if reader == nil {
		panic("audit.NewHandler: reader must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{reader: reader, logger: logger}
}

// RegisterAuthedRoutes wires GET /api/audit on mux. The mux is
// expected to be wrapped in identity's Session middleware before being
// mounted on the public router; the handler itself does not re-check
// auth. Path is /api/audit (not /api/v1/audit) to match the rest of
// the operator API surface — /api/v1/* in this project is reserved
// for agent-facing endpoints behind the host-token middleware, and
// audit retrieval is an operator-only concern.
func (h *Handler) RegisterAuthedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/audit", h.handleList)
}

type listResponse struct {
	Items []api.AuditRow `json:"items"`
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	filter := api.AuditFilter{
		Action:     api.AuditAction(q.Get("action")),
		TargetType: q.Get("target_type"),
		TargetID:   q.Get("target_id"),
	}
	if v := q.Get("user_id"); v != "" {
		uid, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			httpserver.WriteCookieAuthFailure(ctx, w, h.logger, http.StatusBadRequest, "bad_user_id")
			return
		}
		filter.UserID = &uid
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			httpserver.WriteCookieAuthFailure(ctx, w, h.logger, http.StatusBadRequest, "bad_since")
			return
		}
		filter.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			httpserver.WriteCookieAuthFailure(ctx, w, h.logger, http.StatusBadRequest, "bad_until")
			return
		}
		filter.Until = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			httpserver.WriteCookieAuthFailure(ctx, w, h.logger, http.StatusBadRequest, "bad_limit")
			return
		}
		filter.Limit = n
	}
	if v := q.Get("before_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			httpserver.WriteCookieAuthFailure(ctx, w, h.logger, http.StatusBadRequest, "bad_before_id")
			return
		}
		filter.BeforeID = n
	}

	items, err := h.reader.List(ctx, filter)
	if err != nil {
		h.logger.ErrorContext(ctx, "audit list", "err", err)
		httpserver.WriteCookieAuthFailure(ctx, w, h.logger, http.StatusInternalServerError, "internal")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(listResponse{Items: items}); err != nil {
		h.logger.ErrorContext(ctx, "audit list encode", "err", err)
	}
}
