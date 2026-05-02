// Operator-facing endpoint routes:
//
//	GET  /api/enrollments                          - list enrollments
//	POST /api/enrollments/{host_id}/revoke          - revoke an enrollment
//
// Both are session-gated by cmd/main's wiring (Session + CSRF middleware).
// The handler only takes an api.Service; cmd/main passes a Service that
// is bound to the same store backing the agent-facing enroll handler.

package operator

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/httpserver"
)

// revokeBodyCap caps the JSON body size for POST /revoke. The handler
// only reads two short string fields; matches the 64KiB cap admin uses
// for /api/policy and protects the operator surface from clients that
// stream a large body before any auth check fails.
const revokeBodyCap = 64 << 10

// Handler serves the operator-facing enrollment routes.
type Handler struct {
	svc    api.Service
	logger *slog.Logger
}

// New builds an operator handler. Panics if svc is nil.
func New(svc api.Service, logger *slog.Logger) *Handler {
	if svc == nil {
		panic("operator.New: api.Service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{svc: svc, logger: logger}
}

// RegisterRoutes wires the two operator routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/enrollments", h.handleList)
	mux.HandleFunc("POST /api/enrollments/{host_id}/revoke", h.handleRevoke)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.svc.List(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "list enrollments", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	if rows == nil {
		rows = []api.Enrollment{}
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, rows)
}

type revokeRequest struct {
	Reason string `json:"reason"`
	Actor  string `json:"actor"`
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if hostID == "" {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "missing host_id")
		return
	}

	var body revokeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, revokeBodyCap)).Decode(&body); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "bad_body")
		return
	}
	body.Reason = strings.TrimSpace(body.Reason)
	body.Actor = strings.TrimSpace(body.Actor)
	if body.Reason == "" || body.Actor == "" {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "reason and actor are required")
		return
	}

	err := h.svc.Revoke(ctx, hostID, body.Reason, body.Actor)
	switch {
	case errors.Is(err, api.ErrNotFound):
		writeErr(ctx, h.logger, w, http.StatusNotFound, "not_found")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "revoke enrollment", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String(attrkeys.AdminAction, "revoke"),
		attribute.String(attrkeys.AdminActor, body.Actor),
		attribute.String(attrkeys.HostID, hostID),
	)
	h.logger.WarnContext(ctx, "admin action",
		attrkeys.AdminAction, "revoke",
		attrkeys.AdminActor, body.Actor,
		attrkeys.AdminReason, body.Reason,
		attrkeys.HostID, hostID,
	)

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	httpserver.NoStoreJSON(ctx, logger, w, status, body)
}

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
