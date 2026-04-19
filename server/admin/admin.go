// Package admin exposes the Phase 1 operator endpoints: list enrollments and revoke an
// individual host. Both are gated on the admin token by server-side middleware (not by this
// package). Every revoke emits an audit log + span attributes so SOC teams can reconstruct
// what changed and when.
package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/enrollment"
)

// Handler serves the admin endpoints. Construct it with the enrollment store + a slog logger.
type Handler struct {
	enrollments *enrollment.Store
	logger      *slog.Logger
}

// New creates an admin handler. The handler does not perform its own auth — wrap it with
// authn.AdminToken at registration time.
func New(es *enrollment.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{enrollments: es, logger: logger}
}

// RegisterRoutes wires the endpoints onto the mux. Callers wrap the returned handler in the
// admin-token middleware before mounting.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/admin/enrollments", h.handleList)
	mux.HandleFunc("POST /api/v1/admin/enrollments/{host_id}/revoke", h.handleRevoke)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	rows, err := h.enrollments.List(r.Context())
	if err != nil {
		h.logger.ErrorContext(r.Context(), "admin list enrollments", "err", err)
		writeErr(r.Context(), h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(r.Context(), h.logger, w, http.StatusOK, rows)
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "bad_body")
		return
	}
	if body.Reason == "" || body.Actor == "" {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "reason and actor are required")
		return
	}

	err := h.enrollments.Revoke(ctx, hostID, body.Reason, body.Actor)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeErr(ctx, h.logger, w, http.StatusNotFound, "not_found")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "admin revoke", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	// Audit the revoke at WARN so it's visible in SigNoz alert queries. Span attributes give
	// SOC teams the query dimensions they expect (`edr.admin.action`, `edr.admin.actor`).
	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String("edr.admin.action", "revoke"),
		attribute.String("edr.admin.actor", body.Actor),
		attribute.String("edr.host_id", hostID),
	)
	h.logger.WarnContext(ctx, "admin action",
		"edr.admin.action", "revoke",
		"edr.admin.actor", body.Actor,
		"edr.admin.reason", body.Reason,
		"edr.host_id", hostID,
	)

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.ErrorContext(ctx, "admin encode response", "err", err)
	}
}

// writeErr serializes a typed error body through the same JSON+no-store headers as writeJSON,
// so admin responses are consistently application/json instead of text/plain. Callers pass a
// short `code` rather than a human sentence where possible.
func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	writeJSON(ctx, logger, w, status, map[string]string{"error": code})
}
