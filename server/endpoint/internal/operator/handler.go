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
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// revokeBodyCap caps the JSON body size for POST /revoke. The handler
// only reads two short string fields; matches the 64KiB cap admin uses
// for /api/policy and protects the operator surface from clients that
// stream a large body before any auth check fails.
const revokeBodyCap = 64 << 10

// Handler serves the operator-facing enrollment routes.
type Handler struct {
	svc    api.Service
	audit  identityapi.AuditRecorder
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

// SetAudit installs the operator audit recorder. Optional: when not
// set, revoke still applies but no audit row is written.
func (h *Handler) SetAudit(rec identityapi.AuditRecorder) { h.audit = rec }

// RegisterRoutes wires the operator routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/enrollments", h.handleList)
	mux.HandleFunc("POST /api/enrollments/{host_id}/revoke", h.handleRevoke)
	mux.HandleFunc("POST /api/enrollments/{host_id}/rotate", h.handleRotate)
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

	h.recordRevokeAudit(r, hostID, body)
	w.WriteHeader(http.StatusNoContent)
}

// recordRevokeAudit emits one audit row for the just-committed enrollment
// revoke. body.Actor / body.Reason are operator-supplied attribution
// strings carried in the payload; the session userID is the
// authenticated identity that signed the request. Soft-fail on audit
// error.
func (h *Handler) recordRevokeAudit(r *http.Request, hostID string, body revokeRequest) {
	if h.audit == nil {
		return
	}
	ctx := r.Context()
	uid, _ := identityapi.UserIDFromContext(ctx)
	var userID *int64
	if uid > 0 {
		u := uid
		userID = &u
	}
	if err := h.audit.Record(ctx, identityapi.AuditEvent{
		UserID:     userID,
		Action:     identityapi.AuditEnrollmentRevoke,
		TargetType: "host",
		TargetID:   hostID,
		RemoteAddr: r.RemoteAddr,
		Payload: map[string]any{
			"actor":  body.Actor,
			"reason": body.Reason,
		},
	}); err != nil {
		h.logger.WarnContext(ctx, "audit record",
			"err", err, "action", string(identityapi.AuditEnrollmentRevoke),
			attrkeys.HostID, hostID,
		)
	}
}

// rotateRequest is the body shape accepted by POST
// /api/enrollments/{host_id}/rotate. Actor + Reason are required so
// the audit row records the operator who triggered the rotation and
// why; making both required avoids silent rotations that audit
// reviewers can't attribute later.
type rotateRequest struct {
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

func (h *Handler) handleRotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if hostID == "" {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "missing host_id")
		return
	}

	var body rotateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, revokeBodyCap)).Decode(&body); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "bad_body")
		return
	}
	body.Actor = strings.TrimSpace(body.Actor)
	body.Reason = strings.TrimSpace(body.Reason)
	if body.Actor == "" || body.Reason == "" {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "actor and reason are required")
		return
	}

	res, err := h.svc.RotateToken(ctx, hostID, api.RotationTriggerOperator, body.Actor, body.Reason)
	switch {
	case errors.Is(err, api.ErrNotFound):
		writeErr(ctx, h.logger, w, http.StatusNotFound, "not_found")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "rotate enrollment", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	// Span attributes mirror the audit row payload so SigNoz dashboards
	// can pivot from the trace to the audit event by trace_id.
	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String(attrkeys.AdminAction, "rotate_token"),
		attribute.String(attrkeys.AdminActor, body.Actor),
		attribute.String(attrkeys.HostID, hostID),
	)
	h.logger.InfoContext(ctx, "host token rotated",
		attrkeys.AdminAction, "rotate_token",
		attrkeys.AdminActor, body.Actor,
		attrkeys.AdminReason, body.Reason,
		attrkeys.HostID, hostID,
		"edr.command.id", commandIDForLog(res.CommandID),
		"edr.previous_token_id_prefix", res.PreviousTokenIDPrefix,
	)
	writeJSON(ctx, h.logger, w, http.StatusOK, res)
}

func writeJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	httpserver.NoStoreJSON(ctx, logger, w, status, body)
}

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}

// commandIDForLog dereferences a *int64 for slog attribute output, returning
// 0 when the rotation committed but no rotate_token command was queued (the
// nil case carries that signal explicitly on the wire via the omitempty JSON
// shape; the access log uses 0 to keep the attribute monomorphic int64
// rather than mixing int64 and "absent").
func commandIDForLog(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
