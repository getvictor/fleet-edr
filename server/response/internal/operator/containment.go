package operator

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
)

// containmentBodyCap caps POST /api/hosts/{host_id}/containment: a boolean and a reason of at most MaxContainmentReasonLength
// characters, each up to four bytes.
const containmentBodyCap = 16 << 10

// ContainmentService is the host containment surface the operator routes serve.
type ContainmentService interface {
	List(ctx context.Context) ([]api.ContainmentState, error)
	Get(ctx context.Context, hostID string) (api.ContainmentState, error)
	Set(ctx context.Context, actor identityapi.PrincipalRef, remoteAddr, hostID string, contained bool, reason string) (
		api.ContainmentChange, error)
}

// ContainmentHandler serves the host containment routes (#948).
type ContainmentHandler struct {
	svc    ContainmentService
	authz  identityapi.AuthZ
	logger *slog.Logger
}

// NewContainmentHandler builds the handler. svc and authz are required: a nil chokepoint would bypass the role matrix.
func NewContainmentHandler(svc ContainmentService, authz identityapi.AuthZ, logger *slog.Logger) *ContainmentHandler {
	if svc == nil || authz == nil {
		panic("response operator.NewContainmentHandler: svc and authz must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ContainmentHandler{svc: svc, authz: authz, logger: logger}
}

// RegisterRoutes wires the containment routes. The caller wraps them in the session and CSRF middleware.
func (h *ContainmentHandler) RegisterRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/containment", h.handleList)
	mux.HandleFunc("GET /api/hosts/{host_id}/containment", h.handleGet)
	mux.HandleFunc("POST /api/hosts/{host_id}/containment", h.handleSet)
}

type containmentRequest struct {
	Contained *bool  `json:"contained"`
	Reason    string `json:"reason"`
}

// handleList returns every host with a containment state, for the host list's badges. Authorized as host.read over hosts, as the host
// list itself is.
func (h *ContainmentHandler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionHostRead, identityapi.Resource{Type: "host"}) {
		return
	}
	states, err := h.svc.List(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "list containment", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, map[string][]api.ContainmentState{"items": states})
}

func (h *ContainmentHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionHostRead, identityapi.Resource{Type: "host", ID: hostID}) {
		return
	}
	state, err := h.svc.Get(ctx, hostID)
	if err != nil {
		h.logger.ErrorContext(ctx, "get containment", attrkeys.HostID, hostID, "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, state)
}

// handleSet contains or releases a host. Authorized as host.isolate before the body is read, so a caller without it learns nothing
// about the request's validity; the chokepoint also requires a recent authentication for an interactive session.
func (h *ContainmentHandler) handleSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionHostIsolate, identityapi.Resource{Type: "host", ID: hostID}) {
		return
	}
	// The whole capped body must be one JSON object with a contained value, so a valid change cannot carry other data after it.
	var body containmentRequest
	switch outcome := httpserver.DecodeCappedJSON(r, containmentBodyCap, &body); {
	case outcome == httpserver.BodyTooLarge:
		writeErr(ctx, h.logger, w, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	case outcome != httpserver.BodyOK || body.Contained == nil:
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "bad_body")
		return
	}
	var actor identityapi.PrincipalRef
	if a, ok := identityapi.ActorFromContext(ctx); ok {
		actor = a.Principal
	}
	change, err := h.svc.Set(ctx, actor, httpserver.ClientIP(r), hostID, *body.Contained, body.Reason)
	switch {
	case errors.Is(err, api.ErrContainmentReasonRequired):
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "reason_required")
		return
	case errors.Is(err, api.ErrContainmentReasonTooLong):
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "reason_too_long")
		return
	case errors.Is(err, api.ErrContainmentHostNotFound):
		writeErr(ctx, h.logger, w, http.StatusNotFound, "host_not_found")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "set containment", attrkeys.HostID, hostID, "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String(attrkeys.AdminAction, "host_containment"),
		attribute.String(attrkeys.HostID, hostID),
		attribute.Bool("edr.containment.contained", change.State.Contained),
		attribute.Int64("edr.containment.version", change.State.Version),
		attribute.Bool("edr.containment.changed", change.Changed),
	)
	h.logger.InfoContext(ctx, "admin host containment",
		attrkeys.AdminAction, "host_containment", attrkeys.HostID, hostID,
		"edr.containment.contained", change.State.Contained, "edr.containment.version", change.State.Version,
		"edr.containment.changed", change.Changed, "edr.command.id", change.CommandID,
	)
	writeJSON(ctx, h.logger, w, http.StatusOK, change)
}
