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

// reachableBodyCap caps PUT /api/v1/containment/reachable-addresses. It is derived from the limits the set itself allows, rather
// than picked, because a cap below them would refuse a request that every other rule accepts.
//
// The worst case is a full set written entirely in escapes: 64 entries, each with a 200-rune note of non-BMP characters, which JSON
// may legally spell as surrogate pairs at 12 bytes per rune (64 x 200 x 12 = 150 KiB), plus a 1024-rune reason spelled the same way,
// plus the addresses and object syntax. That comes to roughly 169 KiB, so the cap is 256 KiB: above anything the validator would
// accept, and far below a body worth reading to find out it is not this shape.
const reachableBodyCap = 256 << 10

// ReachableService is the reachable-address surface the operator routes serve.
type ReachableService interface {
	Get(ctx context.Context) (api.ReachableSet, error)
	Replace(ctx context.Context, actor identityapi.PrincipalRef, remoteAddr string, addresses []api.ReachableAddress,
		reason string, expected *int64) (api.ReachableSet, error)
}

// ReachableHandler serves the reachable-address routes (issue #1059).
type ReachableHandler struct {
	svc    ReachableService
	authz  identityapi.AuthZ
	logger *slog.Logger
}

// NewReachableHandler builds the handler. svc and authz are required: a nil chokepoint would bypass the role matrix.
func NewReachableHandler(svc ReachableService, authz identityapi.AuthZ, logger *slog.Logger) *ReachableHandler {
	if svc == nil || authz == nil {
		panic("response operator.NewReachableHandler: svc and authz must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ReachableHandler{svc: svc, authz: authz, logger: logger}
}

// RegisterRoutes wires the reachable-address routes. The caller wraps them in the session and CSRF middleware.
func (h *ReachableHandler) RegisterRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/v1/containment/reachable-addresses", h.handleGet)
	mux.HandleFunc("PUT /api/v1/containment/reachable-addresses", h.handleReplace)
}

type reachableRequest struct {
	// Addresses is the whole set, not a delta. The set is replaced whole because it is versioned and delivered whole, and a
	// caller sending only what it wants added could not express a removal.
	//
	// A pointer so an ABSENT list is distinguishable from an empty one. Clearing the set is a real request and stays available as
	// an explicit `"addresses": []`, but a body that omits the field, sends null, or misspells it is a malformed request, and
	// decoding those into an empty slice would silently cut every contained host back to the bare lifeline.
	Addresses *[]api.ReachableAddress `json:"addresses"`
	Reason    string                  `json:"reason"`
	// ExpectedVersion is the set version the caller read before editing. Optional; with it, a set someone else changed in the
	// meantime is reported as a conflict rather than having this operator's edit applied over theirs.
	ExpectedVersion *int64 `json:"expected_version"`
}

func (h *ReachableHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionContainmentConfigRead, identityapi.Resource{Type: "containment_config"}) {
		return
	}
	set, err := h.svc.Get(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "get reachable addresses", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, set)
}

// handleReplace stores a new set. Authorized before the body is read, so a caller without the action learns nothing about the
// request's validity; the chokepoint also requires a recent authentication for an interactive session, because widening this set
// weakens every containment in force.
func (h *ReachableHandler) handleReplace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionContainmentConfigWrite, identityapi.Resource{Type: "containment_config"}) {
		return
	}
	var body reachableRequest
	switch outcome := httpserver.DecodeCappedJSON(r, reachableBodyCap, &body); {
	case outcome == httpserver.BodyTooLarge:
		writeErr(ctx, h.logger, w, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	case outcome != httpserver.BodyOK || body.Addresses == nil:
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "bad_body")
		return
	}
	var actor identityapi.PrincipalRef
	if a, ok := identityapi.ActorFromContext(ctx); ok {
		actor = a.Principal
	}
	set, err := h.svc.Replace(ctx, actor, httpserver.ClientIP(r), *body.Addresses, body.Reason, body.ExpectedVersion)
	if err != nil {
		// Logged with what was ATTEMPTED, not only what went wrong. A replacement that fails after its audit entry could not be
		// committed leaves no durable record at all, and an operator reporting "my change did not save" is asking about a request
		// this line is then the only trace of: who asked, for how many destinations, and against which version.
		h.logger.WarnContext(ctx, "admin containment reachable addresses refused",
			attrkeys.AdminAction, "containment_reachable_update", "edr.actor.id", actor.ID,
			"edr.containment.reachable_count", len(*body.Addresses), "edr.containment.reachable_expected_version", body.ExpectedVersion,
			"err", err)
		h.writeReplaceErr(ctx, w, err)
		return
	}
	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String(attrkeys.AdminAction, "containment_reachable_update"),
		attribute.Int64("edr.containment.reachable_version", set.Version),
		attribute.Int("edr.containment.reachable_count", len(set.Addresses)),
	)
	h.logger.InfoContext(ctx, "admin containment reachable addresses",
		attrkeys.AdminAction, "containment_reachable_update",
		"edr.containment.reachable_version", set.Version, "edr.containment.reachable_count", len(set.Addresses))
	writeJSON(ctx, h.logger, w, http.StatusOK, set)
}

// writeReplaceErr answers a refusal with the code that says which rule it broke. Every validation failure carries the offending
// entry in the error's message, so the operator is told which address to fix rather than that the set was invalid.
func (h *ReachableHandler) writeReplaceErr(ctx context.Context, w http.ResponseWriter, err error) {
	for _, known := range []struct {
		err    error
		status int
		code   string
	}{
		{api.ErrReachableVersionConflict, http.StatusConflict, "version_conflict"},
		{api.ErrReachableReasonRequired, http.StatusBadRequest, "reason_required"},
		{api.ErrReachableReasonTooLong, http.StatusBadRequest, "reason_too_long"},
		{api.ErrReachableTooMany, http.StatusBadRequest, "too_many_addresses"},
		{api.ErrReachableInvalidCIDR, http.StatusBadRequest, "invalid_address"},
		{api.ErrReachableTooBroad, http.StatusBadRequest, "address_too_broad"},
		{api.ErrReachableInvalidPort, http.StatusBadRequest, "invalid_port"},
		{api.ErrReachableInvalidTransport, http.StatusBadRequest, "invalid_transport"},
		{api.ErrReachableNoteTooLong, http.StatusBadRequest, "note_too_long"},
		{api.ErrReachableDuplicate, http.StatusBadRequest, "duplicate_address"},
	} {
		if errors.Is(err, known.err) {
			writeJSON(ctx, h.logger, w, known.status, map[string]string{"error": known.code, "message": err.Error()})
			return
		}
	}
	// The caller above has already logged this with the request's own context, so only the answer is written here.
	writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
}
