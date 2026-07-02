package operator

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// HostDetailReader is the single-host identity + liveness read surface the operator handler serves at GET /api/hosts/{host_id}
// (issue #579). mysql.Store satisfies it by joining the hosts row with the endpoint context's enrollments and host_health tables. A
// dependency distinct from api.Service, matching the HostHealthReader seam, so the alert/host read interface and its mocks stay
// untouched.
type HostDetailReader interface {
	HostDetail(ctx context.Context, hostID string) (api.HostDetail, error)
}

// registerHostDetailRoutes wires the host detail route. Kept in this file alongside handleHostDetail so the whole route + gate +
// handler unit is co-located, matching registerHostHealthRoutes.
func (h *Handler) registerHostDetailRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/hosts/{host_id}", h.handleHostDetail)
}

// SetHostDetail installs the host detail read surface. Bootstrap wires it with the detection store in ModeFull; when it is not set the
// route responds 503, mirroring the host-health seam so a minimally-wired handler degrades rather than nil-derefs. Called after New.
func (h *Handler) SetHostDetail(r HostDetailReader) { h.hostDetail = r }

// handleHostDetail serves the identity + liveness view the host page header renders: enrollment identity (kept fresh by the inventory
// check-in), event liveness, and the agent-health rollup. Gated on host read, the same grant the Hosts list uses. An unknown host id
// is a 404; a host that never enrolled still returns with empty identity fields, matching the list's posture.
func (h *Handler) handleHostDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if hostID == "" {
		h.writeError(ctx, w, http.StatusBadRequest, errHostIDRequired)
		return
	}
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionHostRead, identityapi.Resource{Type: "host", ID: hostID}) {
		return
	}
	if h.hostDetail == nil {
		h.writeError(ctx, w, http.StatusServiceUnavailable, errInternal)
		return
	}
	detail, err := h.hostDetail.HostDetail(ctx, hostID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.writeError(ctx, w, http.StatusNotFound, errNotFound)
			return
		}
		h.logger.ErrorContext(ctx, "get host detail", "host_id", hostID, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	h.writeJSON(w, r, detail)
}
