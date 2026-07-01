package operator

import (
	"context"
	"net/http"

	"github.com/fleetdm/edr/server/detection/api"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// HostHealthReader is the per-host agent-health read surface the operator handler serves at GET /api/hosts/{host_id}/health. mysql.Store
// satisfies it by reading the endpoint context's host_health table (same database, shared host_id). It is a dependency distinct from
// api.Service, matching the WebhookAdmin seam, so the alert/host read interface and its test mocks stay untouched (issue #359).
type HostHealthReader interface {
	HostHealth(ctx context.Context, hostID string) (api.HostHealth, error)
}

// SetHostHealth installs the per-host health read surface. Bootstrap wires it with the detection store in ModeFull; when it is not set
// the health route responds 503, mirroring the webhook seam so a minimally-wired handler degrades rather than nil-derefs. Called after
// New.
func (h *Handler) SetHostHealth(r HostHealthReader) { h.hostHealth = r }

// handleHostHealth serves the operator-facing agent-health detail for one host: the server-computed rollup, the snapshot time, and the
// full component conditions the agent reported. Gated on host read, the same grant the Hosts list uses. A host that has never posted a
// snapshot is not a 404: the reader returns HostHealthUnknown so the detail view renders "unknown" for a real host that simply has not
// checked in health yet.
func (h *Handler) handleHostHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if hostID == "" {
		h.writeError(ctx, w, http.StatusBadRequest, errHostIDRequired)
		return
	}
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionHostRead, identityapi.Resource{Type: "host", ID: hostID}) {
		return
	}
	if h.hostHealth == nil {
		h.writeError(ctx, w, http.StatusServiceUnavailable, errInternal)
		return
	}
	health, err := h.hostHealth.HostHealth(ctx, hostID)
	if err != nil {
		h.logger.ErrorContext(ctx, "get host health", "host_id", hostID, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	h.writeJSON(w, r, health)
}
