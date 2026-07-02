package operator

import (
	"context"
	"net/http"
	"strconv"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// ActivityHistogramReader is the bucketed process-start count surface the operator handler serves at
// GET /api/hosts/{host_id}/activity-histogram (issue #581). mysql.Store satisfies it. A dependency distinct from api.Service,
// matching the HostDetailReader seam, so the alert/host read interface and its mocks stay untouched.
type ActivityHistogramReader interface {
	ActivityHistogram(ctx context.Context, hostID string, fromNs, toNs int64) (api.ActivityHistogram, error)
}

// registerHistogramRoutes wires the histogram route. Kept in this file alongside handleActivityHistogram so the whole route + gate +
// handler unit is co-located, matching registerHostDetailRoutes.
func (h *Handler) registerHistogramRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/hosts/{host_id}/activity-histogram", h.handleActivityHistogram)
}

// SetActivityHistogram installs the histogram read surface. Bootstrap wires it with the detection store in ModeFull; when it is not
// set the route responds 503, mirroring the host-detail seam. Called after New.
func (h *Handler) SetActivityHistogram(r ActivityHistogramReader) { h.histogram = r }

// handleActivityHistogram serves the host page's activity strip: process-start counts per server-derived time bucket. Gated on host
// read, the same grant the tree uses. A window whose from is not strictly before its to is a 400.
func (h *Handler) handleActivityHistogram(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if hostID == "" {
		h.writeError(ctx, w, http.StatusBadRequest, errHostIDRequired)
		return
	}
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionHostRead, identityapi.Resource{Type: "host", ID: hostID}) {
		return
	}
	fromNs, errFrom := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	toNs, errTo := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
	if errFrom != nil || errTo != nil || fromNs >= toNs {
		h.writeError(ctx, w, http.StatusBadRequest, errBadWindow)
		return
	}
	if h.histogram == nil {
		h.writeError(ctx, w, http.StatusServiceUnavailable, errInternal)
		return
	}
	hist, err := h.histogram.ActivityHistogram(ctx, hostID, fromNs, toNs)
	if err != nil {
		h.logger.ErrorContext(ctx, "get activity histogram", "host_id", hostID, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	h.writeJSON(w, r, hist)
}
