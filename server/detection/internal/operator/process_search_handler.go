package operator

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// searchDefaultLimit / searchMaxLimit bound one page of the fleet-wide process search. The default fits a screen of results; the max
// caps how much a single request can pull so a client cannot ask for the whole fleet's history at once (paginate instead).
const (
	searchDefaultLimit = 50
	searchMaxLimit     = 200
)

// ProcessSearchReader is the fleet-wide process search surface the operator handler serves at GET /api/search/processes (issue #582).
// mysql.Store satisfies it. A dependency distinct from api.Service, matching the HostDetailReader seam, so the alert/host read
// interface and its mocks stay untouched.
type ProcessSearchReader interface {
	SearchProcesses(ctx context.Context, filter api.ProcessSearchFilter, cursor string, limit int) (api.ProcessSearchResult, error)
}

// registerSearchRoutes wires the fleet-wide search routes. Kept in this file alongside the handler so the route + gate + handler unit
// is co-located, matching registerHostDetailRoutes. The /api/search/ prefix deliberately avoids /api/hosts/, where the
// {host_id} wildcard would otherwise capture "search".
func (h *Handler) registerSearchRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/search/processes", h.handleProcessSearch)
}

// SetProcessSearch installs the search read surface. Bootstrap wires it with the detection store in ModeFull; when it is not set the
// route responds 503, mirroring the host-detail seam. Called after New.
func (h *Handler) SetProcessSearch(r ProcessSearchReader) { h.processSearch = r }

// handleProcessSearch serves the fleet-wide hunting query: composable filters over the process table, newest-first, keyset-paginated.
// Gated on process read with a fleet-scoped resource (no host id), like handleListHosts. A malformed cursor is a 400.
func (h *Handler) handleProcessSearch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionProcessRead, identityapi.Resource{Type: "process"}) {
		return
	}
	if h.processSearch == nil {
		h.writeError(ctx, w, http.StatusServiceUnavailable, errInternal)
		return
	}

	q := r.URL.Query()
	filter := api.ProcessSearchFilter{
		HostID:     q.Get("host_id"),
		Path:       q.Get("path"),
		Hash:       q.Get("hash"),
		ExitReason: q.Get("exit_reason"),
		Signing:    q.Get("signing"),
		FromNs:     httpserver.ParseInt64Param(r, "from", 0),
		ToNs:       httpserver.ParseInt64Param(r, "to", 0),
	}
	if raw := q.Get("uid"); raw != "" {
		uid, err := strconv.Atoi(raw)
		if err != nil {
			h.writeError(ctx, w, http.StatusBadRequest, errInvalidUser)
			return
		}
		filter.UID = &uid
	}

	limit := httpserver.ParseIntParam(r, "limit", searchDefaultLimit)
	if limit < 1 {
		limit = searchDefaultLimit
	}
	if limit > searchMaxLimit {
		limit = searchMaxLimit
	}

	result, err := h.processSearch.SearchProcesses(ctx, filter, q.Get("cursor"), limit)
	if err != nil {
		if errors.Is(err, api.ErrInvalidCursor) {
			h.writeError(ctx, w, http.StatusBadRequest, errInvalidCursor)
			return
		}
		h.logger.ErrorContext(ctx, "search processes", "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	h.writeJSON(w, r, result)
}
