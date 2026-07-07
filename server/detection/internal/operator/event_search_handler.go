package operator

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// EventSearchReader is the fleet-wide connection/DNS artifact search surface (issue #582). The detection mysql.Store satisfies it by
// delegating to the visibility EventArchive, so the operator handler's seams all stay satisfied by one store, matching HostDetailReader.
type EventSearchReader interface {
	SearchEvents(ctx context.Context, filter visibilityapi.EventSearchFilter, cursor string, limit int) (visibilityapi.EventSearchResult, error)
}

// registerEventSearchRoutes wires the connection and DNS search routes. Both live under /api/search/ (like the process search) so the
// {host_id} wildcard on /api/hosts/ cannot capture them.
func (h *Handler) registerEventSearchRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/search/connections", h.handleConnectionSearch)
	mux.HandleFunc("GET /api/search/dns", h.handleDNSSearch)
}

// SetEventSearch installs the event search surface. Bootstrap wires it with the detection store in ModeFull; unset routes 503,
// mirroring the process-search seam.
func (h *Handler) SetEventSearch(r EventSearchReader) { h.eventSearch = r }

// handleConnectionSearch serves GET /api/search/connections: fleet-wide connections to a remote address.
func (h *Handler) handleConnectionSearch(w http.ResponseWriter, r *http.Request) {
	h.serveEventSearch(w, r, "network_connect", "remote_address")
}

// handleDNSSearch serves GET /api/search/dns: fleet-wide DNS queries for a domain.
func (h *Handler) handleDNSSearch(w http.ResponseWriter, r *http.Request) {
	h.serveEventSearch(w, r, "dns_query", "query_name")
}

// serveEventSearch is the shared body of the two artifact-search routes: same gate, param shape, and pagination; they differ only in
// the event type and the query-parameter name carrying the artifact value. Gated on process read with a fleet-scoped resource.
func (h *Handler) serveEventSearch(w http.ResponseWriter, r *http.Request, eventType, valueParam string) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionProcessRead, identityapi.Resource{Type: "process"}) {
		return
	}
	if h.eventSearch == nil {
		h.writeError(ctx, w, http.StatusServiceUnavailable, errInternal)
		return
	}

	q := r.URL.Query()
	// An absent artifact value is allowed: it lists the most recent events of this type across the fleet (newest-first, same
	// pagination), matching how the process search opens on recent processes. A supplied value narrows to that exact address / domain.
	value := q.Get(valueParam)
	fromNs, ok := parseNonNegativeParam(q, "from")
	if !ok {
		h.writeError(ctx, w, http.StatusBadRequest, errBadWindow)
		return
	}
	toNs, ok := parseNonNegativeParam(q, "to")
	if !ok {
		h.writeError(ctx, w, http.StatusBadRequest, errBadWindow)
		return
	}
	// An inverted window (both bounds present, from after to) matches nothing; reject it as a bad request rather than silently
	// returning zero results.
	if fromNs > 0 && toNs > 0 && fromNs > toNs {
		h.writeError(ctx, w, http.StatusBadRequest, errBadWindow)
		return
	}

	limit := parseSearchLimit(q)
	result, err := h.eventSearch.SearchEvents(ctx, visibilityapi.EventSearchFilter{
		EventType: eventType,
		Value:     value,
		HostID:    q.Get("host_id"),
		FromNs:    fromNs,
		ToNs:      toNs,
	}, q.Get("cursor"), limit)
	if err != nil {
		if errors.Is(err, visibilityapi.ErrInvalidEventCursor) {
			h.writeError(ctx, w, http.StatusBadRequest, errInvalidCursor)
			return
		}
		h.logger.ErrorContext(ctx, "search events", "event_type", eventType, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	h.writeJSON(w, r, result)
}

// parseSearchLimit reads the shared search page-size param, defaulting and clamping to the same bounds as the process search.
func parseSearchLimit(q url.Values) int {
	limit := searchDefaultLimit
	if raw := q.Get("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			limit = v
		}
	}
	if limit < 1 {
		limit = searchDefaultLimit
	}
	if limit > searchMaxLimit {
		limit = searchMaxLimit
	}
	return limit
}
