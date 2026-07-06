package operator

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// maxTimelinePIDs caps the alert-chain pid filter. The process tree is itself capped at processTreeMaxLimit nodes, so a chain cannot
// exceed that; the cap bounds the IN-list size against a malformed caller rather than a real chain.
const maxTimelinePIDs = processTreeMaxLimit

// HostTimelineReader is the host-scoped merged event timeline surface (issue #583): exec, network_connect, and dns_query events for one
// host interleaved in event-time order. mysql.Store satisfies it by delegating to the visibility EventArchive, the same seam the
// fleet-wide event search uses.
type HostTimelineReader interface {
	HostTimeline(ctx context.Context, filter visibilityapi.HostTimelineFilter, cursor string, limit int) (visibilityapi.EventSearchResult, error)
}

// registerHostTimelineRoutes wires the host timeline route. It lives under /api/hosts/{host_id}/ with an extra path segment, so the
// {host_id} wildcard cannot capture it (unlike the fleet-wide /search routes, which had to live off /api/hosts to avoid that capture).
func (h *Handler) registerHostTimelineRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/hosts/{host_id}/timeline", h.handleHostTimeline)
}

// SetHostTimeline installs the timeline read surface. Bootstrap wires it with the detection store in ModeFull; unset routes 503,
// mirroring the event-search and host-detail seams so a minimally-wired handler degrades rather than nil-derefs.
func (h *Handler) SetHostTimeline(r HostTimelineReader) { h.hostTimeline = r }

// handleHostTimeline serves GET /api/hosts/{host_id}/timeline: one host's exec/network/DNS events interleaved newest-first over an
// event-time window, optionally narrowed by ?type= (a comma list of event classes) and ?text= (a case-insensitive payload substring),
// keyset-paginated. Gated on process read scoped to the host, the same grant the process tree uses.
func (h *Handler) handleHostTimeline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostID := r.PathValue("host_id")
	if hostID == "" {
		h.writeError(ctx, w, http.StatusBadRequest, errHostIDRequired)
		return
	}
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionProcessRead, identityapi.Resource{Type: "process", ID: hostID}) {
		return
	}
	if h.hostTimeline == nil {
		h.writeError(ctx, w, http.StatusServiceUnavailable, errInternal)
		return
	}

	q := r.URL.Query()
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
	// An inverted window (both bounds present, from after to) matches nothing; reject it rather than silently returning zero events,
	// matching the fleet-wide event search.
	if fromNs > 0 && toNs > 0 && fromNs > toNs {
		h.writeError(ctx, w, http.StatusBadRequest, errBadWindow)
		return
	}
	types, ok := parseTimelineTypes(q.Get("type"))
	if !ok {
		h.writeError(ctx, w, http.StatusBadRequest, errInvalidEventType)
		return
	}
	// ?pids= is the alert-chain scope: the client passes the pids of the alerted process plus its ancestors and descendants so the
	// timeline mirrors the graph's focus. Absent means the full host stream.
	pids, ok := parseTimelinePIDs(q.Get("pids"))
	if !ok {
		h.writeError(ctx, w, http.StatusBadRequest, errInvalidPID)
		return
	}

	limit := parseSearchLimit(q)
	result, err := h.hostTimeline.HostTimeline(ctx, visibilityapi.HostTimelineFilter{
		HostID:     hostID,
		FromNs:     fromNs,
		ToNs:       toNs,
		EventTypes: types,
		Text:       q.Get("text"),
		PIDs:       pids,
	}, q.Get("cursor"), limit)
	if err != nil {
		if errors.Is(err, visibilityapi.ErrInvalidEventCursor) {
			h.writeError(ctx, w, http.StatusBadRequest, errInvalidCursor)
			return
		}
		h.logger.ErrorContext(ctx, "host timeline", "host_id", hostID, "err", err)
		h.writeError(ctx, w, http.StatusInternalServerError, errInternal)
		return
	}
	h.writeJSON(w, r, result)
}

// parseTimelineTypes parses the optional ?type= comma list into a validated subset of the timeline event classes. An empty param means
// "all classes" (nil slice; the archive defaults to every class). An unrecognized class makes ok=false so the handler rejects it with a
// 400 rather than silently returning an empty page.
func parseTimelineTypes(raw string) ([]string, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, true
	}
	var types []string
	seen := map[string]bool{}
	for t := range strings.SplitSeq(raw, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !visibilityapi.IsTimelineEventType(t) {
			return nil, false
		}
		if seen[t] {
			continue // dedupe: the allowlist is tiny, so canonicalize a repeated ?type=exec,exec,... to a bounded set
		}
		seen[t] = true
		types = append(types, t)
	}
	return types, true
}

// parseTimelinePIDs parses the optional ?pids= comma list (the alert-chain scope) into a deduped []int64. An empty param means no pid
// filter (nil slice; the full host stream). A non-integer or negative entry, or more than maxTimelinePIDs entries, makes ok=false so the
// handler rejects it with a 400 rather than scoping to the wrong set.
func parseTimelinePIDs(raw string) ([]int64, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, true
	}
	var pids []int64
	seen := map[int64]bool{}
	for p := range strings.SplitSeq(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseInt(p, 10, 64)
		if err != nil || v < 0 {
			return nil, false
		}
		if seen[v] {
			continue // a chain can list a pid more than once across generations; collapse to one IN entry
		}
		if len(pids) >= maxTimelinePIDs {
			return nil, false
		}
		seen[v] = true
		pids = append(pids, v)
	}
	return pids, true
}
