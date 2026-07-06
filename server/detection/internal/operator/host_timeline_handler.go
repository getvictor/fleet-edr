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

// maxTimelineChain caps the alert-chain scope. The process tree is itself capped at processTreeMaxLimit nodes, so a chain cannot exceed
// that; the cap bounds the OR-clause count against a malformed caller rather than a real chain.
const maxTimelineChain = processTreeMaxLimit

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
	// ?chain= is the alert-chain scope: the client passes one `pid:fromIngestedNs:toIngestedNs` triple per chain process generation
	// (the alerted process plus its ancestors and descendants) so the timeline mirrors the graph's focus. Absent means the full stream.
	chain, ok := parseTimelineChain(q.Get("chain"))
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
		Chain:      chain,
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

// parseTimelineChain parses the optional ?chain= scope: a comma-separated list of `pid:pidversion` pairs, one per alert-chain process
// generation. An empty param means no scope (the full host stream). A malformed pair, a negative value, or more than maxTimelineChain
// entries makes ok=false so the handler rejects it with a 400 rather than scoping to the wrong set.
func parseTimelineChain(raw string) ([]visibilityapi.ProcessGeneration, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, true
	}
	var chain []visibilityapi.ProcessGeneration
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if len(chain) >= maxTimelineChain {
			return nil, false
		}
		pidStr, verStr, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, false
		}
		pid, e1 := strconv.ParseInt(pidStr, 10, 64)
		ver, e2 := strconv.ParseInt(verStr, 10, 64)
		if e1 != nil || e2 != nil || pid < 0 || ver < 0 {
			return nil, false
		}
		chain = append(chain, visibilityapi.ProcessGeneration{PID: pid, PIDVersion: ver})
	}
	return chain, true
}
