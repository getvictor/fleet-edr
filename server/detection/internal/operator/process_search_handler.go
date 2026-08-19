package operator

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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

// validSigningClasses is the accepted signing filter vocabulary, matching signingClassSQL and the UI's SigningVerdictKind. A value
// outside this set is a 400 rather than a silently-unfiltered fleet query, since an analyst must be able to trust that the filter
// they typed was applied.
var validSigningClasses = map[string]bool{
	"unsigned": true, "invalid": true, "ad-hoc": true, "developer-id": true, "platform": true, "signed": true,
}

// validExitReasons is the accepted exit_reason filter vocabulary, the same closed set the graph writes (api.ExitReason*). A value
// outside it is a 400 rather than a silently-empty fleet query, matching the signing filter: an analyst must be able to trust that the
// filter they typed was applied, not silently misspelled into zero results.
var validExitReasons = map[string]bool{
	api.ExitReasonEvent: true, api.ExitReasonTTLReconciliation: true, api.ExitReasonPIDReuse: true,
	api.ExitReasonReExec: true, api.ExitReasonHostReconciled: true,
}

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

	filter, limit, ok := h.parseProcessSearchRequest(ctx, w, r)
	if !ok {
		return
	}

	result, err := h.processSearch.SearchProcesses(ctx, filter, r.URL.Query().Get("cursor"), limit)
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

// parseProcessSearchRequest reads and validates the process-search filter and page limit from the request query. On a bad value it
// writes the 400 and returns ok=false so the handler stops. Extracted from handleProcessSearch so that handler stays under Sonar's
// cognitive-complexity cap (go:S3776): the sequential validation guards live here, one concern per function.
func (h *Handler) parseProcessSearchRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) (api.ProcessSearchFilter, int, bool) {
	q := r.URL.Query()
	filter := api.ProcessSearchFilter{
		HostID:     q.Get("host_id"),
		Path:       q.Get("path"),
		Hash:       q.Get("hash"),
		ExitReason: q.Get("exit_reason"),
		Signing:    q.Get("signing"),
	}
	if sc := filter.Signing; sc != "" && !validSigningClasses[sc] {
		h.writeError(ctx, w, http.StatusBadRequest, errInvalidSigning)
		return filter, 0, false
	}
	if er := filter.ExitReason; er != "" && !validExitReasons[er] {
		h.writeError(ctx, w, http.StatusBadRequest, errInvalidExitReason)
		return filter, 0, false
	}
	// Parse from/to strictly: ParseInt64Param would silently default an unparseable value to 0, turning a mistyped or negative bound
	// into an unbounded fleet scan (COUNT included) instead of a rejected request. A present-but-bad or negative bound is a 400.
	fromNs, ok := parseNonNegativeParam(q, "from")
	if !ok {
		h.writeError(ctx, w, http.StatusBadRequest, errBadWindow)
		return filter, 0, false
	}
	toNs, ok := parseNonNegativeParam(q, "to")
	if !ok {
		h.writeError(ctx, w, http.StatusBadRequest, errBadWindow)
		return filter, 0, false
	}
	filter.FromNs, filter.ToNs = fromNs, toNs
	if raw := q.Get("uid"); raw != "" {
		uid, err := strconv.Atoi(raw)
		if err != nil || uid < 0 {
			h.writeError(ctx, w, http.StatusBadRequest, errInvalidUser)
			return filter, 0, false
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
	return filter, limit, true
}

// parsePIDVersionParam reads the optional `pidversion` query param naming one process generation. Absent -> (nil, true), meaning
// "resolve by as-of instead". Present but unparseable, negative, or wider than a uint32 -> (nil, false) so the caller returns 400: a
// typo must not quietly resolve a different generation than the one asked for, which is the whole point of addressing by identity.
// The result is a pointer because a present zero is a real kernel generation and has to survive as a value, not collapse into absence.
func parsePIDVersionParam(q url.Values) (*uint32, bool) {
	raw := q.Get("pidversion")
	if raw == "" {
		return nil, true
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return nil, false
	}
	pidVersion := uint32(v)
	return &pidVersion, true
}

// parseNonNegativeParam reads an optional non-negative int64 query param. Absent -> (0, true), meaning "no bound". Present but
// unparseable or negative -> (0, false) so the caller returns 400 rather than treating a bad bound as unbounded.
func parseNonNegativeParam(q url.Values, name string) (int64, bool) {
	raw := q.Get(name)
	if raw == "" {
		return 0, true
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}
