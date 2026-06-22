package audit

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
)

// Handler serves GET /api/audit-events. Cookie-auth gated by the identity Session middleware (caller wraps before mounting);
// the handler also gates the read on api.ActionAuditRead through the AuthZ chokepoint so only roles whose grants include audit.read
// (auditor, super_admin) can list audit history.
type Handler struct {
	reader api.AuditReader
	authz  api.AuthZ
	logger *slog.Logger
}

// NewHandler builds a handler around the given AuditReader. Panics if reader or authz is nil; both are load-bearing dependencies and a
// Handler that always 500s on either is not useful.
func NewHandler(reader api.AuditReader, authz api.AuthZ, logger *slog.Logger) *Handler {
	if reader == nil {
		panic("audit.NewHandler: reader must not be nil")
	}
	if authz == nil {
		panic("audit.NewHandler: authz must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{reader: reader, authz: authz, logger: logger}
}

// RegisterAuthedRoutes wires GET /api/audit-events on mux. The mux is
// expected to be wrapped in identity's Session middleware before being
// mounted on the public router; the handler itself does not re-check
// auth. Path is /api/audit-events (not /api/v1/audit) to match the
// rest of the operator API surface; /api/v1/* in this project is
// reserved for agent-facing endpoints behind the host-token
// middleware, and audit retrieval is an operator-only concern.
//
// The chokepoint emits an `authz.audit.read` row on every invocation
// of this route (audit.read is exempt from the read_sampling gate),
// so the audit-of-audit invariant holds without any handler-level
// emission.
func (h *Handler) RegisterAuthedRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/audit-events", h.handleList)
}

type listResponse struct {
	Items []api.AuditRow `json:"items"`
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionAuditRead,
		api.Resource{Type: "audit"}) {
		return
	}
	filter, errCode, ok := parseAuditFilter(r.URL.Query())
	if !ok {
		writeListErr(ctx, h.logger, w, http.StatusBadRequest, errCode)
		return
	}
	items, err := h.reader.List(ctx, filter)
	if err != nil {
		h.logger.ErrorContext(ctx, "audit list", "err", err)
		writeListErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, listResponse{Items: items})
}

// parseAuditFilter centralises the per-query-param decode + validate so
// handleList stays at a cognitive complexity below Sonar's S3776 threshold.
// On a parse error returns the wire-format error code (e.g. "bad_user_id")
// alongside ok=false so the caller can write a 400 with the same body
// shape every other operator endpoint uses. Successful parse returns the
// populated filter, "" for the error code, and ok=true.
//
// Per-field decoding is factored into helpers so the parent stays at
// CC<=8 (Sonar's S3776 threshold is 15; the wave-1 ceiling we set on
// ourselves is lower because the function is on the operator hot path).
func parseAuditFilter(q url.Values) (api.AuditFilter, string, bool) {
	f := api.AuditFilter{
		Action:     api.AuditAction(q.Get("action")),
		TargetType: q.Get("target_type"),
		TargetID:   q.Get("target_id"),
	}
	uid, code, ok := parseOptionalUserID(q.Get("user_id"))
	if !ok {
		return f, code, false
	}
	f.UserID = uid

	since, code, ok := parseOptionalTime(q.Get("since"), "bad_since")
	if !ok {
		return f, code, false
	}
	f.Since = since

	until, code, ok := parseOptionalTime(q.Get("until"), "bad_until")
	if !ok {
		return f, code, false
	}
	f.Until = until

	limit, code, ok := parsePositiveInt(q.Get("limit"), "bad_limit")
	if !ok {
		return f, code, false
	}
	f.Limit = limit

	beforeID, code, ok := parsePositiveInt64(q.Get("before_id"), "bad_before_id")
	if !ok {
		return f, code, false
	}
	f.BeforeID = beforeID
	return f, "", true
}

// parseOptionalUserID parses ?user_id=. Empty returns (nil, "", true) because the filter field is optional. A non-empty unparseable
// value returns the wire error code.
func parseOptionalUserID(v string) (*int64, string, bool) {
	if v == "" {
		return nil, "", true
	}
	uid, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil, "bad_user_id", false
	}
	return &uid, "", true
}

// parseOptionalTime parses an RFC3339 query-string time. Empty input returns the zero time; the AuditFilter treats t.IsZero() as "no
// constraint" so the wire shape preserves the optional-filter semantics every operator endpoint shares.
func parseOptionalTime(v, code string) (time.Time, string, bool) {
	if v == "" {
		return time.Time{}, "", true
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, code, false
	}
	return t, "", true
}

// parsePositiveInt parses a strictly-positive integer query parameter. Empty input returns (0, "", true). Non-numeric or non-positive
// inputs return the wire error code.
func parsePositiveInt(v, code string) (int, string, bool) {
	if v == "" {
		return 0, "", true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, code, false
	}
	return n, "", true
}

// parsePositiveInt64 is the int64 sibling of parsePositiveInt; the audit cursor is int64-keyed because the audit_events.id column is
// BIGINT.
func parsePositiveInt64(v, code string) (int64, string, bool) {
	if v == "" {
		return 0, "", true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, code, false
	}
	return n, "", true
}

// writeListErr writes a 4xx / 5xx response from the audit-list endpoint using the project's standard `{"error": "code"}` body.
// NoStoreJSON (not WriteCookieAuthFailure) is the right helper here because these failures are validation / backend-read errors,
// not authentication failures: routing them through WriteCookieAuthFailure would stamp `edr.auth.result=fail` on the active OTel span
// and emit `authn failed` log lines, polluting auth dashboards with parsing errors.
func writeListErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
