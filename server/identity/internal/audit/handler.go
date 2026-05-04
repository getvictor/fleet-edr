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

// Handler serves GET /api/audit. Cookie-auth gated by the identity
// Session middleware (caller wraps before mounting); the handler also
// gates the read on api.ActionAuditRead through the AuthZ chokepoint
// so only roles whose grants include audit.read (auditor, super_admin)
// can list audit history.
type Handler struct {
	reader api.AuditReader
	authz  api.AuthZ
	logger *slog.Logger
}

// NewHandler builds a handler around the given AuditReader. Panics if
// reader or authz is nil; both are load-bearing dependencies and a
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

// RegisterAuthedRoutes wires GET /api/audit on mux. The mux is
// expected to be wrapped in identity's Session middleware before being
// mounted on the public router; the handler itself does not re-check
// auth. Path is /api/audit (not /api/v1/audit) to match the rest of
// the operator API surface; /api/v1/* in this project is reserved for
// agent-facing endpoints behind the host-token middleware, and audit
// retrieval is an operator-only concern.
func (h *Handler) RegisterAuthedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/audit", h.handleList)
}

type listResponse struct {
	Items []api.AuditRow `json:"items"`
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionAuditRead,
		api.Resource{TenantID: api.ActorTenantID(ctx), Type: "audit"}) {
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
func parseAuditFilter(q url.Values) (api.AuditFilter, string, bool) {
	f := api.AuditFilter{
		Action:     api.AuditAction(q.Get("action")),
		TargetType: q.Get("target_type"),
		TargetID:   q.Get("target_id"),
	}
	if v := q.Get("user_id"); v != "" {
		uid, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return f, "bad_user_id", false
		}
		f.UserID = &uid
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, "bad_since", false
		}
		f.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, "bad_until", false
		}
		f.Until = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return f, "bad_limit", false
		}
		f.Limit = n
	}
	if v := q.Get("before_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return f, "bad_before_id", false
		}
		f.BeforeID = n
	}
	return f, "", true
}

// writeListErr writes a 4xx / 5xx response from the audit-list endpoint
// using the project's standard `{"error": "code"}` body. NoStoreJSON
// (not WriteCookieAuthFailure) is the right helper here because these
// failures are validation / backend-read errors, not authentication
// failures: routing them through WriteCookieAuthFailure would stamp
// `edr.auth.result=fail` on the active OTel span and emit `authn failed`
// log lines, polluting auth dashboards with parsing errors.
func writeListErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
