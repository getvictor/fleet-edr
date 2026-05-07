// Login handler: GET /api/session (who-am-i) and DELETE /api/session
// (logout). The Phase 4 OIDC + break-glass refactor replaced the
// password-based POST /api/session login path with the dedicated
// `/api/auth/login` (OIDC) and `/admin/break-glass` flows; the legacy
// POST handler was retired in Phase 5b along with Service.Login.
//
// This handler owns HTTP-flavoured concerns for the session-read +
// session-delete surface: cookie parsing, audit log emission on
// logout, and the session-JSON response shape returned by GET.

package login

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
)

// Handler serves the session-check + logout endpoints.
type Handler struct {
	svc       api.Service
	audit     api.AuditRecorder
	logger    *slog.Logger
	cookieSec bool
}

// Options tune handler behaviour.
type Options struct {
	// CookieSecure controls the Secure cookie flag. Set true when TLS is on.
	CookieSecure bool
	// Logger for audit lines.
	Logger *slog.Logger
	// Audit is the operator-action audit recorder. Optional: when nil the
	// handler skips the Record calls (existing tests that don't care about
	// the audit trail need not stand one up). When set, the logout path
	// emits one row through this recorder after the action commits.
	Audit api.AuditRecorder
}

// New builds a session handler. Panics if svc is nil.
func New(svc api.Service, opts Options) *Handler {
	if svc == nil {
		panic("login.New: identity service must not be nil")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		svc:       svc,
		audit:     opts.Audit,
		logger:    logger,
		cookieSec: opts.CookieSecure,
	}
}

// RegisterPublicRoutes wires DELETE /api/session on the given mux.
// Logout is public (and permissive) by design — a stale cookie still
// needs a clearing Set-Cookie regardless of session validity.
func (h *Handler) RegisterPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("DELETE /api/session", h.handleLogout)
}

// RegisterAuthedRoutes wires GET /api/session on the given mux. Caller
// wraps the mux in Session + CSRF middleware before mounting.
func (h *Handler) RegisterAuthedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/session", h.handleGet)
}

type userResponse struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

type sessionResponse struct {
	User       userResponse `json:"user"`
	CSRFToken  string       `json:"csrf_token"`
	AuthMethod string       `json:"auth_method"`
}

type errBody struct {
	Error string `json:"error"`
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := api.SessionFromContext(ctx)
	if !ok {
		h.logger.ErrorContext(ctx, "GET /session hit without Session on ctx -- middleware wiring broken")
		writeJSON(ctx, h.logger, w, http.StatusInternalServerError, errBody{Error: "session_misconfigured"})
		return
	}
	u, err := h.svc.GetUser(ctx, sess.UserID)
	if err != nil {
		h.logger.ErrorContext(ctx, "get user for session", "err", err, attrkeys.UserID, sess.UserID)
		writeJSON(ctx, h.logger, w, http.StatusInternalServerError, errBody{Error: "internal"})
		return
	}
	h.writeSessionJSON(ctx, w, u, sess.CSRFToken)
}

// handleLogout is public (not behind Session middleware). It does its own
// cookie lookup so a stale / expired / unknown cookie still produces a
// clearing Set-Cookie. Idempotent: any decode / lookup failure falls
// through to the cookie clear.
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := httpserver.ClientIP(r)

	raw := h.decodeLogoutToken(r)
	if raw != nil {
		// Resolve the session BEFORE deletion so we can record who logged
		// out. Logout is idempotent on missing sessions, so a failed
		// resolve falls through silently to the cookie clear without an
		// audit row (there is nothing to audit).
		actorUserID, actorEmail := h.resolveLogoutActor(ctx, raw)
		switch err := h.svc.Logout(ctx, raw); {
		case err != nil:
			h.logger.ErrorContext(ctx, "session delete", "err", err)
		case actorUserID != nil:
			trace.SpanFromContext(ctx).SetAttributes(
				attribute.String(attrkeys.AuthAction, "logout"),
			)
			h.logger.InfoContext(ctx, "logout ok",
				attrkeys.AuthAction, "logout",
				attrkeys.SessionIDPrefix, idPrefix(raw),
			)
			h.recordAudit(ctx, api.AuditEvent{
				UserID:     actorUserID,
				ActorEmail: actorEmail,
				Action:     api.AuditAuthLogout,
				RemoteAddr: ip,
			})
		}
	}

	http.SetCookie(w, h.expireCookie())
	w.WriteHeader(http.StatusNoContent)
}

// decodeLogoutToken extracts the raw session token from the logout request,
// returning nil when the cookie is absent, empty, or malformed. Pulled out
// of handleLogout so its happy path is a single early-return instead of a
// double-nested `if cookie { if raw, err := ...`. Returning nil on every
// failure mode preserves logout's "always clear the cookie, never error"
// contract.
func (h *Handler) decodeLogoutToken(r *http.Request) []byte {
	cookie, err := r.Cookie(api.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}
	raw, err := api.DecodeToken(cookie.Value)
	if err != nil {
		return nil
	}
	return raw
}

// resolveLogoutActor looks up the user behind a session token so the audit
// row records the right user_id + email. Returns (nil, "") when the
// session is unknown / expired (logout is idempotent so a missing session
// produces no audit row). When the session resolves but the users row
// fetch fails (e.g. the user was deleted between session create and now),
// returns the user_id with an empty email; the audit row still records
// the user_id, and reviewers can correlate via that.
func (h *Handler) resolveLogoutActor(ctx context.Context, raw []byte) (*int64, string) {
	sess, err := h.svc.GetSession(ctx, raw)
	if err != nil {
		return nil, ""
	}
	uid := sess.UserID
	u, err := h.svc.GetUser(ctx, sess.UserID)
	if err != nil {
		return &uid, ""
	}
	return &uid, u.Email
}

func (h *Handler) writeSessionJSON(ctx context.Context, w http.ResponseWriter, u api.User, csrfToken []byte) {
	// auth_method is read off the session pinned to ctx (Session
	// middleware wired by App.tsx's authed routes). Every session in
	// the system is now minted by either the OIDC callback or the
	// break-glass FinishLogin path; if no session is on ctx the
	// caller is misconfigured (this handler is GET /api/session,
	// always behind Session middleware). The "local_password"
	// fallback remains as a defense-in-depth default since reading
	// it as the empty string would surface as "" in the wire response.
	authMethod := "local_password"
	if sess, ok := api.SessionFromContext(ctx); ok && sess.AuthMethod != "" {
		authMethod = sess.AuthMethod
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, sessionResponse{
		User:       userResponse{ID: u.ID, Email: u.Email},
		CSRFToken:  api.EncodeToken(csrfToken),
		AuthMethod: authMethod,
	})
}

func (h *Handler) expireCookie() *http.Cookie {
	return &http.Cookie{
		Name:     api.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSec,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// idPrefix returns the first 8 hex chars of a session token for audit
// logs. Full tokens must never land in logs because they're the bearer.
func idPrefix(id []byte) string {
	const n = 4
	if len(id) < n {
		return ""
	}
	return hex.EncodeToString(id[:n])
}

func writeJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.ErrorContext(ctx, "session encode response", "err", err)
	}
}

// recordAudit writes one audit row, treating recorder errors as soft:
// log-warn-and-continue. The action being audited (login/logout) has
// already committed by the time we reach this helper, so failing the
// HTTP response on an audit-table hiccup would be worse than a missed
// audit row. The structured warn line preserves the full event for
// log-based reconstruction if needed.
func (h *Handler) recordAudit(ctx context.Context, e api.AuditEvent) {
	if h.audit == nil {
		return
	}
	if err := h.audit.Record(ctx, e); err != nil {
		h.logger.WarnContext(ctx, "audit record",
			"err", err,
			"action", string(e.Action),
			attrkeys.UserEmail, e.ActorEmail,
		)
	}
}
