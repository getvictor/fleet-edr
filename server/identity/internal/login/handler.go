// Login handler: POST /api/session, GET /api/session, DELETE /api/session.
// Delegates business logic to identity/api.Service; owns HTTP-flavoured
// concerns (rate limiting, request body parsing, cookie construction,
// audit log).

package login

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
)

// Handler serves the login + session-check + logout endpoints.
type Handler struct {
	svc       api.Service
	audit     api.AuditRecorder
	logger    *slog.Logger
	limiter   *httpserver.IPLimiter
	cookieSec bool
}

// Options tune handler behaviour.
type Options struct {
	// RatePerMinute is the per-source-IP login attempt cap. Defaults to 6.
	RatePerMinute int
	// CookieSecure controls the Secure cookie flag. Set true when TLS is on.
	CookieSecure bool
	// Logger for audit lines.
	Logger *slog.Logger
	// Audit is the operator-action audit recorder. Optional: when nil the
	// handler skips the Record calls (existing tests that don't care about
	// the audit trail need not stand one up). When set, login_success,
	// login_failed, and logout each emit one row through this recorder
	// after the action commits.
	Audit api.AuditRecorder
}

// New builds a session handler. Panics if svc is nil.
func New(svc api.Service, opts Options) *Handler {
	if svc == nil {
		panic("login.New: identity service must not be nil")
	}
	if opts.RatePerMinute <= 0 {
		opts.RatePerMinute = 6
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		svc:       svc,
		audit:     opts.Audit,
		logger:    logger,
		limiter:   httpserver.NewIPLimiter(rate.Every(time.Minute/time.Duration(opts.RatePerMinute)), opts.RatePerMinute),
		cookieSec: opts.CookieSecure,
	}
}

// RegisterPublicRoutes wires POST + DELETE /api/session on the given mux.
// Both are public: login mints a session, logout is permissive by design
// (a stale cookie still needs a clearing Set-Cookie).
func (h *Handler) RegisterPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/session", h.handleLogin)
	mux.HandleFunc("DELETE /api/session", h.handleLogout)
}

// RegisterAuthedRoutes wires GET /api/session on the given mux. Caller
// wraps the mux in Session + CSRF middleware before mounting.
func (h *Handler) RegisterAuthedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/session", h.handleGet)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// String redacts the password so an accidental %v / slog("req", r) doesn't leak.
func (r loginRequest) String() string {
	// Use a literal that doesn't have the secret-equals-string shape so
	// static analyzers (Sonar S2068) don't flag the redaction marker as
	// a hard-coded credential. The visible field name is preserved for
	// log readability.
	return "loginRequest{email=" + r.Email + " password:[redacted]}"
}

type userResponse struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

type sessionResponse struct {
	User      userResponse `json:"user"`
	CSRFToken string       `json:"csrf_token"`
}

type errBody struct {
	Error string `json:"error"`
}

const loginBodyCap = 4 << 10 // 4 KiB

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)
	ip := httpserver.RemoteIP(r)
	span.SetAttributes(attribute.String(attrkeys.RemoteAddr, ip))

	if !h.limiter.Allow(ip) {
		w.Header().Set("Retry-After", "60")
		h.fail(ctx, w, http.StatusTooManyRequests, "rate_limited", failInfo{IP: ip},
			attrkeys.AuthReason, "rate_limited")
		// Audit-record the throttled attempt: a brute force shows up as a
		// dense sequence of rate_limited rows, which is an observability
		// signal even though the wire response is just "try again."
		h.recordLoginFailed(ctx, "", ip, "rate_limited")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, loginBodyCap)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.fail(ctx, w, http.StatusBadRequest, "bad_body", failInfo{IP: ip},
			attrkeys.AuthReason, "bad_body", "err", err.Error())
		return
	}
	if req.Email == "" || req.Password == "" {
		h.fail(ctx, w, http.StatusBadRequest, "bad_body", failInfo{IP: ip, Email: req.Email},
			attrkeys.AuthReason, "bad_body", "missing_fields", true)
		return
	}

	result, err := h.svc.Login(ctx, req.Email, req.Password)
	switch {
	case errors.Is(err, api.ErrUserNotFound):
		// Same wire response as ErrBadPassword so the caller cannot enumerate
		// emails. Audit log records the distinction.
		h.fail(ctx, w, http.StatusUnauthorized, "invalid_credentials", failInfo{IP: ip, Email: req.Email},
			attrkeys.AuthReason, "user_not_found")
		h.recordLoginFailed(ctx, req.Email, ip, "user_not_found")
		return
	case errors.Is(err, api.ErrBadPassword):
		h.fail(ctx, w, http.StatusUnauthorized, "invalid_credentials", failInfo{IP: ip, Email: req.Email},
			attrkeys.AuthReason, "password_mismatch")
		h.recordLoginFailed(ctx, req.Email, ip, "password_mismatch")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "login", "err", err)
		h.fail(ctx, w, http.StatusInternalServerError, "internal", failInfo{IP: ip, Email: req.Email},
			attrkeys.AuthReason, "internal")
		return
	}

	http.SetCookie(w, h.buildCookie(result.SessionToken, result.ExpiresAt))
	span.SetAttributes(
		attribute.String(attrkeys.AuthAction, "login"),
		attribute.String(attrkeys.AuthResult, "ok"),
		attribute.Int64(attrkeys.UserID, result.User.ID),
	)
	h.logger.InfoContext(ctx, "login ok",
		attrkeys.AuthAction, "login",
		attrkeys.UserID, result.User.ID,
		attrkeys.UserEmail, result.User.Email,
		attrkeys.SessionIDPrefix, idPrefix(result.SessionToken),
		attrkeys.RemoteAddr, ip,
	)

	h.recordAudit(ctx, api.AuditEvent{
		UserID:     &result.User.ID,
		ActorEmail: result.User.Email,
		Action:     api.AuditAuthLoginSuccess,
		RemoteAddr: ip,
	})

	h.writeSessionJSON(ctx, w, result.User, result.CSRFToken)
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
	ip := httpserver.RemoteIP(r)

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
	writeJSON(ctx, h.logger, w, http.StatusOK, sessionResponse{
		User:      userResponse{ID: u.ID, Email: u.Email},
		CSRFToken: api.EncodeToken(csrfToken),
	})
}

func (h *Handler) buildCookie(sessionToken []byte, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     api.SessionCookieName,
		Value:    api.EncodeToken(sessionToken),
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSec,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	}
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

// failInfo carries the identity + audit fields for a failed login attempt.
type failInfo struct {
	IP     string
	UserID int64
	Email  string
}

func (h *Handler) fail(ctx context.Context, w http.ResponseWriter, status int, code string, info failInfo, attrs ...any) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String(attrkeys.AuthResult, "fail"),
		attribute.Int("http.response.status_code", status),
	)
	logAttrs := append([]any{
		attrkeys.AuthResult, "fail",
		attrkeys.RemoteAddr, info.IP,
		attrkeys.UserEmail, info.Email,
	}, attrs...)
	if info.UserID > 0 {
		logAttrs = append(logAttrs, attrkeys.UserID, info.UserID)
	}
	h.logger.WarnContext(ctx, "login failed", logAttrs...)
	writeJSON(ctx, h.logger, w, status, errBody{Error: code})
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

// recordLoginFailed writes an auth.login.failed audit row with the
// reason the login was rejected. UserID is always nil for failed
// attempts: the email may map to no user (user_not_found), to the
// wrong password (password_mismatch), or be untouched by the rate
// limiter (rate_limited), and recording a UserID would imply the
// attempt got past authentication.
func (h *Handler) recordLoginFailed(ctx context.Context, email, ip, reason string) {
	h.recordAudit(ctx, api.AuditEvent{
		ActorEmail: email,
		Action:     api.AuditAuthLoginFailed,
		RemoteAddr: ip,
		Payload:    map[string]any{"reason": reason},
	})
}
