// Package session serves the Phase 3 login / logout / session-check endpoints.
//
//	POST   /api/v1/session  — public, rate-limited, validates email+password, creates
//	                          session row, sets Set-Cookie, returns {user, csrf_token}.
//	GET    /api/v1/session  — session-required, returns the current {user, csrf_token}.
//	DELETE /api/v1/session  — session-required, deletes the session row, clears cookie.
//
// The shape of the login response body intentionally returns both the user AND the CSRF
// token so the UI can store the CSRF for unsafe methods without a round-trip. The
// cookie itself is HttpOnly + Secure (when TLS is on) + SameSite=Lax so JS cannot read
// the session id.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	"github.com/fleetdm/edr/server/authn"
	"github.com/fleetdm/edr/server/sessions"
	"github.com/fleetdm/edr/server/users"
)

// Handler serves the session endpoints.
type Handler struct {
	users     *users.Store
	sessions  *sessions.Store
	logger    *slog.Logger
	limiter   *ipLimiter
	cookieSec bool // Secure flag on the Set-Cookie; driven by TLSEnabled at construction time
}

// Options tune handler behaviour.
type Options struct {
	// RatePerMinute is the per-source-IP login attempt cap. Defaults to 6 (same order
	// as enrollment's default). An operator can raise this for automated testing but
	// the default keeps brute-force expensive.
	RatePerMinute int
	// CookieSecure controls the `Secure` cookie flag. Set to true when TLS is on; false
	// only for local dev with EDR_ALLOW_INSECURE_HTTP=1 (browsers reject Secure cookies
	// on plain HTTP, so dev mode would otherwise break the UI).
	CookieSecure bool
	// Logger for audit lines.
	Logger *slog.Logger
}

// New builds a session handler. Panics if either store is nil.
func New(us *users.Store, ss *sessions.Store, opts Options) *Handler {
	if us == nil {
		panic("session.New: users store must not be nil")
	}
	if ss == nil {
		panic("session.New: sessions store must not be nil")
	}
	if opts.RatePerMinute <= 0 {
		opts.RatePerMinute = 6
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		users:     us,
		sessions:  ss,
		logger:    logger,
		limiter:   newIPLimiter(rate.Every(time.Minute/time.Duration(opts.RatePerMinute)), opts.RatePerMinute),
		cookieSec: opts.CookieSecure,
	}
}

// RegisterPublicRoutes wires POST /api/v1/session on the given mux. The login endpoint
// is public (there is no session yet); the server caller is responsible for keeping
// GET + DELETE behind the Session middleware.
func (h *Handler) RegisterPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/session", h.handleLogin)
}

// RegisterAuthedRoutes wires GET + DELETE /api/v1/session on the given mux. Caller
// wraps the mux in `authn.Session` + `authn.CSRF` at mount time — see main.go.
func (h *Handler) RegisterAuthedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/session", h.handleGet)
	mux.HandleFunc("DELETE /api/v1/session", h.handleLogout)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// String redacts the password so an accidental %v / slog("req", r) never leaks. Same
// pattern as enrollment.enrollRequest.
func (r loginRequest) String() string {
	return "loginRequest{email=" + r.Email + " password=REDACTED}"
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

// loginBodyCap bounds the POST body — login payloads are tiny (email + password);
// anything larger is either a misuse or a DoS probe.
const loginBodyCap = 4 << 10 // 4 KiB

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)
	ip := remoteIP(r)
	span.SetAttributes(attribute.String("edr.remote_addr", ip))

	if !h.limiter.allow(ip) {
		w.Header().Set("Retry-After", "60")
		h.fail(ctx, w, http.StatusTooManyRequests, "rate_limited", ip, 0, "",
			"edr.auth.reason", "rate_limited")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, loginBodyCap)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.fail(ctx, w, http.StatusBadRequest, "bad_body", ip, 0, "",
			"edr.auth.reason", "bad_body", "err", err.Error())
		return
	}
	if req.Email == "" || req.Password == "" {
		h.fail(ctx, w, http.StatusBadRequest, "bad_body", ip, 0, req.Email,
			"edr.auth.reason", "bad_body", "missing_fields", true)
		return
	}

	u, err := h.users.VerifyPassword(ctx, req.Email, req.Password)
	switch {
	case errors.Is(err, users.ErrNotFound):
		// Same wire response as ErrBadPassword so the caller cannot enumerate emails.
		// The server-side audit log records the distinction so forensics can tell
		// "hit a real account with wrong password" apart from "probed unknown email".
		h.fail(ctx, w, http.StatusUnauthorized, "invalid_credentials", ip, 0, req.Email,
			"edr.auth.reason", "user_not_found")
		return
	case errors.Is(err, users.ErrBadPassword):
		h.fail(ctx, w, http.StatusUnauthorized, "invalid_credentials", ip, 0, req.Email,
			"edr.auth.reason", "password_mismatch")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "login verify", "err", err)
		h.fail(ctx, w, http.StatusInternalServerError, "internal", ip, 0, req.Email,
			"edr.auth.reason", "internal")
		return
	}

	sess, err := h.sessions.Create(ctx, u.ID)
	if err != nil {
		h.logger.ErrorContext(ctx, "session create", "err", err, "edr.user.id", u.ID)
		h.fail(ctx, w, http.StatusInternalServerError, "internal", ip, u.ID, req.Email,
			"edr.auth.reason", "session_create_failed")
		return
	}

	http.SetCookie(w, h.buildCookie(sess))
	span.SetAttributes(
		attribute.String("edr.auth.action", "login"),
		attribute.String("edr.auth.result", "ok"),
		attribute.Int64("edr.user.id", u.ID),
	)
	h.logger.InfoContext(ctx, "login ok",
		"edr.auth.action", "login",
		"edr.user.id", u.ID,
		"edr.user.email", u.Email,
		"edr.session.id_prefix", idPrefix(sess.ID),
		"edr.remote_addr", ip,
	)

	h.writeSessionJSON(w, u, sess)
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := authn.SessionFromContext(ctx)
	if !ok {
		// Middleware mis-wiring; fail loud so the ops team sees it.
		h.logger.ErrorContext(ctx, "GET /session hit without Session on ctx — middleware wiring broken")
		writeJSON(ctx, h.logger, w, http.StatusInternalServerError, errBody{Error: "session_misconfigured"})
		return
	}
	u, err := h.users.Get(ctx, sess.UserID)
	if err != nil {
		h.logger.ErrorContext(ctx, "get user for session", "err", err, "edr.user.id", sess.UserID)
		writeJSON(ctx, h.logger, w, http.StatusInternalServerError, errBody{Error: "internal"})
		return
	}
	h.writeSessionJSON(w, u, sess)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := authn.SessionFromContext(ctx)
	if !ok {
		// No session on ctx — the Session middleware would normally 401 before we got
		// here, but treat this as a permissive "already logged out" and clear the
		// cookie anyway. The logout endpoint is one of those places where being lax
		// about a missing credential is the right UX.
		http.SetCookie(w, h.expireCookie())
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := h.sessions.Delete(ctx, sess.ID); err != nil {
		h.logger.ErrorContext(ctx, "session delete", "err", err, "edr.user.id", sess.UserID)
		writeJSON(ctx, h.logger, w, http.StatusInternalServerError, errBody{Error: "internal"})
		return
	}
	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String("edr.auth.action", "logout"),
		attribute.Int64("edr.user.id", sess.UserID),
	)
	h.logger.InfoContext(ctx, "logout ok",
		"edr.auth.action", "logout",
		"edr.user.id", sess.UserID,
		"edr.session.id_prefix", idPrefix(sess.ID),
	)
	http.SetCookie(w, h.expireCookie())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeSessionJSON(w http.ResponseWriter, u *users.User, sess *sessions.Session) {
	writeJSON(context.Background(), h.logger, w, http.StatusOK, sessionResponse{
		User:      userResponse{ID: u.ID, Email: u.Email},
		CSRFToken: authn.EncodeSessionID(sess.CSRFToken),
	})
}

func (h *Handler) buildCookie(sess *sessions.Session) *http.Cookie {
	return &http.Cookie{
		Name:     authn.SessionCookieName,
		Value:    authn.EncodeSessionID(sess.ID),
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSec,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
		MaxAge:   int(time.Until(sess.ExpiresAt).Seconds()),
	}
}

func (h *Handler) expireCookie() *http.Cookie {
	return &http.Cookie{
		Name:     authn.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSec,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// idPrefix returns the first 8 hex chars of the session id for audit logs. Full ids
// must never land in logs because they're the bearer of session auth.
func idPrefix(id []byte) string {
	const n = 4 // 4 bytes = 8 hex chars
	if len(id) < n {
		return ""
	}
	return toHex(id[:n])
}

func toHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, hex[v>>4], hex[v&0x0f])
	}
	return string(out)
}

// fail writes a typed 4xx/5xx JSON error + audit log. userID is best-effort (0 when the
// email didn't resolve). email in the audit helps forensics but we never echo it in the
// response body so the client cannot enumerate.
func (h *Handler) fail(ctx context.Context, w http.ResponseWriter, status int, code, ip string, userID int64, email string, attrs ...any) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("edr.auth.result", "fail"),
		attribute.Int("http.response.status_code", status),
	)
	logAttrs := append([]any{
		"edr.auth.result", "fail",
		"edr.remote_addr", ip,
		"edr.user.email", email,
	}, attrs...)
	if userID > 0 {
		logAttrs = append(logAttrs, "edr.user.id", userID)
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

// --- ipLimiter mirrors enrollment.ipLimiter. Duplicated to avoid a cross-package
// private export; both packages are short enough that the duplication is a smaller
// cost than the coupling. Refactor into a shared limiter package when we add a third.

type ipLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	buckets map[string]*rate.Limiter
}

func newIPLimiter(limit rate.Limit, burst int) *ipLimiter {
	return &ipLimiter{limit: limit, burst: burst, buckets: make(map[string]*rate.Limiter)}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	rl, ok := l.buckets[ip]
	if !ok {
		rl = rate.NewLimiter(l.limit, l.burst)
		l.buckets[ip] = rl
	}
	return rl.Allow()
}

// remoteIP strips the port from r.RemoteAddr. Falls back to the raw field if the host
// portion is ambiguous (IPv6 without port, etc).
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
