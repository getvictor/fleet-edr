package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
)

// defaultRedirect is the post-login landing path when the AuthURL
// query string did not pin a `next` parameter or the pin was unsafe.
const defaultRedirect = "/ui/"

// defaultStateTTL is the wave-1 fall-through when caller doesn't
// pin opts.StateTTL. Mirrors config's defaultOIDCStateCookieTTL.
const defaultStateTTL = 5 * time.Minute

// Handler serves the OIDC login + callback routes. Construct via
// NewHandler; mount with RegisterPublicRoutes.
type Handler struct {
	client       *Client
	provisioner  *Provisioner
	sessions     *sessions.Store
	signingKey   []byte
	stateTTL     time.Duration
	cookieSecure bool
	audit        api.AuditRecorder
	logger       *slog.Logger
}

// HandlerOptions configures the Handler. SigningKey is the same key
// used by the session cookie; reusing it (per spec) avoids a second
// secret to rotate. CookieSecure should mirror the deployment's TLS
// state so the state cookie won't leak over plaintext.
type HandlerOptions struct {
	Client       *Client
	Provisioner  *Provisioner
	Sessions     *sessions.Store
	SigningKey   []byte
	StateTTL     time.Duration
	CookieSecure bool
	Audit        api.AuditRecorder
	Logger       *slog.Logger
}

// NewHandler constructs a Handler. Panics on missing dependencies —
// every field is load-bearing in production.
func NewHandler(opts HandlerOptions) *Handler {
	if opts.Client == nil {
		panic("oidc.NewHandler: Client is required")
	}
	if opts.Provisioner == nil {
		panic("oidc.NewHandler: Provisioner is required")
	}
	if opts.Sessions == nil {
		panic("oidc.NewHandler: Sessions is required")
	}
	if len(opts.SigningKey) == 0 {
		panic("oidc.NewHandler: SigningKey is required")
	}
	stateTTL := opts.StateTTL
	if stateTTL <= 0 {
		stateTTL = defaultStateTTL
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		client:       opts.Client,
		provisioner:  opts.Provisioner,
		sessions:     opts.Sessions,
		signingKey:   opts.SigningKey,
		stateTTL:     stateTTL,
		cookieSecure: opts.CookieSecure,
		audit:        opts.Audit,
		logger:       logger,
	}
}

// RegisterPublicRoutes mounts GET /api/auth/login + GET
// /api/auth/callback. Both are pre-auth routes (no session yet).
func (h *Handler) RegisterPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/login", h.handleLogin)
	mux.HandleFunc("GET /api/auth/callback", h.handleCallback)
}

// handleLogin starts the flow: generate per-flow secrets, set the
// signed state cookie, redirect the browser to the IdP. The optional
// ?next= query parameter pins the post-login redirect; unsafe values
// (off-site URLs, javascript: schemes) are dropped silently and the
// flow falls through to defaultRedirect.
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state, nonce, codeVerifier, codeChallenge, err := GenerateFlowSecrets()
	if err != nil {
		h.logger.ErrorContext(ctx, "oidc generate flow secrets", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	redirect := safeRedirect(r.URL.Query().Get("next"))
	cookieValue, err := EncodeStateClaim(h.signingKey, state, nonce, codeVerifier, redirect, time.Now())
	if err != nil {
		h.logger.ErrorContext(ctx, "oidc encode state", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    cookieValue,
		Path:     "/api/auth/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.stateTTL.Seconds()),
	})
	http.Redirect(w, r, h.client.AuthURL(state, nonce, codeChallenge), http.StatusFound)
}

// handleCallback finishes the flow: verify state cookie, exchange
// code, run JIT, mint a session, redirect to the original next URL.
// Every error path returns a 4xx (state-related) or 5xx (engine /
// IdP / DB) with a wire-format reason header so the UI can render a
// directed error page.
func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookie, err := r.Cookie(StateCookieName)
	if err != nil {
		h.fail(ctx, w, http.StatusBadRequest, "missing_state", err)
		return
	}
	decoded, err := DecodeStateClaim(h.signingKey, cookie.Value, time.Now(), h.stateTTL)
	if err != nil {
		h.fail(ctx, w, http.StatusBadRequest, "invalid_state", err)
		return
	}
	if r.URL.Query().Get("state") != decoded.State {
		h.fail(ctx, w, http.StatusBadRequest, "state_mismatch",
			errors.New("state query param does not match cookie"))
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		// IdP errors land in the query string per OAuth2 §4.1.2.1.
		h.fail(ctx, w, http.StatusBadRequest, "missing_code",
			errors.New("idp returned: "+r.URL.Query().Get("error")))
		return
	}
	claims, err := h.client.Exchange(ctx, code, decoded.CodeVerifier, decoded.Nonce)
	if err != nil {
		h.fail(ctx, w, http.StatusBadRequest, "exchange_failed", err)
		return
	}
	userID, identityID, err := h.provisioner.ProvisionOrFind(ctx, claims)
	if err != nil {
		if errors.Is(err, ErrUnknownIdentity) {
			h.recordAudit(ctx, api.AuditEvent{
				ActorEmail: claims.Email,
				Action:     api.AuditAction("auth.oidc.unknown_subject"),
				Payload:    map[string]any{"subject": claims.Subject},
			})
			h.fail(ctx, w, http.StatusForbidden, "unknown_subject", err)
			return
		}
		h.logger.ErrorContext(ctx, "oidc jit provision", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	idCopy := identityID
	sess, err := h.sessions.Create(ctx, userID, sessions.CreateOptions{
		IdentityID: &idCopy,
		AuthMethod: "oidc",
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "oidc create session", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	uid := userID
	h.recordAudit(ctx, api.AuditEvent{
		UserID:     &uid,
		ActorEmail: claims.Email,
		Action:     api.AuditAction("auth.oidc.success"),
		TargetType: "user",
		TargetID:   strconv.FormatInt(userID, 10),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     api.SessionCookieName,
		Value:    api.EncodeToken(sess.ID),
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
		MaxAge:   int(time.Until(sess.ExpiresAt).Seconds()),
	})
	// Clear the state cookie now that the flow finished.
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    "",
		Path:     "/api/auth/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, decoded.Redirect, http.StatusFound)
}

// fail writes a uniform error response with the wire-format reason
// header the UI reads. Audits the reason via auth.oidc.failed unless
// the caller already recorded a more specific row (e.g.
// unknown_subject).
func (h *Handler) fail(ctx context.Context, w http.ResponseWriter, status int, reason string, err error) {
	if err != nil {
		h.logger.WarnContext(ctx, "oidc callback failed",
			"reason", reason, "err", err)
	}
	if reason != "unknown_subject" {
		h.recordAudit(ctx, api.AuditEvent{
			Action:  api.AuditAction("auth.oidc.failed"),
			Payload: map[string]any{"reason": reason},
		})
	}
	w.Header().Set("X-Edr-Auth-Reason", reason)
	http.Error(w, reason, status)
}

// recordAudit is the soft-fail audit recorder. A missing audit row
// does not propagate as an HTTP error; the slog WARN preserves the
// signal.
func (h *Handler) recordAudit(ctx context.Context, e api.AuditEvent) {
	if h.audit == nil {
		return
	}
	if err := h.audit.Record(ctx, e); err != nil {
		h.logger.WarnContext(ctx, "oidc audit record",
			"err", err, "action", string(e.Action))
	}
}

// safeRedirect sanitises the post-login `next` query parameter.
// Returns defaultRedirect for empty / malformed / off-site values.
// Only same-origin absolute paths (starting with `/` and not `//`)
// pass through, so an attacker cannot smuggle the operator to an
// off-site phishing target via a crafted login URL.
func safeRedirect(next string) string {
	if next == "" {
		return defaultRedirect
	}
	u, err := url.Parse(next)
	if err != nil {
		return defaultRedirect
	}
	if u.Scheme != "" || u.Host != "" {
		return defaultRedirect
	}
	if !pathStartsWithSingleSlash(u.Path) {
		return defaultRedirect
	}
	return u.String()
}

// pathStartsWithSingleSlash returns true for "/foo" but false for
// "//foo" — the latter is a protocol-relative URL the browser would
// resolve cross-origin.
func pathStartsWithSingleSlash(p string) bool {
	return len(p) > 0 && p[0] == '/' && (len(p) == 1 || p[1] != '/')
}
