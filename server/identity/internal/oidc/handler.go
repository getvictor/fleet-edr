package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
)

// defaultRedirect is the post-login landing path when the AuthURL
// query string did not pin a `next` parameter or the pin was unsafe.
const defaultRedirect = "/ui/"

// defaultStateTTL is the wave-1 fall-through when caller doesn't
// pin opts.StateTTL. Mirrors config's defaultOIDCStateCookieTTL.
const defaultStateTTL = 5 * time.Minute

// httpServerErrorThreshold is the smallest 5xx code; the audit row's
// decision flips to "error" at or above it (per spec 4xx audits as
// "deny", 5xx as "error").
const httpServerErrorThreshold = 500

// IDPClient is the per-flow IdP-facing surface the handler depends
// on. *Client implements it; tests in this package's _test sibling
// inject a fake so handleCallback's happy path can be exercised
// without spinning up a discovery server + signed-token fixture.
//
// Exported only for the test seam below; production code constructs
// via NewHandler with a real *Client.
type IDPClient interface {
	AuthURL(state, nonce, codeChallenge string) string
	Exchange(ctx context.Context, code, codeVerifier, expectedNonce string) (*Claims, error)
}

// Handler serves the OIDC login + callback routes. Construct via
// NewHandler; mount with RegisterPublicRoutes.
type Handler struct {
	client      IDPClient
	provisioner *Provisioner
	sessions    *sessions.Store
	signingKey  []byte
	stateTTL    time.Duration
	audit       api.AuditRecorder
	logger      *slog.Logger
}

// HandlerOptions configures the Handler. SigningKey is the same key
// used by the session cookie; reusing it (per spec) avoids a second
// secret to rotate.
//
// All cookies emitted by this handler are unconditionally Secure. The
// browser carve-out for `localhost`/`127.0.0.1` over HTTP keeps dev
// workflows working without an opt-out flag, and production behind a
// TLS-terminating proxy is the only other supported deployment. A
// configurable Secure flag here would risk shipping plaintext cookies
// in misconfigured production deployments and trips
// CodeQL go/cookie-secure-not-set on every static analysis pass.
type HandlerOptions struct {
	Client      *Client
	Provisioner *Provisioner
	Sessions    *sessions.Store
	SigningKey  []byte
	StateTTL    time.Duration
	Audit       api.AuditRecorder
	Logger      *slog.Logger
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
		client:      opts.Client,
		provisioner: opts.Provisioner,
		sessions:    opts.Sessions,
		signingKey:  opts.SigningKey,
		stateTTL:    stateTTL,
		audit:       opts.Audit,
		logger:      logger,
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
	state, nonce, codeVerifier, codeChallenge, err := GenerateFlowSecrets()
	if err != nil {
		h.callbackError(r, w, http.StatusInternalServerError, "flow_secrets_failed", err)
		return
	}
	redirect := safeRedirect(r.URL.Query().Get("next"))
	cookieValue, err := EncodeStateClaim(h.signingKey, state, nonce, codeVerifier, redirect, time.Now())
	if err != nil {
		h.callbackError(r, w, http.StatusInternalServerError, "state_encode_failed", err)
		return
	}
	h.writeStateCookie(w, cookieValue, int(h.stateTTL.Seconds()))
	http.Redirect(w, r, h.client.AuthURL(state, nonce, codeChallenge), http.StatusFound)
}

// handleCallback finishes the flow: verify state cookie, exchange
// code, run JIT, mint a session, redirect to the original next URL.
// Every error path emits an audit row keyed by spec action
// (auth.oidc.callback.error or auth.oidc.failure) and redirects the
// browser to /login?error=<reason> so the UI renders a directed error
// page; the operator never sees raw plaintext.
func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookie, err := r.Cookie(StateCookieName)
	if err != nil {
		h.callbackError(r, w, http.StatusBadRequest, "missing_state", err)
		return
	}
	decoded, err := DecodeStateClaim(h.signingKey, cookie.Value, time.Now(), h.stateTTL)
	if err != nil {
		h.callbackError(r, w, http.StatusBadRequest, "invalid_state", err)
		return
	}
	if r.URL.Query().Get("state") != decoded.State {
		h.callbackError(r, w, http.StatusBadRequest, "state_mismatch",
			errors.New("state query param does not match cookie"))
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		// IdP errors land in the query string per OAuth2 §4.1.2.1.
		idpErr := r.URL.Query().Get("error")
		h.callbackError(r, w, http.StatusBadRequest, "missing_code",
			fmt.Errorf("idp returned: %s", idpErr))
		return
	}
	claims, err := h.client.Exchange(ctx, code, decoded.CodeVerifier, decoded.Nonce)
	if err != nil {
		// Exchange failure crosses two boundaries: a malformed code
		// (caller's fault, 400) is indistinguishable in the wire from
		// an IdP/token-endpoint outage. Treat as 502 — closer to the
		// truth: the upstream we depend on did not produce a usable
		// token. Operators get a "try again" redirect either way.
		h.callbackError(r, w, http.StatusBadGateway, "exchange_failed", err)
		return
	}
	userID, identityID, err := h.provisioner.ProvisionOrFind(ctx, claims)
	if err != nil {
		if errors.Is(err, ErrUnknownIdentity) {
			h.failureAudit(r, "oidc.unknown_subject", api.AuditEvent{
				ActorEmail: claims.Email,
				Payload:    map[string]any{"subject": claims.Subject},
			})
			h.errorRedirect(w, r, http.StatusForbidden, "unknown_subject")
			return
		}
		if errors.Is(err, ErrEmailConflict) {
			// Email already binds another account — surface a directed
			// reason so the operator knows to ask an admin to merge,
			// not a 500.
			h.failureAudit(r, "oidc.email_conflict", api.AuditEvent{
				ActorEmail: claims.Email,
				Payload:    map[string]any{"subject": claims.Subject},
			})
			h.errorRedirect(w, r, http.StatusConflict, "email_conflict")
			return
		}
		h.callbackError(r, w, http.StatusInternalServerError, "provision_failed", err)
		return
	}
	idCopy := identityID
	sess, err := h.sessions.Create(ctx, userID, sessions.CreateOptions{
		IdentityID: &idCopy,
		AuthMethod: "oidc",
	})
	if err != nil {
		h.callbackError(r, w, http.StatusInternalServerError, "session_create_failed", err)
		return
	}
	uid := userID
	idForAudit := identityID
	h.recordAudit(ctx, api.AuditEvent{
		UserID:     &uid,
		ActorEmail: claims.Email,
		Action:     api.AuditAction("auth.oidc.success"),
		TargetType: "user",
		TargetID:   strconv.FormatInt(userID, 10),
		RemoteAddr: httpserver.ClientIP(r),
		Payload: map[string]any{
			"decision":    "allow",
			"user_agent":  r.UserAgent(),
			"identity_id": idForAudit,
		},
	})
	h.writeSessionCookie(w, sess)
	h.writeStateCookie(w, "", -1) // clear state cookie post-flow
	http.Redirect(w, r, decoded.Redirect, http.StatusFound)
}

// callbackError audits an auth.oidc.callback.error row (the OAuth
// callback machinery itself rejected the request: bad state, bad code,
// upstream failure) and redirects the operator to the login page with
// the reason in the query string. status influences the slog level:
// 5xx errors warrant ERROR; 4xx warrants WARN. The wire-format reason
// header is preserved so direct callers (curl, tests) can still discern
// the failure mode without parsing redirects.
func (h *Handler) callbackError(r *http.Request, w http.ResponseWriter, status int, reason string, err error) {
	ctx := r.Context()
	if err != nil {
		if status >= httpServerErrorThreshold {
			h.logger.ErrorContext(ctx, "oidc callback failed",
				"reason", reason, "status", status, "err", err)
		} else {
			h.logger.WarnContext(ctx, "oidc callback failed",
				"reason", reason, "status", status, "err", err)
		}
	}
	decision := "deny"
	if status >= httpServerErrorThreshold {
		decision = "error"
	}
	h.recordAudit(ctx, api.AuditEvent{
		Action:     api.AuditAction("auth.oidc.callback.error"),
		RemoteAddr: httpserver.ClientIP(r),
		Payload: map[string]any{
			"decision":   decision,
			"reason":     "oidc." + reason,
			"status":     status,
			"user_agent": r.UserAgent(),
		},
	})
	h.errorRedirect(w, r, status, reason)
}

// failureAudit records an auth.oidc.failure row (a denied login with a
// known actor: e.g., unknown subject under JIT-disabled). Caller sets
// the reason verbatim per spec wording (e.g. "oidc.unknown_subject").
func (h *Handler) failureAudit(r *http.Request, reason string, base api.AuditEvent) {
	base.Action = api.AuditAction("auth.oidc.failure")
	if base.RemoteAddr == "" {
		base.RemoteAddr = httpserver.ClientIP(r)
	}
	if base.Payload == nil {
		base.Payload = map[string]any{}
	}
	base.Payload["decision"] = "deny"
	base.Payload["reason"] = reason
	if _, ok := base.Payload["user_agent"]; !ok {
		base.Payload["user_agent"] = r.UserAgent()
	}
	h.recordAudit(r.Context(), base)
}

// errorRedirect sends the operator to /login with the failure reason
// in the query string. The reason header is also set so non-browser
// clients can still discriminate without following the 302. The state
// cookie is cleared on every error so a stuck flow doesn't replay.
func (h *Handler) errorRedirect(w http.ResponseWriter, r *http.Request, status int, reason string) {
	h.writeStateCookie(w, "", -1)
	w.Header().Set("X-Edr-Auth-Reason", reason)
	w.Header().Set("X-Edr-Auth-Status", strconv.Itoa(status))
	dest := "/login?error=" + url.QueryEscape(reason)
	http.Redirect(w, r, dest, http.StatusFound)
}

// writeStateCookie writes (or clears, when maxAge<0) the per-flow
// state cookie. Single audited construction site so the security
// flags (Secure, HttpOnly, SameSite, Path scope) live in one place.
// Secure is unconditional; see the package-level rationale on
// HandlerOptions.
func (h *Handler) writeStateCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    value,
		Path:     "/api/auth/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// writeSessionCookie writes the session cookie. Same single-site
// rationale + unconditional Secure as writeStateCookie.
func (h *Handler) writeSessionCookie(w http.ResponseWriter, sess *sessions.Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     api.SessionCookieName,
		Value:    api.EncodeToken(sess.ID),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
		MaxAge:   int(time.Until(sess.ExpiresAt).Seconds()),
	})
}

// recordAudit is the soft-fail audit recorder. A missing audit row
// does not propagate as an HTTP error; the spec mandates ERROR-level
// logging on write failure plus a metric so the operator pipeline
// notices the gap even when the user request still succeeds.
func (h *Handler) recordAudit(ctx context.Context, e api.AuditEvent) {
	if h.audit == nil {
		return
	}
	if err := h.audit.Record(ctx, e); err != nil {
		h.logger.ErrorContext(ctx, "oidc audit record failed",
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
// "//foo" or "/\foo". Some browsers normalise "\" to "/" before
// resolving redirects, so /\evil.com would otherwise be treated as a
// protocol-relative URL pointing off-origin.
func pathStartsWithSingleSlash(p string) bool {
	if len(p) == 0 || p[0] != '/' {
		return false
	}
	if len(p) == 1 {
		return true
	}
	return p[1] != '/' && p[1] != '\\'
}
