package breakglass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// Cookie path scope: only sent on /admin/break-glass paths so the challenge cookie doesn't leak to /api/* on the same origin.
// NO trailing slash: per RFC 6265 §5.1.4, a cookie with Path=/foo/ matches request paths whose prefix is "/foo/" - `/foo` (without
// the trailing slash) does NOT match. Since the login route is /admin/break-glass (no trailing slash), the cookie path must be
// /admin/break-glass for the assertion cookie to round-trip between the GET-challenge POST and the POST-login.
const cookiePath = "/admin/break-glass"

// reauthCookiePath scopes the reauth challenge cookie to /api/auth/reauth. The login challenge cookie at cookiePath is path-
// scoped to /admin/break-glass and would NOT round-trip on the reauth POST (browsers only send a cookie when the request path matches
// the cookie's Path prefix per RFC 6265 §5.1.4). A separate path AND name keeps the two flows independent - an operator running a
// break-glass login in one tab and a reauth in another won't have one flow's cookie clobber the other's.
const reauthCookiePath = "/api/auth/reauth"

// reauthChallengeCookieName is distinct from the login challenge cookie so a tab running the login flow + a tab running reauth don't
// trample each other's WebAuthn challenges.
const reauthChallengeCookieName = "edr_reauth_challenge"

// challengeCookieMaxAge is the per-flow cookie lifetime in seconds.
// Matches the WebAuthn challenge timeout the browser enforces.
const challengeCookieMaxAge = 300

// Cache-Control header semantics applied uniformly to break-glass auth responses. Success paths set signed challenge / session
// cookies; error paths are throwaway. Either way the response should not land in any shared cache.
const (
	headerCacheControl  = "Cache-Control"
	cacheControlNoStore = "no-store"
)

// loginBodyMaxBytes caps the JSON body the login handler reads. 64 KiB comfortably accommodates a CredentialAssertionResponse (with
// attestationObject) without inviting OOM via a hostile payload.
const loginBodyMaxBytes = 64 * 1024

// emailBodyMaxBytes caps the begin-login challenge body - only the
// email field, so 4 KiB is generous.
const emailBodyMaxBytes = 4 * 1024

// authReasonHeader is the wire-format header the failure helpers emit. Lifted to a const so Sonar's S1192 (duplicated literal) is
// satisfied as new helpers land.
const authReasonHeader = "X-Edr-Auth-Reason"

// Handler serves the four break-glass routes. Construct via
// NewHandler; mount via RegisterPublicRoutes.
type Handler struct {
	svc        *Service
	identity   api.Service // used by the reauth POST to stamp last_auth_at
	signingKey []byte
	rates      *RateLimits
	allowlist  *Allowlist
	logger     *slog.Logger
}

// HandlerOptions bundles the per-deployment knobs.
type HandlerOptions struct {
	Service    *Service
	Identity   api.Service // optional; required only when RegisterAuthedRoutes is called
	SigningKey []byte
	RateLimits *RateLimits
	Allowlist  *Allowlist
	Logger     *slog.Logger
}

// NewHandler validates dependencies and returns the handler.
func NewHandler(opts HandlerOptions) *Handler {
	if opts.Service == nil {
		panic("breakglass.NewHandler: Service is required")
	}
	if len(opts.SigningKey) == 0 {
		panic("breakglass.NewHandler: SigningKey is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	rates := opts.RateLimits
	if rates == nil {
		rates = NewRateLimits(0, 0, 0)
	}
	return &Handler{
		svc:        opts.Service,
		identity:   opts.Identity,
		signingKey: opts.SigningKey,
		rates:      rates,
		allowlist:  opts.Allowlist,
		logger:     logger,
	}
}

// AllowlistMiddleware returns next wrapped by the configured IP allowlist. When no allowlist is configured (dev mode), returns next
// unchanged. Exported so cmd/main can apply the same gate to the React UI's break-glass subroutes - without it, an off-allowlist
// caller could load /ui/admin/break-glass and see the React form shell, defeating the path-concealment promise of the API gate.
func (h *Handler) AllowlistMiddleware(next http.Handler) http.Handler {
	if h.allowlist == nil {
		return next
	}
	return h.allowlist.Middleware(next)
}

// RegisterPublicRoutes mounts the break-glass routes onto mux. Route shape:
//
//	GET  /admin/break-glass            → 302 /ui/admin/break-glass (UI page)
//	GET  /admin/break-glass/setup      → 302 /ui/admin/break-glass/setup (UI)
//	POST /admin/break-glass/challenge       → JSON: assertion challenge
//	POST /admin/break-glass/setup/challenge → JSON: registration challenge
//	POST /admin/break-glass                  → JSON: finish login
//	POST /admin/break-glass/setup            → JSON: atomic redemption
//
// All paths are pre-auth; the IP allowlist middleware + per-IP rate
// limit gate access at request time. The GET redirects do NOT consume
// the rate-limit budget - they're the public landing for an operator
// who clicked the printed redemption URL, and a redirect is cheaper
// than an HTML payload.
func (h *Handler) RegisterPublicRoutes(mux *http.ServeMux) {
	wrap := func(handler http.HandlerFunc) http.Handler {
		// IP allowlist runs FIRST so off-list callers see a 404 indistinguishable from "no such path" - they must not learn
		// the path exists by bumping into a rate-limit 429.
		var inner http.Handler = handler
		if h.allowlist != nil {
			inner = h.allowlist.Middleware(inner)
		}
		return inner
	}
	mux.Handle("GET /admin/break-glass/setup", wrap(h.handleSetupRedirect))
	mux.Handle("GET /admin/break-glass", wrap(h.handleLoginRedirect))
	mux.Handle("POST /admin/break-glass/setup/challenge", wrap(h.handleBeginSetup))
	mux.Handle("POST /admin/break-glass/setup", wrap(h.handleFinishSetup))
	mux.Handle("POST /admin/break-glass/challenge", wrap(h.handleBeginLogin))
	mux.Handle("POST /admin/break-glass", wrap(h.handleFinishLogin))
}

// RegisterAuthedRoutes mounts the break-glass reauth surface.
// Both routes assume the operator already has a valid session - they
// run BEHIND the session + CSRF middleware. Calling this method without
// a non-nil HandlerOptions.Identity panics, so a misconfigured wiring
// fails at boot rather than producing nil-pointer 500s at request time.
//
//	POST /api/auth/reauth/challenge → assertion options + signed
//	    challenge cookie. The operator's email is read from the
//	    current session - no email enumeration vector since the
//	    caller is already authenticated.
//	POST /api/auth/reauth → verify password + assertion against the
//	    current session's user; on success stamp last_auth_at
//	    via the identity Service. No new cookie minted.
func (h *Handler) RegisterAuthedRoutes(mux *http.ServeMux) {
	if h.identity == nil {
		panic("breakglass.RegisterAuthedRoutes: HandlerOptions.Identity is required")
	}
	mux.HandleFunc("POST /api/auth/reauth/challenge", h.handleReauthChallenge)
	mux.HandleFunc("POST /api/auth/reauth", h.handleReauth)
}

// handleSetupRedirect 302s to the React setup page, preserving the `token` query string. The redirection target is
// /ui/admin/break-glass/setup because the React UI is mounted under /ui/. The IP allowlist still applies so off-list callers see 404
// instead of a redirect (don't leak the path's existence). Cache-Control: no-store keeps the token-bearing Location header out of
// browser history / proxy caches: the redemption URL is sensitive bearer state.
func (h *Handler) handleSetupRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerCacheControl, cacheControlNoStore)
	dest := "/ui/admin/break-glass/setup"
	if q := r.URL.RawQuery; q != "" {
		dest += "?" + q
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// handleLoginRedirect 302s to the React login page. Same no-store posture as handleSetupRedirect for consistency, even though this
// path carries no token.
func (h *Handler) handleLoginRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerCacheControl, cacheControlNoStore)
	http.Redirect(w, r, "/ui/admin/break-glass", http.StatusFound)
}

// ---- /admin/break-glass/setup ----------------------------------------------

// gateSetupRequest applies the public-setup admission gate shared by handleBeginSetup + handleFinishSetup: write the no-store cache
// header, enforce per-IP + setup-flow rate limits, and parse the redemption token from the query string. Returns the trimmed token and
// ok=true when the caller should continue; ok=false means the response has already been written (4xx) and the caller must return.
func (h *Handler) gateSetupRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	// no-store on every break-glass auth response: success paths set signed challenge / session cookies; error paths are throwaway.
	// Either way the response should not land in a shared cache.
	w.Header().Set(headerCacheControl, cacheControlNoStore)
	ctx := r.Context()
	if !h.rates.AllowIP(httpserver.ClientIP(r)) {
		h.tooMany(ctx, w, "rate_limited")
		return "", false
	}
	if !h.rates.AllowSetup() {
		h.tooMany(ctx, w, "setup_rate_limited")
		return "", false
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		h.gone(ctx, w, "token_missing")
		return "", false
	}
	return token, true
}

// handleBeginSetup validates the redemption token query parameter and issues a WebAuthn registration challenge. The challenge state
// rides in a signed cookie; the response body carries CredentialCreationOptions for the browser API. The 4c UI hits this on form load;
// until then, an operator can call it directly with curl + a WebAuthn CLI (or the operator runbook's example browser shim).
func (h *Handler) handleBeginSetup(w http.ResponseWriter, r *http.Request) {
	token, ok := h.gateSetupRequest(w, r)
	if !ok {
		return
	}
	challenge, _, _, err := h.svc.BeginSetup(r.Context(), token)
	if err != nil {
		h.svc.AuditFailure(r.Context(), "", reasonForTokenErr(err),
			httpserver.ClientIP(r), r.UserAgent())
		h.gone(r.Context(), w, reasonForTokenErr(err))
		return
	}
	cookieValue, err := EncodeChallengeState(h.signingKey, challenge.SessionData)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "breakglass encode setup state", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	h.setChallengeCookie(w, cookieValue)
	h.writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"publicKey": challenge.Options.Response,
	})
}

// handleFinishSetup parses the JSON body, decodes the cookie, and
// runs the atomic redemption. Wire shape:
//
//	POST /admin/break-glass/setup
//	  body: {"password": "...", "credential_name": "yk1", "attestation": <CredentialCreationResponse JSON>}
func (h *Handler) handleFinishSetup(w http.ResponseWriter, r *http.Request) {
	token, ok := h.gateSetupRequest(w, r)
	if !ok {
		return
	}
	cookie, err := r.Cookie(ChallengeStateCookieName)
	if err != nil {
		h.badRequest(r.Context(), w, "challenge_missing")
		return
	}
	sd, err := DecodeChallengeState(h.signingKey, cookie.Value)
	if err != nil {
		h.badRequest(r.Context(), w, "challenge_invalid")
		return
	}
	var body struct {
		Password       string          `json:"password"`
		CredentialName string          `json:"credential_name"`
		Attestation    json.RawMessage `json:"attestation"`
	}
	if err := decodeJSONBody(w, r, &body, loginBodyMaxBytes); err != nil {
		h.badRequest(r.Context(), w, "body_invalid")
		return
	}
	if len(body.Attestation) == 0 {
		h.badRequest(r.Context(), w, "attestation_missing")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Attestation)
	if err != nil {
		h.badRequest(r.Context(), w, "attestation_parse_failed")
		return
	}
	_, tok, user, err := h.svc.BeginSetup(r.Context(), token)
	if err != nil {
		h.svc.AuditFailure(r.Context(), "", reasonForTokenErr(err),
			httpserver.ClientIP(r), r.UserAgent())
		h.gone(r.Context(), w, reasonForTokenErr(err))
		return
	}
	res, err := h.svc.FinishSetup(r.Context(), FinishSetupRequest{
		Token:          tok,
		User:           user,
		Session:        sd,
		Password:       body.Password,
		CredentialName: body.CredentialName,
		Attestation:    parsed,
	})
	if err != nil {
		reason := reasonForSetupErr(err)
		h.svc.AuditFailure(r.Context(), user.Email, reason,
			httpserver.ClientIP(r), r.UserAgent())
		h.badRequest(r.Context(), w, reason)
		return
	}
	h.clearChallengeCookie(w)
	if res.Session == nil {
		// Token redemption committed but the post-commit session mint failed. The token is consumed; the operator must log in via
		// /admin/break-glass to get a session. Surface a directed redirect rather than silently failing.
		h.writeJSON(r.Context(), w, http.StatusOK, map[string]any{
			"redirect": cookiePath,
			"hint":     "session_mint_failed",
		})
		return
	}
	h.setSessionCookie(w, res.Session)
	h.writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"redirect": "/ui/",
	})
}

// ---- /admin/break-glass (login) --------------------------------------------

// handleBeginLogin issues the WebAuthn assertion challenge for the
// presented email. JSON body: {"email": "..."}.
func (h *Handler) handleBeginLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerCacheControl, cacheControlNoStore)
	if !h.rates.AllowIP(httpserver.ClientIP(r)) {
		h.tooMany(r.Context(), w, "rate_limited")
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := decodeJSONBody(w, r, &body, emailBodyMaxBytes); err != nil {
		h.badRequest(r.Context(), w, "body_invalid")
		return
	}
	challenge, _, err := h.svc.BeginLogin(r.Context(), body.Email)
	if err != nil {
		// Email enumeration: collapse all not-found / no-credentials
		// to the same wire response so an attacker cannot probe.
		if errors.Is(err, ErrNoCredentials) {
			h.badRequest(r.Context(), w, "no_credentials")
			return
		}
		h.logger.ErrorContext(r.Context(), "breakglass begin login", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	cookieValue, err := EncodeChallengeState(h.signingKey, challenge.SessionData)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "breakglass encode login state", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	h.setChallengeCookie(w, cookieValue)
	h.writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"publicKey": challenge.Options.Response,
	})
}

// handleFinishLogin verifies password + assertion and mints a
// session. JSON body: {"email": "...", "password": "...", "assertion": <CredentialAssertionResponse JSON>}.
func (h *Handler) handleFinishLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerCacheControl, cacheControlNoStore)
	if !h.rates.AllowIP(httpserver.ClientIP(r)) {
		h.tooMany(r.Context(), w, "rate_limited")
		return
	}
	cookie, err := r.Cookie(ChallengeStateCookieName)
	if err != nil {
		h.badRequest(r.Context(), w, "challenge_missing")
		return
	}
	sd, err := DecodeChallengeState(h.signingKey, cookie.Value)
	if err != nil {
		h.badRequest(r.Context(), w, "challenge_invalid")
		return
	}
	var body struct {
		Email     string          `json:"email"`
		Password  string          `json:"password"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if err := decodeJSONBody(w, r, &body, loginBodyMaxBytes); err != nil {
		h.badRequest(r.Context(), w, "body_invalid")
		return
	}
	// Per-email budget: token-bucket Allow() is consume-or-reject; no non-consuming peek is exposed by the IPLimiter primitive. Consume
	// one token at the START of the attempt so a brute-forcer who exhausted the budget on prior failures cannot trigger another argon2 +
	// WebAuthn round-trip. Successful logins burn one slot too, but break-glass logins are rare by design (incident-only) so the wasted
	// slot is harmless. Spec nuance: this is the failed-login budget, but practical constraint of consume-only limiters means it gates
	// EVERY attempt; the documentation in ratelimit.go has been updated to reflect this.
	if !h.rates.AllowEmailFail(body.Email) {
		h.tooMany(r.Context(), w, "email_rate_limited")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Assertion)
	if err != nil {
		h.badRequest(r.Context(), w, "assertion_parse_failed")
		return
	}
	user, err := h.svc.users.GetByEmail(r.Context(), body.Email)
	if err != nil {
		h.svc.AuditFailure(r.Context(), body.Email, "user_not_found",
			httpserver.ClientIP(r), r.UserAgent())
		h.unauthorized(r.Context(), w)
		return
	}
	if !user.IsBreakglass {
		h.svc.AuditFailure(r.Context(), body.Email, "not_breakglass",
			httpserver.ClientIP(r), r.UserAgent())
		h.unauthorized(r.Context(), w)
		return
	}
	sess, err := h.svc.FinishLogin(r.Context(), FinishLoginRequest{
		User:      user,
		Session:   sd,
		Password:  body.Password,
		Assertion: parsed,
	})
	if err != nil {
		reason := reasonForLoginErr(err)
		// When the failure falls through to the generic "login.error" catch-all, the audit row's redacted reason leaves the
		// operator without a way to diagnose what actually failed (origin mismatch, signature verify fail, missing challenge
		// cookie, etc.). Log the underlying error at WARN so SigNoz captures the breadcrumb. The wire response and audit row
		// stay generic so a probing attacker can't enumerate failure modes; the log is operator-only.
		if reason == "login.error" {
			h.logger.WarnContext(r.Context(), "breakglass login fell through to generic error",
				"err", err,
				attrkeys.UserEmail, user.Email,
				attrkeys.RemoteAddr, httpserver.ClientIP(r),
			)
		}
		h.svc.AuditFailure(r.Context(), user.Email, reason,
			httpserver.ClientIP(r), r.UserAgent())
		h.unauthorized(r.Context(), w)
		return
	}
	h.clearChallengeCookie(w)
	h.setSessionCookie(w, sess)
	h.svc.AuditSuccess(r.Context(), user, httpserver.ClientIP(r), r.UserAgent())
	h.writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"redirect": "/ui/",
	})
}

// ---- helpers ---------------------------------------------------------------

func (h *Handler) writeJSON(ctx context.Context, w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.logger.WarnContext(ctx, "breakglass write json", "err", err)
	}
}

func (h *Handler) badRequest(ctx context.Context, w http.ResponseWriter, reason string) {
	w.Header().Set(authReasonHeader, reason)
	h.writeJSON(ctx, w, http.StatusBadRequest, map[string]any{"reason": reason})
}

func (h *Handler) unauthorized(ctx context.Context, w http.ResponseWriter) {
	// Every break-glass 401 reports the same generic reason on purpose: not revealing whether the user, the credential, or
	// the assertion was at fault denies an attacker a credential oracle.
	const reason = "invalid_credentials"
	w.Header().Set(authReasonHeader, reason)
	h.writeJSON(ctx, w, http.StatusUnauthorized, map[string]any{"reason": reason})
}

func (h *Handler) gone(ctx context.Context, w http.ResponseWriter, reason string) {
	w.Header().Set(authReasonHeader, reason)
	h.writeJSON(ctx, w, http.StatusGone, map[string]any{"reason": reason})
}

func (h *Handler) tooMany(ctx context.Context, w http.ResponseWriter, reason string) {
	w.Header().Set(authReasonHeader, reason)
	w.Header().Set("Retry-After", "60")
	h.writeJSON(ctx, w, http.StatusTooManyRequests, map[string]any{"reason": reason})
}

func (h *Handler) setChallengeCookie(w http.ResponseWriter, value string) {
	h.writeChallengeCookie(w, ChallengeStateCookieName, cookiePath, value, challengeCookieMaxAge)
}

func (h *Handler) clearChallengeCookie(w http.ResponseWriter) {
	h.writeChallengeCookie(w, ChallengeStateCookieName, cookiePath, "", -1)
}

func (h *Handler) setReauthChallengeCookie(w http.ResponseWriter, value string) {
	h.writeChallengeCookie(w, reauthChallengeCookieName, reauthCookiePath, value, challengeCookieMaxAge)
}

func (h *Handler) clearReauthChallengeCookie(w http.ResponseWriter) {
	h.writeChallengeCookie(w, reauthChallengeCookieName, reauthCookiePath, "", -1)
}

// writeChallengeCookie is the shared cookie-emit helper for both the login (cookiePath / ChallengeStateCookieName) and reauth
// (reauthCookiePath / reauthChallengeCookieName) WebAuthn flows. The per-flow path scoping keeps each flow's cookie from leaking onto
// the other's request paths and preserves the path-existence concealment property of the IP allowlist gate on the login routes.
func (h *Handler) writeChallengeCookie(w http.ResponseWriter, name, path, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// setSessionCookie writes the api.SessionCookieName cookie with the freshly minted session token. Same Secure-true policy as the OIDC
// handler (browser localhost carve-out keeps dev workflows working over plain HTTP).
func (h *Handler) setSessionCookie(w http.ResponseWriter, sess *sessions.Session) {
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

// reasonForTokenErr maps the typed token-store errors to the audit-payload reason. The wire response uniformly says "token is gone";
// the audit row records the precise cause.
func reasonForTokenErr(err error) string {
	switch {
	case errors.Is(err, ErrTokenExpired):
		return "bootstrap.expired"
	case errors.Is(err, ErrTokenConsumed):
		return "bootstrap.consumed"
	case errors.Is(err, ErrTokenInvalid):
		return "bootstrap.invalid"
	default:
		return "bootstrap.error"
	}
}

// reasonForSetupErr maps Setup-time errors to audit reasons.
func reasonForSetupErr(err error) string {
	switch {
	case errors.Is(err, ErrPasswordTooShort):
		return "password.too_short"
	case errors.Is(err, ErrTokenExpired):
		return "bootstrap.expired"
	case errors.Is(err, ErrTokenConsumed):
		return "bootstrap.consumed"
	case errors.Is(err, ErrTokenInvalid):
		return "bootstrap.invalid"
	default:
		return "setup.error"
	}
}

// gateReauthRequest applies the authed-reauth admission gate shared by handleReauthChallenge + handleReauth: write the no-store
// cache header, require a session on the request context, require auth_method=local_password (OIDC sessions dispatch reauth via
// /api/auth/login?reauth=1 instead), and enforce per-IP rate limits. Returns the resolved session and ok=true to continue; ok=false
// means the response is already written and the caller must return. The caller re-derives the context with r.Context() to keep
// contextcheck happy (linter cannot trace context inheritance through a helper return value).
func (h *Handler) gateReauthRequest(w http.ResponseWriter, r *http.Request) (*api.Session, bool) {
	w.Header().Set(headerCacheControl, cacheControlNoStore)
	ctx := r.Context()
	sess, ok := api.SessionFromContext(ctx)
	if !ok {
		// Middleware mis-wiring: route mounted without Session().
		// Fail loud with 500 because the misconfig is server-side.
		h.logger.ErrorContext(ctx, "reauth invoked without session on ctx")
		http.Error(w, "internal", http.StatusInternalServerError)
		return nil, false
	}
	if sess.AuthMethod != "local_password" {
		h.badRequest(ctx, w, "reauth_not_supported")
		return nil, false
	}
	if !h.rates.AllowIP(httpserver.ClientIP(r)) {
		h.tooMany(ctx, w, "rate_limited")
		return nil, false
	}
	return sess, true
}

// handleReauthChallenge issues a fresh assertion challenge for the
// operator on the current session. Reauth flow: an authed operator hit
// a destructive action that's outside the reauth window;
// the UI calls this endpoint to get assertion options + a signed
// challenge cookie before prompting the authenticator.
//
// The operator's email is read from the current session, NOT a request
// body - there's no email-enumeration vector here (the caller is
// already authenticated) and reading from session pins the reauth to
// the operator who's actually signed in. Sessions whose auth_method
// is not "local_password" get 400 reauth_not_supported; the UI is
// expected to dispatch OIDC reauth via /api/auth/login?reauth=1.
func (h *Handler) handleReauthChallenge(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.gateReauthRequest(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	user, err := h.svc.users.Get(ctx, sess.UserID)
	if err != nil {
		// Session refers to a deleted user - middleware should have
		// caught this; treat as session-invalid.
		h.unauthorized(ctx, w)
		return
	}
	challenge, _, err := h.svc.BeginLogin(ctx, user.Email)
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			h.badRequest(ctx, w, "no_credentials")
			return
		}
		h.logger.ErrorContext(ctx, "reauth begin login", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	cookieValue, err := EncodeChallengeState(h.signingKey, challenge.SessionData)
	if err != nil {
		h.logger.ErrorContext(ctx, "reauth encode state", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	// Use the reauth-scoped cookie (Path=/api/auth/reauth) so the browser sends it back on POST /api/auth/reauth. The login challenge
	// cookie is path-scoped to /admin/break-glass and would not round-trip here.
	h.setReauthChallengeCookie(w, cookieValue)
	h.writeJSON(ctx, w, http.StatusOK, map[string]any{
		"publicKey": challenge.Options.Response,
	})
}

// handleReauth verifies password + assertion against the current session's user and stamps last_auth_at to NOW(), resetting the
// freshness window. No new session is minted - the existing cookie keeps working with a refreshed timestamp. On success returns 200 +
// {"ok": true}; on failure returns 401 invalid_credentials with the same wire-shape as a regular break-glass login so an attacker who
// hijacks a session cookie cannot enumerate password-correctness via the reauth endpoint.
func (h *Handler) handleReauth(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.gateReauthRequest(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	cookie, err := r.Cookie(reauthChallengeCookieName)
	if err != nil {
		h.badRequest(ctx, w, "challenge_missing")
		return
	}
	sd, err := DecodeChallengeState(h.signingKey, cookie.Value)
	if err != nil {
		h.badRequest(ctx, w, "challenge_invalid")
		return
	}
	var body struct {
		Password  string          `json:"password"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if err := decodeJSONBody(w, r, &body, loginBodyMaxBytes); err != nil {
		h.badRequest(ctx, w, "body_invalid")
		return
	}
	user, err := h.svc.users.Get(ctx, sess.UserID)
	if err != nil {
		h.unauthorized(ctx, w)
		return
	}
	if !h.rates.AllowEmailFail(user.Email) {
		h.tooMany(ctx, w, "email_rate_limited")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Assertion)
	if err != nil {
		h.badRequest(ctx, w, "assertion_parse_failed")
		return
	}
	if err := h.svc.VerifyLogin(ctx, FinishLoginRequest{
		User:      user,
		Session:   sd,
		Password:  body.Password,
		Assertion: parsed,
	}); err != nil {
		reason := reasonForLoginErr(err)
		h.svc.AuditFailure(ctx, user.Email, reason,
			httpserver.ClientIP(r), r.UserAgent())
		h.unauthorized(ctx, w)
		return
	}
	// Re-derive the raw cookie token from the request so the identity service can stamp last_auth_at on this session row. The plaintext is
	// the cookie value; api.Session deliberately does not carry it.
	rawToken, err := readSessionCookieToken(r)
	if err != nil {
		h.logger.ErrorContext(ctx, "reauth read session cookie", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if err := h.identity.UpdateLastAuthAt(ctx, rawToken); err != nil {
		h.logger.ErrorContext(ctx, "reauth update last_auth_at", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	h.clearReauthChallengeCookie(w)
	h.svc.AuditSuccess(ctx, user, httpserver.ClientIP(r), r.UserAgent())
	h.writeJSON(ctx, w, http.StatusOK, map[string]any{"ok": true})
}

// readSessionCookieToken decodes the api.SessionCookieName value back into the raw plaintext token bytes. Mirrors the middleware's
// cookie-read path so the reauth endpoint stamps last_auth_at on the SAME row the middleware loaded.
func readSessionCookieToken(r *http.Request) ([]byte, error) {
	cookie, err := r.Cookie(api.SessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("read session cookie: %w", err)
	}
	return api.DecodeToken(cookie.Value)
}

// reasonForLoginErr maps login-time errors to audit reasons.
func reasonForLoginErr(err error) string {
	switch {
	case errors.Is(err, users.ErrBadPassword):
		return "password.mismatch"
	case errors.Is(err, users.ErrNotFound):
		return "user_not_found"
	case errors.Is(err, ErrCredentialClonedDetected):
		return "webauthn.cloned"
	case errors.Is(err, ErrCredentialNotFound):
		return "webauthn.unknown_credential"
	case errors.Is(err, ErrNoCredentials):
		return "webauthn.no_credentials"
	default:
		return "login.error"
	}
}

// decodeJSONBody is the standard limited-reader + strict-JSON pattern used elsewhere in identity. maxBytes caps the body size so a
// hostile payload cannot exhaust memory. Passing the ResponseWriter lets net/http emit the canonical 413 response on overflow rather
// than falling through to a generic decode error.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	body := http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
