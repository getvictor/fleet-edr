package breakglass

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/sessions"
	"github.com/fleetdm/edr/server/identity/internal/users"
)

// Cookie path scope: only sent on /admin/break-glass paths so the
// challenge cookie doesn't leak to /api/* on the same origin. NO
// trailing slash: per RFC 6265 §5.1.4, a cookie with Path=/foo/
// matches request paths whose prefix is "/foo/" — `/foo` (without
// the trailing slash) does NOT match. Since the login route is
// /admin/break-glass (no trailing slash), the cookie path must be
// /admin/break-glass for the assertion cookie to round-trip
// between the GET-challenge POST and the POST-login.
const cookiePath = "/admin/break-glass"

// challengeCookieMaxAge is the per-flow cookie lifetime in seconds.
// Matches the WebAuthn challenge timeout the browser enforces.
const challengeCookieMaxAge = 300

// loginBodyMaxBytes caps the JSON body the login handler reads.
// 64 KiB comfortably accommodates a CredentialAssertionResponse
// (with attestationObject) without inviting OOM via a hostile
// payload.
const loginBodyMaxBytes = 64 * 1024

// emailBodyMaxBytes caps the begin-login challenge body — only the
// email field, so 4 KiB is generous.
const emailBodyMaxBytes = 4 * 1024

// authReasonHeader is the wire-format header the failure helpers
// emit. Lifted to a const so Sonar's S1192 (duplicated literal) is
// satisfied as new helpers land.
const authReasonHeader = "X-Edr-Auth-Reason"

// Handler serves the four break-glass routes. Construct via
// NewHandler; mount via RegisterPublicRoutes.
type Handler struct {
	svc        *Service
	signingKey []byte
	rates      *RateLimits
	allowlist  *Allowlist
	logger     *slog.Logger
}

// HandlerOptions bundles the per-deployment knobs.
type HandlerOptions struct {
	Service    *Service
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
		signingKey: opts.SigningKey,
		rates:      rates,
		allowlist:  opts.Allowlist,
		logger:     logger,
	}
}

// RegisterPublicRoutes mounts the break-glass routes onto mux.
// Phase 4c shape:
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
// the rate-limit budget — they're the public landing for an operator
// who clicked the printed redemption URL, and a redirect is cheaper
// than an HTML payload.
func (h *Handler) RegisterPublicRoutes(mux *http.ServeMux) {
	wrap := func(handler http.HandlerFunc) http.Handler {
		// IP allowlist runs FIRST so off-list callers see a 404
		// indistinguishable from "no such path" — they must not
		// learn the path exists by bumping into a rate-limit 429.
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

// handleSetupRedirect 302s to the React setup page, preserving the
// `token` query string. The redirection target is /ui/admin/break-glass/setup
// because the React UI is mounted under /ui/. The IP allowlist still
// applies so off-list callers see 404 instead of a redirect (don't
// leak the path's existence). Cache-Control: no-store keeps the
// token-bearing Location header out of browser history / proxy
// caches: the redemption URL is sensitive bearer state.
func (h *Handler) handleSetupRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	dest := "/ui/admin/break-glass/setup"
	if q := r.URL.RawQuery; q != "" {
		dest += "?" + q
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// handleLoginRedirect 302s to the React login page. Same no-store
// posture as handleSetupRedirect for consistency, even though this
// path carries no token.
func (h *Handler) handleLoginRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/ui/admin/break-glass", http.StatusFound)
}

// ---- /admin/break-glass/setup ----------------------------------------------

// handleBeginSetup validates the redemption token query parameter
// and issues a WebAuthn registration challenge. The challenge state
// rides in a signed cookie; the response body carries
// CredentialCreationOptions for the browser API. The 4c UI hits
// this on form load; until then, an operator can call it directly
// with curl + a WebAuthn CLI (or the operator runbook's example
// browser shim).
func (h *Handler) handleBeginSetup(w http.ResponseWriter, r *http.Request) {
	if !h.rates.AllowIP(httpserver.ClientIP(r)) {
		h.tooMany(r.Context(), w, "rate_limited")
		return
	}
	if !h.rates.AllowSetup() {
		h.tooMany(r.Context(), w, "setup_rate_limited")
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		h.gone(r.Context(), w, "token_missing")
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
	if !h.rates.AllowIP(httpserver.ClientIP(r)) {
		h.tooMany(r.Context(), w, "rate_limited")
		return
	}
	if !h.rates.AllowSetup() {
		h.tooMany(r.Context(), w, "setup_rate_limited")
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		h.gone(r.Context(), w, "token_missing")
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
		// Token redemption committed but the post-commit session
		// mint failed. The token is consumed; the operator must log
		// in via /admin/break-glass to get a session. Surface a
		// directed redirect rather than silently failing.
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
	// Per-email budget: token-bucket Allow() is consume-or-reject;
	// no non-consuming peek is exposed by the IPLimiter primitive.
	// Consume one token at the START of the attempt so a brute-
	// forcer who exhausted the budget on prior failures cannot
	// trigger another argon2 + WebAuthn round-trip. Successful
	// logins burn one slot too, but break-glass logins are rare by
	// design (incident-only) so the wasted slot is harmless. Spec
	// nuance: this is the failed-login budget, but practical
	// constraint of consume-only limiters means it gates EVERY
	// attempt; the documentation in ratelimit.go has been updated
	// to reflect this.
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
		h.unauthorized(r.Context(), w, "invalid_credentials")
		return
	}
	if !user.IsBreakglass {
		h.svc.AuditFailure(r.Context(), body.Email, "not_breakglass",
			httpserver.ClientIP(r), r.UserAgent())
		h.unauthorized(r.Context(), w, "invalid_credentials")
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
		h.svc.AuditFailure(r.Context(), user.Email, reason,
			httpserver.ClientIP(r), r.UserAgent())
		h.unauthorized(r.Context(), w, "invalid_credentials")
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

func (h *Handler) unauthorized(ctx context.Context, w http.ResponseWriter, reason string) {
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
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeStateCookieName,
		Value:    value,
		Path:     cookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   challengeCookieMaxAge,
	})
}

func (h *Handler) clearChallengeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeStateCookieName,
		Value:    "",
		Path:     cookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// setSessionCookie writes the api.SessionCookieName cookie with the
// freshly minted session token. Same Secure-true policy as the OIDC
// handler (browser localhost carve-out keeps dev workflows working
// over plain HTTP).
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

// reasonForTokenErr maps the typed token-store errors to the
// audit-payload reason. The wire response uniformly says "token is
// gone"; the audit row records the precise cause.
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

// decodeJSONBody is the standard limited-reader + strict-JSON
// pattern used elsewhere in identity. maxBytes caps the body size
// so a hostile payload cannot exhaust memory. Passing the
// ResponseWriter lets net/http emit the canonical 413 response on
// overflow rather than falling through to a generic decode error.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	body := http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
