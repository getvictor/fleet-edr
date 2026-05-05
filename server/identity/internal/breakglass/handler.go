package breakglass

import (
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
// challenge cookie doesn't leak to /api/* on the same origin.
const cookiePath = "/admin/break-glass/"

// challengeCookieMaxAge is the per-flow cookie lifetime. Matches
// the WebAuthn challenge timeout the browser enforces (5 min).
const challengeCookieMaxAge = 5 * 60

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

// RegisterPublicRoutes mounts the four break-glass routes onto mux.
// All four are pre-auth; access is gated by the IP allowlist
// middleware + per-IP rate limit at request time.
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
	mux.Handle("GET /admin/break-glass/setup", wrap(h.handleBeginSetup))
	mux.Handle("POST /admin/break-glass/setup", wrap(h.handleFinishSetup))
	mux.Handle("GET /admin/break-glass", wrap(h.handleLoginForm))
	mux.Handle("POST /admin/break-glass/challenge", wrap(h.handleBeginLogin))
	mux.Handle("POST /admin/break-glass", wrap(h.handleFinishLogin))
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
		h.tooMany(w, "rate_limited")
		return
	}
	if !h.rates.AllowSetup() {
		h.tooMany(w, "setup_rate_limited")
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		h.gone(w, "token_missing")
		return
	}
	challenge, _, _, err := h.svc.BeginSetup(r.Context(), token)
	if err != nil {
		h.svc.AuditFailure(r.Context(), "", reasonForTokenErr(err),
			httpserver.ClientIP(r), r.UserAgent())
		h.gone(w, reasonForTokenErr(err))
		return
	}
	cookieValue, err := EncodeChallengeState(h.signingKey, challenge.SessionData)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "breakglass encode setup state", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	h.setChallengeCookie(w, cookieValue)
	h.writeJSON(w, http.StatusOK, map[string]any{
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
		h.tooMany(w, "rate_limited")
		return
	}
	if !h.rates.AllowSetup() {
		h.tooMany(w, "setup_rate_limited")
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		h.gone(w, "token_missing")
		return
	}
	cookie, err := r.Cookie(ChallengeStateCookieName)
	if err != nil {
		h.badRequest(w, "challenge_missing")
		return
	}
	sd, err := DecodeChallengeState(h.signingKey, cookie.Value)
	if err != nil {
		h.badRequest(w, "challenge_invalid")
		return
	}
	var body struct {
		Password       string          `json:"password"`
		CredentialName string          `json:"credential_name"`
		Attestation    json.RawMessage `json:"attestation"`
	}
	if err := decodeJSONBody(r, &body, 64*1024); err != nil {
		h.badRequest(w, "body_invalid")
		return
	}
	if len(body.Attestation) == 0 {
		h.badRequest(w, "attestation_missing")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Attestation)
	if err != nil {
		h.badRequest(w, "attestation_parse_failed")
		return
	}
	_, tok, user, err := h.svc.BeginSetup(r.Context(), token)
	if err != nil {
		h.svc.AuditFailure(r.Context(), "", reasonForTokenErr(err),
			httpserver.ClientIP(r), r.UserAgent())
		h.gone(w, reasonForTokenErr(err))
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
		h.badRequest(w, reason)
		return
	}
	h.clearChallengeCookie(w)
	h.setSessionCookie(w, res.Session)
	h.writeJSON(w, http.StatusOK, map[string]any{
		"redirect": "/ui/",
	})
}

// ---- /admin/break-glass (login) --------------------------------------------

// handleLoginForm returns a tiny JSON descriptor describing the
// route shape so the 4c UI (or any caller) can introspect at GET
// time. Pre-4c there's no HTML to render here; the operator hits
// /challenge → /admin/break-glass directly via the runbook's
// browser shim.
func (h *Handler) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if !h.rates.AllowIP(httpserver.ClientIP(r)) {
		h.tooMany(w, "rate_limited")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"endpoints": map[string]string{
			"challenge": "/admin/break-glass/challenge",
			"submit":    "/admin/break-glass",
		},
		"requires": []string{"email", "password", "webauthn_assertion"},
	})
}

// handleBeginLogin issues the WebAuthn assertion challenge for the
// presented email. JSON body: {"email": "..."}.
func (h *Handler) handleBeginLogin(w http.ResponseWriter, r *http.Request) {
	if !h.rates.AllowIP(httpserver.ClientIP(r)) {
		h.tooMany(w, "rate_limited")
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := decodeJSONBody(r, &body, 4*1024); err != nil {
		h.badRequest(w, "body_invalid")
		return
	}
	challenge, _, err := h.svc.BeginLogin(r.Context(), body.Email)
	if err != nil {
		// Email enumeration: collapse all not-found / no-credentials
		// to the same wire response so an attacker cannot probe.
		if errors.Is(err, ErrNoCredentials) {
			h.badRequest(w, "no_credentials")
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
	h.writeJSON(w, http.StatusOK, map[string]any{
		"publicKey": challenge.Options.Response,
	})
}

// handleFinishLogin verifies password + assertion and mints a
// session. JSON body: {"email": "...", "password": "...", "assertion": <CredentialAssertionResponse JSON>}.
func (h *Handler) handleFinishLogin(w http.ResponseWriter, r *http.Request) {
	if !h.rates.AllowIP(httpserver.ClientIP(r)) {
		h.tooMany(w, "rate_limited")
		return
	}
	cookie, err := r.Cookie(ChallengeStateCookieName)
	if err != nil {
		h.badRequest(w, "challenge_missing")
		return
	}
	sd, err := DecodeChallengeState(h.signingKey, cookie.Value)
	if err != nil {
		h.badRequest(w, "challenge_invalid")
		return
	}
	var body struct {
		Email     string          `json:"email"`
		Password  string          `json:"password"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if err := decodeJSONBody(r, &body, 64*1024); err != nil {
		h.badRequest(w, "body_invalid")
		return
	}
	if !h.rates.AllowEmailFail(body.Email) {
		h.tooMany(w, "email_rate_limited")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Assertion)
	if err != nil {
		h.badRequest(w, "assertion_parse_failed")
		return
	}
	user, err := h.svc.users.GetByEmail(r.Context(), body.Email)
	if err != nil {
		h.svc.AuditFailure(r.Context(), body.Email, "user_not_found",
			httpserver.ClientIP(r), r.UserAgent())
		h.unauthorized(w, "invalid_credentials")
		return
	}
	if !user.IsBreakglass {
		h.svc.AuditFailure(r.Context(), body.Email, "not_breakglass",
			httpserver.ClientIP(r), r.UserAgent())
		h.unauthorized(w, "invalid_credentials")
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
		h.unauthorized(w, "invalid_credentials")
		return
	}
	h.clearChallengeCookie(w)
	h.setSessionCookie(w, sess)
	h.svc.AuditSuccess(r.Context(), user, httpserver.ClientIP(r), r.UserAgent())
	h.writeJSON(w, http.StatusOK, map[string]any{
		"redirect": "/ui/",
	})
}

// ---- helpers ---------------------------------------------------------------

func (h *Handler) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.logger.Warn("breakglass write json", "err", err)
	}
}

func (h *Handler) badRequest(w http.ResponseWriter, reason string) {
	w.Header().Set("X-Edr-Auth-Reason", reason)
	h.writeJSON(w, http.StatusBadRequest, map[string]any{"reason": reason})
}

func (h *Handler) unauthorized(w http.ResponseWriter, reason string) {
	w.Header().Set("X-Edr-Auth-Reason", reason)
	h.writeJSON(w, http.StatusUnauthorized, map[string]any{"reason": reason})
}

func (h *Handler) gone(w http.ResponseWriter, reason string) {
	w.Header().Set("X-Edr-Auth-Reason", reason)
	h.writeJSON(w, http.StatusGone, map[string]any{"reason": reason})
}

func (h *Handler) tooMany(w http.ResponseWriter, reason string) {
	w.Header().Set("X-Edr-Auth-Reason", reason)
	w.Header().Set("Retry-After", "60")
	h.writeJSON(w, http.StatusTooManyRequests, map[string]any{"reason": reason})
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
// pattern used elsewhere in identity. cap caps the body size so a
// hostile payload cannot exhaust memory.
func decodeJSONBody(r *http.Request, dst any, cap int64) error {
	body := http.MaxBytesReader(nil, r.Body, cap)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
