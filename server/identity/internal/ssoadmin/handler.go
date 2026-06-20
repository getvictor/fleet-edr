// Package ssoadmin serves the admin API for the deployment's OIDC configuration (issue #375): read the current config (never the
// client secret), update it (write-only secret rotation), and test the provider connection before saving. Every route funnels through
// the authorization chokepoint on api.ActionSSOManage; the update emits an audit row. The handler depends on small interfaces (the
// config store and a connection prober) so it is unit-testable without a database or a live IdP.
package ssoadmin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
)

// updateBodyLimit caps the PUT/test-connection request body. The config payload is a handful of short strings; 64 KiB is generous.
const updateBodyLimit = 1 << 16

// allowedJITRoles bounds the default-role selector to the two lowest-privilege roles. Admin is never auto-granted from an SSO claim
// (matches the seeded-role posture and the design's Analyst/Auditor-only selector).
var allowedJITRoles = map[string]bool{"analyst": true, "auditor": true}

// configStore is the subset of *ssoconfig.Store the handler needs. Narrowed to an interface so tests inject a fake.
type configStore interface {
	Get(ctx context.Context) (*ssoconfig.Config, error)
	Upsert(ctx context.Context, in ssoconfig.UpsertInput) error
}

// prober verifies a candidate issuer is reachable. Production wraps oidc.Probe with the deployment HTTP client; tests inject a fake.
type prober func(ctx context.Context, issuer string) error

// Handler serves the /api/settings/sso routes. Construct via NewHandler; mount with RegisterAuthedRoutes behind the session + CSRF
// middleware.
type Handler struct {
	store  configStore
	authz  api.AuthZ
	audit  api.AuditRecorder
	probe  prober
	logger *slog.Logger
}

// NewHandler builds the handler. store, authz, and probe are load-bearing; logger defaults to slog.Default. audit may be nil only in
// tests that do not assert on the audit row.
func NewHandler(store configStore, authz api.AuthZ, audit api.AuditRecorder, probe prober, logger *slog.Logger) *Handler {
	if store == nil {
		panic("ssoadmin.NewHandler: store is required")
	}
	if authz == nil {
		panic("ssoadmin.NewHandler: authz is required")
	}
	if probe == nil {
		panic("ssoadmin.NewHandler: probe is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: store, authz: authz, audit: audit, probe: probe, logger: logger}
}

// RegisterAuthedRoutes mounts the SSO settings routes. The mux is expected to be wrapped in the session + CSRF middleware before being
// mounted; the unsafe methods (PUT/POST) inherit the CSRF check from that wrapper.
func (h *Handler) RegisterAuthedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/settings/sso", h.handleGet)
	mux.HandleFunc("PUT /api/settings/sso", h.handleUpdate)
	mux.HandleFunc("POST /api/settings/sso/test-connection", h.handleTestConnection)
}

// configResponse is the read shape. It NEVER carries the client secret; SecretSet reports whether one is stored. Configured is false
// when no config row exists yet (the UI renders an empty first-time form).
type configResponse struct {
	Configured  bool     `json:"configured"`
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"client_id"`
	RedirectURL string   `json:"redirect_url"`
	Scopes      []string `json:"scopes"`
	JITEnabled  bool     `json:"jit_enabled"`
	DefaultRole string   `json:"default_role"`
	SecretSet   bool     `json:"secret_set"`
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionSSOManage, api.Resource{Type: "sso_config"}) {
		return
	}
	cfg, err := h.store.Get(ctx)
	if errors.Is(err, ssoconfig.ErrNotFound) {
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, configResponse{Configured: false})
		return
	}
	if err != nil {
		h.logger.ErrorContext(ctx, "sso config get", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, toResponse(cfg))
}

// updateRequest is the write shape. ClientSecret is a pointer so the field is distinguishable as absent (keep the stored secret) vs
// present. An empty string is also treated as "keep", so a UI that always submits the field but leaves it blank never clears a secret;
// only a non-empty value rotates it.
type updateRequest struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret *string  `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
	JITEnabled   bool     `json:"jit_enabled"`
	DefaultRole  string   `json:"default_role"`
}

func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionSSOManage, api.Resource{Type: "sso_config"}) {
		return
	}
	req, ok := decodeJSON[updateRequest](ctx, h.logger, w, r)
	if !ok {
		return
	}
	in, reason, ok := req.toUpsert()
	if !ok {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, reason)
		return
	}
	actor, ok := api.ActorFromContext(ctx)
	if !ok {
		// Session middleware guarantees an actor past HTTPGate's allow path; its absence here is a wiring bug.
		h.logger.ErrorContext(ctx, "sso config update: no actor on context")
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	in.UpdatedBy = &actor.UserID
	if err := h.store.Upsert(ctx, in); err != nil {
		h.logger.ErrorContext(ctx, "sso config upsert", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	h.recordUpdate(ctx, r, actor.UserID, in)

	cfg, err := h.store.Get(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "sso config re-read after update", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, toResponse(cfg))
}

// testConnectionRequest carries the candidate issuer to probe. Empty issuer means "probe the stored config".
type testConnectionRequest struct {
	Issuer string `json:"issuer"`
}

type testConnectionResponse struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

func (h *Handler) handleTestConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionSSOManage, api.Resource{Type: "sso_config"}) {
		return
	}
	req, ok := decodeJSON[testConnectionRequest](ctx, h.logger, w, r)
	if !ok {
		return
	}
	issuer := strings.TrimSpace(req.Issuer)
	if issuer == "" {
		cfg, err := h.store.Get(ctx)
		if errors.Is(err, ssoconfig.ErrNotFound) {
			writeErr(ctx, h.logger, w, http.StatusBadRequest, "no_issuer")
			return
		}
		if err != nil {
			h.logger.ErrorContext(ctx, "sso test-connection read stored", "err", err)
			writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
			return
		}
		issuer = cfg.Issuer
	}
	// Probe persists nothing; a failure is a 200 with ok=false + reason so the UI can render the diagnostic inline.
	if err := h.probe(ctx, issuer); err != nil {
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, testConnectionResponse{OK: false, Reason: err.Error()})
		return
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, testConnectionResponse{OK: true})
}

// recordUpdate emits the mutation audit row. It never includes the client secret, only whether one was rotated.
func (h *Handler) recordUpdate(ctx context.Context, r *http.Request, userID int64, in ssoconfig.UpsertInput) {
	if h.audit == nil {
		return
	}
	uid := userID
	if err := h.audit.Record(ctx, api.AuditEvent{
		UserID:     &uid,
		Action:     api.AuditAction("sso.config.updated"),
		TargetType: "sso_config",
		RemoteAddr: httpserver.ClientIP(r),
		Payload: map[string]any{
			"issuer":         in.Issuer,
			"jit_enabled":    in.JITEnabled,
			"default_role":   in.DefaultRole,
			"secret_rotated": in.NewSecret != nil,
		},
	}); err != nil {
		h.logger.ErrorContext(ctx, "sso config audit record failed", "err", err)
	}
}

// toUpsert validates the request and maps it to a store UpsertInput. Returns a wire-format reason + false on the first validation
// failure. NewSecret is set only when a non-empty client_secret was supplied (rotate-only); otherwise the stored secret is preserved.
func (req updateRequest) toUpsert() (ssoconfig.UpsertInput, string, bool) {
	issuer := strings.TrimSpace(req.Issuer)
	if !validAbsoluteURL(issuer) {
		return ssoconfig.UpsertInput{}, "invalid_issuer", false
	}
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		return ssoconfig.UpsertInput{}, "missing_client_id", false
	}
	redirect := strings.TrimSpace(req.RedirectURL)
	if !validAbsoluteURL(redirect) {
		return ssoconfig.UpsertInput{}, "invalid_redirect_url", false
	}
	scopes := normalizeScopes(req.Scopes)
	if !slicesContains(scopes, "openid") {
		return ssoconfig.UpsertInput{}, "missing_openid_scope", false
	}
	role := strings.ToLower(strings.TrimSpace(req.DefaultRole))
	if role == "" {
		role = "analyst"
	}
	// The default role is meaningful only when JIT is on, but we validate it whenever provided so a stored value is always one the
	// chokepoint posture allows (never admin from a claim).
	if !allowedJITRoles[role] {
		return ssoconfig.UpsertInput{}, "invalid_default_role", false
	}
	var newSecret *string
	if req.ClientSecret != nil && *req.ClientSecret != "" {
		s := *req.ClientSecret
		newSecret = &s
	}
	return ssoconfig.UpsertInput{
		Issuer:      issuer,
		ClientID:    clientID,
		NewSecret:   newSecret,
		RedirectURL: redirect,
		Scopes:      scopes,
		JITEnabled:  req.JITEnabled,
		DefaultRole: role,
	}, "", true
}

func toResponse(c *ssoconfig.Config) configResponse {
	return configResponse{
		Configured:  true,
		Issuer:      c.Issuer,
		ClientID:    c.ClientID,
		RedirectURL: c.RedirectURL,
		Scopes:      c.Scopes,
		JITEnabled:  c.JITEnabled,
		DefaultRole: c.DefaultRole,
		SecretSet:   c.HasSecret,
	}
}

// validAbsoluteURL accepts an http/https URL with a host. http is permitted so local dev IdPs (e.g. a localhost Dex) work; production
// IdPs are https.
func validAbsoluteURL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func normalizeScopes(in []string) []string {
	if len(in) == 0 {
		return []string{"openid", "email", "profile"}
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func slicesContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func decodeJSON[T any](ctx context.Context, logger *slog.Logger, w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	body, err := io.ReadAll(io.LimitReader(r.Body, updateBodyLimit))
	if err != nil {
		writeErr(ctx, logger, w, http.StatusBadRequest, "read_body")
		return v, false
	}
	if err := json.Unmarshal(body, &v); err != nil {
		writeErr(ctx, logger, w, http.StatusBadRequest, "invalid_json")
		return v, false
	}
	return v, true
}

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
