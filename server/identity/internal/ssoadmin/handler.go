// Package ssoadmin serves the admin API for the deployment's OIDC configuration (issue #375): read the current config (never the
// client secret), update it (write-only secret rotation), and test the provider connection before saving. Every route funnels through
// the authorization chokepoint on api.ActionSSOManage; the update emits an audit row. The handler depends on small interfaces (the
// config store and a connection prober) so it is unit-testable without a database or a live IdP.
package ssoadmin

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/appconfig"
	"github.com/fleetdm/edr/server/identity/internal/rbac"
	"github.com/fleetdm/edr/server/identity/internal/ssoconfig"
)

// updateBodyLimit caps the PUT/test-connection request body. The config payload is a handful of short strings; 64 KiB is generous.
const updateBodyLimit = 1 << 16

// allowedJITRoles bounds the default role, the one every operator with no mapped group holds, to the two lowest-privilege roles
// (matches the design's Analyst/Auditor-only selector). Only a group mapping an admin configures can grant more.
var allowedJITRoles = map[string]bool{"analyst": true, "auditor": true}

// maxGroupFieldLen bounds the groups claim name and a mapped group name in characters, matching the groups_claim column (VARCHAR(255)).
const maxGroupFieldLen = 255

// configStore is the read subset of *ssoconfig.Store the handler needs. Writes go through applyUpdate (transactional). Narrowed to an
// interface so tests inject a fake.
type configStore interface {
	Get(ctx context.Context) (*ssoconfig.Config, error)
}

// appConfigStore is the read subset of *appconfig.Store the handler needs: the general settings document the external URL lives in.
type appConfigStore interface {
	Get(ctx context.Context) (appconfig.AppConfig, int64, error)
}

// applyUpdate persists the OIDC config and the app-config document ATOMICALLY (one DB transaction), so a partial write can never leave
// a new issuer/client paired with a stale derived redirect. expectedAppVersion drives the app-config optimistic-concurrency check;
// implementations return appconfig.ErrVersionConflict on a concurrent edit. Injected so the handler stays unit-testable without a DB.
type applyUpdate func(
	ctx context.Context, oidcIn ssoconfig.UpsertInput, appCfg appconfig.AppConfig, expectedAppVersion int64, updatedBy string,
) error

// prober verifies a candidate issuer is reachable. Production wraps oidc.Probe with the deployment HTTP client; tests inject a fake.
type prober func(ctx context.Context, issuer string) error

// Handler serves the /api/settings/sso routes. Construct via NewHandler; mount with RegisterAuthedRoutes behind the session + CSRF
// middleware. It spans two stores: the typed oidc_config (with its sealed secret) and the appconfig document (external URL).
type Handler struct {
	store  configStore
	appCfg appConfigStore
	apply  applyUpdate
	authz  api.AuthZ
	audit  api.AuditRecorder
	probe  prober
	logger *slog.Logger
}

// NewHandler builds the handler. store, appCfg, apply, authz, and probe are load-bearing; logger defaults to slog.Default. audit may
// be nil only in tests that do not assert on the audit row.
func NewHandler(
	store configStore, appCfg appConfigStore, apply applyUpdate,
	authz api.AuthZ, audit api.AuditRecorder, probe prober, logger *slog.Logger,
) *Handler {
	if store == nil {
		panic("ssoadmin.NewHandler: store is required")
	}
	if appCfg == nil {
		panic("ssoadmin.NewHandler: appCfg is required")
	}
	if apply == nil {
		panic("ssoadmin.NewHandler: apply is required")
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
	return &Handler{store: store, appCfg: appCfg, apply: apply, authz: authz, audit: audit, probe: probe, logger: logger}
}

// RegisterAuthedRoutes mounts the SSO settings routes. The mux is expected to be wrapped in the session + CSRF middleware before being
// mounted; the unsafe methods (PUT/POST) inherit the CSRF check from that wrapper.
func (h *Handler) RegisterAuthedRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/settings/sso", h.handleGet)
	mux.HandleFunc("PUT /api/settings/sso", h.handleUpdate)
	mux.HandleFunc("POST /api/settings/sso/test-connection", h.handleTestConnection)
}

// configResponse is the read shape. It NEVER carries the client secret; SecretSet reports whether one is stored. Configured is false
// when no config row exists yet (the UI renders an empty first-time form).
type configResponse struct {
	Configured bool   `json:"configured"`
	Issuer     string `json:"issuer"`
	ClientID   string `json:"client_id"`
	// ExternalURL is the operator-editable deployment base URL; RedirectURL is derived from it (external + /api/auth/callback) and is
	// read-only in the UI (the value to register at the IdP).
	ExternalURL string   `json:"external_url"`
	RedirectURL string   `json:"redirect_url"`
	Scopes      []string `json:"scopes"`
	JITEnabled  bool     `json:"jit_enabled"`
	DefaultRole string   `json:"default_role"`
	// GroupsClaim and GroupRoles are the group to role mapping: empty and [] when it is off.
	GroupsClaim string                `json:"groups_claim"`
	GroupRoles  []ssoconfig.GroupRole `json:"group_roles"`
	SecretSet   bool                  `json:"secret_set"`
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionSSOManage, api.Resource{Type: "sso_config"}) {
		return
	}
	// External URL is deployment-level (appconfig) and may be set even before OIDC is configured; always include it.
	appCfg, _, err := h.appCfg.Get(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "app config get", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	cfg, err := h.store.Get(ctx)
	if errors.Is(err, ssoconfig.ErrNotFound) {
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, configResponse{
			Configured:  false,
			ExternalURL: appCfg.ExternalURL,
			RedirectURL: ssoconfig.RedirectURLFor(appCfg.ExternalURL),
			GroupRoles:  []ssoconfig.GroupRole{},
		})
		return
	}
	if err != nil {
		h.logger.ErrorContext(ctx, "sso config get", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, toResponse(cfg, appCfg.ExternalURL))
}

// updateRequest is the write shape. ClientSecret is a pointer so the field is distinguishable as absent (keep the stored secret) vs
// present. An empty string is also treated as "keep", so a UI that always submits the field but leaves it blank never clears a secret;
// only a non-empty value rotates it. GroupsClaim and GroupRoles are pointers for the same reason: when both are absent the stored group
// mapping is kept, so a client that does not edit the mapping cannot clear one saved by another; when either is present, the two
// replace the stored mapping together.
type updateRequest struct {
	Issuer       string                 `json:"issuer"`
	ClientID     string                 `json:"client_id"`
	ClientSecret *string                `json:"client_secret"`
	ExternalURL  string                 `json:"external_url"`
	Scopes       []string               `json:"scopes"`
	JITEnabled   bool                   `json:"jit_enabled"`
	DefaultRole  string                 `json:"default_role"`
	GroupsClaim  *string                `json:"groups_claim"`
	GroupRoles   *[]ssoconfig.GroupRole `json:"group_roles"`
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
	in, externalURL, reason, ok := req.toUpsert()
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
	// Record the acting principal id (usr_<id> for a user, svc_<id> for a service account) as updated_by. Both are valid principals(id)
	// FK targets, so a service-account SSO update is attributed to the service account rather than the interim NULL the #515 stopgap
	// recorded. See ADR-0017.
	in.UpdatedBy = actor.Principal.ID
	// Read the app-config document (read-modify-write preserves unrelated settings) and capture its version for the optimistic-
	// concurrency check inside the transactional apply.
	appCfg, appVersion, err := h.appCfg.Get(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "app config read for update", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	appCfg.ExternalURL = externalURL
	// One transaction writes oidc_config + app_config together: a partial write can never pair a new issuer with a stale redirect.
	if err := h.apply(ctx, in, appCfg, appVersion, in.UpdatedBy); err != nil {
		if errors.Is(err, appconfig.ErrVersionConflict) {
			writeErr(ctx, h.logger, w, http.StatusConflict, "version_conflict")
			return
		}
		h.logger.ErrorContext(ctx, "sso config apply", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	h.recordUpdate(ctx, r, actor.Principal, in, externalURL)

	cfg, err := h.store.Get(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "sso config re-read after update", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, toResponse(cfg, externalURL))
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
	} else if !validAbsoluteURL(issuer) {
		// Validate a caller-supplied candidate the same way handleUpdate does, so a malformed issuer is a fast 400 rather than a
		// network discovery attempt that fails opaquely.
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_issuer")
		return
	}
	// Probe persists nothing; a failure is a 200 with ok=false + reason so the UI can render the diagnostic inline.
	if err := h.probe(ctx, issuer); err != nil {
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, testConnectionResponse{OK: false, Reason: err.Error()})
		return
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, testConnectionResponse{OK: true})
}

// recordUpdate emits the mutation audit row. It never includes the client secret, only whether one was rotated.
func (h *Handler) recordUpdate(ctx context.Context, r *http.Request, actor api.PrincipalRef, in ssoconfig.UpsertInput, externalURL string) {
	if h.audit == nil {
		return
	}
	payload := map[string]any{
		"issuer":         in.Issuer,
		"external_url":   externalURL,
		"jit_enabled":    in.JITEnabled,
		"default_role":   in.DefaultRole,
		"secret_rotated": in.NewSecret != nil,
	}
	// The mapping is recorded only when this update replaced it; an update that kept it says nothing about it.
	if in.GroupMapping != nil {
		payload["groups_claim"] = in.GroupMapping.Claim
		payload["group_roles"] = in.GroupMapping.Roles
	}
	if err := h.audit.Record(ctx, api.AuditEvent{
		Actor:      actor,
		Action:     api.AuditAction("sso.config.updated"),
		TargetType: "sso_config",
		RemoteAddr: httpserver.ClientIP(r),
		Payload:    payload,
	}); err != nil {
		h.logger.ErrorContext(ctx, "sso config audit record failed", "err", err)
	}
}

// toUpsert validates the request and maps it to a store UpsertInput plus the external URL (persisted separately in appconfig). Returns
// a wire-format reason + false on the first validation failure. NewSecret is set only when a non-empty client_secret was supplied
// (rotate-only); otherwise the stored secret is preserved.
func (req updateRequest) toUpsert() (ssoconfig.UpsertInput, string, string, bool) {
	issuer := strings.TrimSpace(req.Issuer)
	if !validAbsoluteURL(issuer) {
		return ssoconfig.UpsertInput{}, "", "invalid_issuer", false
	}
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		return ssoconfig.UpsertInput{}, "", "missing_client_id", false
	}
	externalURL := strings.TrimSpace(req.ExternalURL)
	if !validAbsoluteURL(externalURL) {
		return ssoconfig.UpsertInput{}, "", "invalid_external_url", false
	}
	scopes := normalizeScopes(req.Scopes)
	if !slices.Contains(scopes, "openid") {
		return ssoconfig.UpsertInput{}, "", "missing_openid_scope", false
	}
	role := strings.ToLower(strings.TrimSpace(req.DefaultRole))
	if role == "" {
		role = "analyst"
	}
	// The default role is meaningful only when JIT is on, but we validate it whenever provided so a stored value is always one the
	// chokepoint posture allows (never admin from a claim).
	if !allowedJITRoles[role] {
		return ssoconfig.UpsertInput{}, "", "invalid_default_role", false
	}
	var mapping *ssoconfig.GroupMapping
	if req.GroupsClaim != nil || req.GroupRoles != nil {
		var claim string
		var roles []ssoconfig.GroupRole
		if req.GroupsClaim != nil {
			claim = *req.GroupsClaim
		}
		if req.GroupRoles != nil {
			roles = *req.GroupRoles
		}
		m, reason := validGroupMapping(claim, roles)
		if reason != "" {
			return ssoconfig.UpsertInput{}, "", reason, false
		}
		mapping = &m
	}
	var newSecret *string
	if req.ClientSecret != nil && *req.ClientSecret != "" {
		s := *req.ClientSecret
		newSecret = &s
	}
	return ssoconfig.UpsertInput{
		Issuer:       issuer,
		ClientID:     clientID,
		NewSecret:    newSecret,
		Scopes:       scopes,
		JITEnabled:   req.JITEnabled,
		DefaultRole:  role,
		GroupMapping: mapping,
	}, externalURL, "", true
}

// validGroupMapping trims and checks the groups claim and the group mappings, returning them normalized (roles lower-cased) or a
// wire-format reason. The claim and the mappings come together: a claim with no mappings would put every operator in the default role
// at sign-in, and mappings with no claim would never apply.
func validGroupMapping(claim string, in []ssoconfig.GroupRole) (ssoconfig.GroupMapping, string) {
	claim = strings.TrimSpace(claim)
	switch {
	case utf8.RuneCountInString(claim) > maxGroupFieldLen:
		return ssoconfig.GroupMapping{}, "invalid_groups_claim"
	case claim == "" && len(in) > 0:
		return ssoconfig.GroupMapping{}, "missing_groups_claim"
	case claim != "" && len(in) == 0:
		return ssoconfig.GroupMapping{}, "missing_group_roles"
	}
	out := make([]ssoconfig.GroupRole, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, gr := range in {
		group := strings.TrimSpace(gr.Group)
		role := strings.ToLower(strings.TrimSpace(gr.Role))
		if group == "" || utf8.RuneCountInString(group) > maxGroupFieldLen || !rbac.GrantableRoles[role] {
			return ssoconfig.GroupMapping{}, "invalid_group_role"
		}
		if seen[group] {
			return ssoconfig.GroupMapping{}, "duplicate_group"
		}
		seen[group] = true
		out = append(out, ssoconfig.GroupRole{Group: group, Role: role})
	}
	return ssoconfig.GroupMapping{Claim: claim, Roles: out}, ""
}

func toResponse(c *ssoconfig.Config, externalURL string) configResponse {
	groupRoles := c.GroupRoles
	if groupRoles == nil {
		groupRoles = []ssoconfig.GroupRole{}
	}
	return configResponse{
		Configured:  true,
		Issuer:      c.Issuer,
		ClientID:    c.ClientID,
		ExternalURL: externalURL,
		RedirectURL: ssoconfig.RedirectURLFor(externalURL),
		Scopes:      c.Scopes,
		JITEnabled:  c.JITEnabled,
		DefaultRole: c.DefaultRole,
		GroupsClaim: c.GroupsClaim,
		GroupRoles:  groupRoles,
		SecretSet:   c.HasSecret,
	}
}

// validAbsoluteURL accepts an http/https URL with a host. http is permitted so local dev IdPs (e.g. a localhost Dex) work; production
// IdPs are https.
func validAbsoluteURL(raw string) bool {
	if raw == "" {
		return false
	}
	// Reject any query string or fragment up front: an OIDC issuer per spec carries neither, and the redirect URI is derived from the
	// external URL's origin + path. A raw scan also catches a bare trailing marker like "https://e?" (Go parses that into ForceQuery
	// with an empty RawQuery), which would otherwise validate and then serialize a redirect URI with a stray "?".
	if strings.ContainsAny(raw, "?#") {
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

func decodeJSON[T any](ctx context.Context, logger *slog.Logger, w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	outcome := httpserver.DecodeCappedJSON(r, updateBodyLimit, &v)
	if outcome == httpserver.BodyReadFailed {
		writeErr(ctx, logger, w, http.StatusBadRequest, "read_body")
		return v, false
	}
	if outcome == httpserver.BodyTooLarge {
		writeErr(ctx, logger, w, http.StatusRequestEntityTooLarge, "body_too_large")
		return v, false
	}
	if outcome == httpserver.BodyInvalidJSON {
		writeErr(ctx, logger, w, http.StatusBadRequest, "invalid_json")
		return v, false
	}
	return v, true
}

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.WriteJSONError(ctx, logger, w, status, code)
}
