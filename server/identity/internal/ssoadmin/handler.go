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

// configStore is the read subset of *ssoconfig.Store the handler needs outside a snapshot: the stored issuer the test-connection
// probe falls back to. Everything the settings surface reports goes through ReadFunc instead. Narrowed to an interface so tests
// inject a fake.
type configStore interface {
	Get(ctx context.Context) (*ssoconfig.Config, error)
}

// Snapshot is the whole SSO settings surface as it stood at one instant: both stored parts and the version covering them.
//
// Reading it in one go is the point. The two parts were read separately before, so a response could pair one part's new version with
// the other's old value, describing a state that never existed; a client sending that version back passed the concurrency check
// while holding stale data (issue #1046). Config is nil when OIDC has not been configured, which is a state to report rather than an
// error: the deployment may still have an external URL.
type Snapshot struct {
	Config    *ssoconfig.Config
	AppConfig appconfig.AppConfig
	Version   Version
}

// ReadFunc reads both stored parts and their versions from one transaction. Injected so the handler stays unit-testable without
// a DB.
type ReadFunc func(ctx context.Context) (Snapshot, error)

// Expectation says what a save is conditioned on. Checked is false when the caller named no version, which is the unconditional
// overwrite a script that means to overwrite keeps asking for; the write is then still guarded against a change landing between the
// server's own read and its write, as it always was.
type Expectation struct {
	Version Version
	Checked bool
}

// ApplyFunc persists the OIDC config and the app-config document ATOMICALLY (one DB transaction), so a partial write can never
// leave a new issuer/client paired with a stale derived redirect, and reads the result back inside that same transaction so the
// response cannot report a version that does not describe the values beside it. Implementations return a version-conflict error
// (appconfig.ErrVersionConflict or ssoconfig.ErrVersionConflict) when the Expectation does not hold, having written nothing.
type ApplyFunc func(
	ctx context.Context, oidcIn ssoconfig.UpsertInput, appCfg appconfig.AppConfig, expected Expectation, updatedBy string,
) (Snapshot, error)

// prober verifies a candidate issuer is reachable. Production wraps oidc.Probe with the deployment HTTP client; tests inject a fake.
type prober func(ctx context.Context, issuer string) error

// Handler serves the /api/settings/sso routes. Construct via NewHandler; mount with RegisterAuthedRoutes behind the session + CSRF
// middleware. It spans two stores: the typed oidc_config (with its sealed secret) and the appconfig document (external URL).
type Handler struct {
	store  configStore
	read   ReadFunc
	apply  ApplyFunc
	authz  api.AuthZ
	audit  api.AuditRecorder
	probe  prober
	logger *slog.Logger
}

// NewHandler builds the handler. store, appCfg, apply, authz, and probe are load-bearing; logger defaults to slog.Default. audit may
// be nil only in tests that do not assert on the audit row.
func NewHandler(
	store configStore, read ReadFunc, apply ApplyFunc,
	authz api.AuthZ, audit api.AuditRecorder, probe prober, logger *slog.Logger,
) *Handler {
	if store == nil {
		panic("ssoadmin.NewHandler: store is required")
	}
	if read == nil {
		panic("ssoadmin.NewHandler: read is required")
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
	return &Handler{store: store, read: read, apply: apply, authz: authz, audit: audit, probe: probe, logger: logger}
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
	// Version identifies the configuration this response describes. Send it back on a save to have that save refused if anything
	// here changed in the meantime. Opaque: read it, send it, do not take it apart.
	Version string `json:"version"`
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !api.HTTPGate(ctx, w, h.authz, h.logger, api.ActionSSOManage, api.Resource{Type: "sso_config"}) {
		return
	}
	// Both parts from one snapshot, so the version this reports describes the values reported beside it. The external URL is
	// deployment-level and may be set before OIDC is configured, so it is included either way.
	snap, err := h.read(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "sso settings read", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, toResponse(snap))
}

// updateRequest is the write shape. ClientSecret is a pointer so the field is distinguishable as absent (keep the stored secret) vs
// present. An empty string is also treated as "keep", so a UI that always submits the field but leaves it blank never clears a secret;
// only a non-empty value rotates it. Every other field replaces what is stored, the group mapping included.
type updateRequest struct {
	Issuer       string                `json:"issuer"`
	ClientID     string                `json:"client_id"`
	ClientSecret *string               `json:"client_secret"`
	ExternalURL  string                `json:"external_url"`
	Scopes       []string              `json:"scopes"`
	JITEnabled   bool                  `json:"jit_enabled"`
	DefaultRole  string                `json:"default_role"`
	GroupsClaim  string                `json:"groups_claim"`
	GroupRoles   []ssoconfig.GroupRole `json:"group_roles"`
	// Version is the one read from this endpoint, sent back to have the save refused if the configuration changed since. OMIT it to
	// overwrite whatever is stored, which is what automation that means to set the configuration outright wants.
	//
	// A pointer so an absent field is distinguishable from a present one, because the two mean opposite things here and the string
	// zero value cannot carry both. Sending "" is a client that has a version field and nothing to put in it, which is the state a
	// page has before its first read completes: refused, rather than quietly promoted to the overwrite. JSON null reads as absent,
	// the same as ClientSecret above, since a client that writes null is saying the field has no value.
	Version *string `json:"version"`
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
	// A version the caller named is the configuration it was editing. One it did not is the unconditional overwrite a script asks
	// for by omission, which stays available deliberately: automation that means to set the configuration outright should not have
	// to read it first. A version that does not parse is refused rather than dropped, because dropping it would quietly turn a
	// conditional save into that overwrite.
	expected := Expectation{}
	if req.Version != nil {
		parsed, parseErr := ParseVersion(*req.Version)
		if parseErr != nil {
			writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_version")
			return
		}
		expected = Expectation{Version: parsed, Checked: true}
	}
	// Read-modify-write on the app-config document so unrelated settings survive. The snapshot.s own versions guard the write when
	// the caller named none, which is what kept a concurrent edit from being lost between this read and the write below.
	snap, err := h.read(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "sso settings read for update", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	if !expected.Checked {
		expected.Version = snap.Version
	}
	appCfg := snap.AppConfig
	appCfg.ExternalURL = externalURL
	// One transaction writes oidc_config + app_config together and reads both back: a partial write can never pair a new issuer
	// with a stale redirect, and the version returned describes the values returned with it.
	saved, err := h.apply(ctx, in, appCfg, expected, in.UpdatedBy)
	if err != nil {
		if errors.Is(err, appconfig.ErrVersionConflict) || errors.Is(err, ssoconfig.ErrVersionConflict) {
			writeErr(ctx, h.logger, w, http.StatusConflict, "version_conflict")
			return
		}
		h.logger.ErrorContext(ctx, "sso config apply", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	h.recordUpdate(ctx, r, actor.Principal, in, externalURL)
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, toResponse(saved))
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
	if err := h.audit.Record(ctx, api.AuditEvent{
		Actor:      actor,
		Action:     api.AuditAction("sso.config.updated"),
		TargetType: "sso_config",
		RemoteAddr: httpserver.ClientIP(r),
		Payload: map[string]any{
			"issuer":         in.Issuer,
			"external_url":   externalURL,
			"jit_enabled":    in.JITEnabled,
			"default_role":   in.DefaultRole,
			"groups_claim":   in.GroupsClaim,
			"group_roles":    in.GroupRoles,
			"secret_rotated": in.NewSecret != nil,
		},
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
	groupsClaim, groupRoles, reason := validGroupMapping(req.GroupsClaim, req.GroupRoles)
	if reason != "" {
		return ssoconfig.UpsertInput{}, "", reason, false
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
		Scopes:      scopes,
		JITEnabled:  req.JITEnabled,
		DefaultRole: role,
		GroupsClaim: groupsClaim,
		GroupRoles:  groupRoles,
	}, externalURL, "", true
}

// validGroupMapping trims and checks the groups claim and the group mappings, returning them normalized (roles lower-cased) or a
// wire-format reason. The claim and the mappings come together: a claim with no mappings would put every operator in the default role
// at sign-in, and mappings with no claim would never apply.
func validGroupMapping(claim string, in []ssoconfig.GroupRole) (string, []ssoconfig.GroupRole, string) {
	claim = strings.TrimSpace(claim)
	switch {
	case utf8.RuneCountInString(claim) > maxGroupFieldLen:
		return "", nil, "invalid_groups_claim"
	case claim == "" && len(in) > 0:
		return "", nil, "missing_groups_claim"
	case claim != "" && len(in) == 0:
		return "", nil, "missing_group_roles"
	}
	out := make([]ssoconfig.GroupRole, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, gr := range in {
		group := strings.TrimSpace(gr.Group)
		role := strings.ToLower(strings.TrimSpace(gr.Role))
		if group == "" || utf8.RuneCountInString(group) > maxGroupFieldLen || !rbac.GrantableRoles[role] {
			return "", nil, "invalid_group_role"
		}
		if seen[group] {
			return "", nil, "duplicate_group"
		}
		seen[group] = true
		out = append(out, ssoconfig.GroupRole{Group: group, Role: role})
	}
	return claim, out, ""
}

// toResponse renders a Snapshot. An unconfigured deployment still reports its external URL and its version, because the version is
// what the first save is conditioned on: a client with no version to send could only overwrite, which is the race this closes.
func toResponse(snap Snapshot) configResponse {
	externalURL := snap.AppConfig.ExternalURL
	if snap.Config == nil {
		return configResponse{
			Configured:  false,
			ExternalURL: externalURL,
			RedirectURL: ssoconfig.RedirectURLFor(externalURL),
			GroupRoles:  []ssoconfig.GroupRole{},
			Version:     snap.Version.String(),
		}
	}
	c := snap.Config
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
		Version:     snap.Version.String(),
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
