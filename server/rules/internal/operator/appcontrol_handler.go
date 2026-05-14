package operator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/appcontrol"
)

// applicationControlReadBodyLimit caps the size of an incoming
// create-rule request body. The expected payload is a small JSON
// object (a few hundred bytes); 16 KiB is far more than that and
// stops a hostile client from streaming megabytes through the handler.
const applicationControlReadBodyLimit = 16 * 1024

// internalErrorMessage is the human-readable body the handler writes
// on every 5xx response that isn't otherwise typed. Extracted to one
// constant so the wire shape stays stable and Sonar's duplicate-
// literal rule (go:S1192) doesn't fire on the four call sites.
const internalErrorMessage = "internal error"

// AppControlHandler serves the rules-context /api/v1/app-control/*
// admin routes. Separate from the catalog Handler because the surface,
// the dependencies (audit + commands + hosts), and the auth gates
// don't overlap; folding both into one struct would force the catalog
// handler tests to mock orchestration concerns they have no business
// touching.
type AppControlHandler struct {
	svc    *appcontrol.Service
	authz  identityapi.AuthZ
	logger *slog.Logger
}

// NewAppControl builds the application-control operator handler. svc
// + authz are required; logger defaults to slog.Default. A nil authz
// would bypass the role matrix entirely — the same panic-on-nil
// posture the catalog handler uses.
func NewAppControl(svc *appcontrol.Service, authz identityapi.AuthZ, logger *slog.Logger) *AppControlHandler {
	if svc == nil {
		panic("rules operator.NewAppControl: Service must not be nil")
	}
	if authz == nil {
		panic("rules operator.NewAppControl: authz must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &AppControlHandler{svc: svc, authz: authz, logger: logger}
}

// RegisterRoutes wires the demo-cut application-control routes:
//
//	GET  /api/v1/app-control/policies
//	GET  /api/v1/app-control/policies/{id}
//	POST /api/v1/app-control/policies/{id}/rules
//
// PATCH / DELETE / bulkUpsert / host-groups / assignments are
// post-demo and not registered here. Caller wraps the mux in identity
// Session + CSRF middleware before mounting (the existing operator
// pattern in cmd/main).
func (h *AppControlHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/app-control/policies", h.handleListPolicies)
	mux.HandleFunc("GET /api/v1/app-control/policies/{id}", h.handleGetPolicy)
	mux.HandleFunc("POST /api/v1/app-control/policies/{id}/rules", h.handleCreateRule)
}

func (h *AppControlHandler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := identityapi.ActorTenantID(ctx)
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlRead,
		identityapi.Resource{TenantID: tenantID, Type: "application_control"}) {
		return
	}
	policies, err := h.svc.ListPolicies(ctx, tenantID)
	if err != nil {
		h.logger.ErrorContext(ctx, "appcontrol list policies", "err", err)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, "internal", internalErrorMessage)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, map[string]any{"policies": policies})
}

func (h *AppControlHandler) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := identityapi.ActorTenantID(ctx)
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlRead,
		identityapi.Resource{TenantID: tenantID, Type: "application_control"}) {
		return
	}
	policyID, ok := parsePolicyID(r)
	if !ok {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, "application_control.invalid_policy_id", "invalid policy id")
		return
	}
	policy, err := h.svc.GetPolicyWithRules(ctx, tenantID, policyID)
	if err != nil {
		if errors.Is(err, api.ErrAppControlPolicyNotFound) {
			writeAppControlErr(ctx, h.logger, w, http.StatusNotFound, "application_control.policy_not_found", "policy not found")
			return
		}
		h.logger.ErrorContext(ctx, "appcontrol get policy", "err", err, "policy_id", policyID)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, "internal", internalErrorMessage)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, policy)
}

// createRuleRequest is the wire shape POST consumers send. Mirrors
// api.CreateRuleRequest but excludes the server-supplied fields
// (PolicyID comes from the URL, Actor from the actor on ctx). Keeping
// the JSON struct local to the handler so the public api.CreateRule
// Request stays a pure server-internal contract that catalog tests
// keep using without HTTP scaffolding.
type createRuleRequest struct {
	RuleType   api.RuleType `json:"rule_type"`
	Identifier string       `json:"identifier"`
	CustomMsg  *string      `json:"custom_msg,omitempty"`
	CustomURL  *string      `json:"custom_url,omitempty"`
	Comment    string       `json:"comment,omitempty"`
	Severity   api.Severity `json:"severity,omitempty"`
	Reason     string       `json:"reason"`
}

func (h *AppControlHandler) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := identityapi.ActorTenantID(ctx)
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlRuleCreate,
		identityapi.Resource{TenantID: tenantID, Type: "application_control"}) {
		return
	}
	policyID, ok := parsePolicyID(r)
	if !ok {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, "application_control.invalid_policy_id", "invalid policy id")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, applicationControlReadBodyLimit))
	if err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, "application_control.read_body", "could not read body")
		return
	}
	var req createRuleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, "application_control.invalid_json", "invalid json")
		return
	}
	actor, ok := identityapi.ActorFromContext(ctx)
	if !ok {
		// Session middleware guarantees an actor on every request that
		// reaches HTTPGate's allow path; an absent actor here is a
		// wiring bug, not a user error. Surface a 500 so the
		// regression is loud rather than silently let CreateRule fall
		// through to a service-layer guard.
		h.logger.ErrorContext(ctx, "appcontrol create rule: no actor on ctx despite session middleware")
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, "internal", internalErrorMessage)
		return
	}

	rule, err := h.svc.CreateRule(ctx, tenantID, api.CreateRuleRequest{
		PolicyID:   policyID,
		RuleType:   req.RuleType,
		Identifier: req.Identifier,
		CustomMsg:  req.CustomMsg,
		CustomURL:  req.CustomURL,
		Comment:    req.Comment,
		Severity:   req.Severity,
		Actor:      actorIdentifierFromContext(ctx),
		Reason:     req.Reason,
	}, actor)
	if err != nil {
		h.writeCreateRuleError(ctx, w, err, policyID)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusCreated, rule)
}

// writeCreateRuleError maps an appcontrol.Service.CreateRule error
// onto the HTTP wire shape. Switching on errors.Is keeps the mapping
// in one place so the handler reads as a happy-path linear function.
func (h *AppControlHandler) writeCreateRuleError(ctx context.Context, w http.ResponseWriter, err error, policyID int64) {
	switch {
	case errors.Is(err, api.ErrAppControlPolicyNotFound):
		writeAppControlErr(ctx, h.logger, w, http.StatusNotFound, "application_control.policy_not_found", "policy not found")
	case errors.Is(err, api.ErrAppControlDuplicateRule):
		writeAppControlErr(ctx, h.logger, w, http.StatusConflict, "application_control.duplicate_rule", "rule already exists for this identifier")
	case api.IsApplicationControlValidationError(err):
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, "application_control.invalid_rule", err.Error())
	default:
		h.logger.ErrorContext(ctx, "appcontrol create rule", "err", err, "policy_id", policyID)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, "internal", internalErrorMessage)
	}
}

// parsePolicyID extracts the {id} path value and parses it as int64.
// Reports false on missing or non-numeric values so callers respond
// 400 with the typed error code rather than letting strconv error
// strings leak into the response.
func parsePolicyID(r *http.Request) (int64, bool) {
	raw := r.PathValue("id")
	if raw == "" {
		return 0, false
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// actorIdentifierFromContext returns a stable string identifier the
// store + audit row use as the "who authored this" tag. The actor's
// email isn't on identityapi.Actor today (Actor carries UserID +
// TenantID + Roles but not email; the audit recorder fetches the
// email separately when writing the row), so this helper renders the
// canonical `user:<id>` shape the store-level "actor is required"
// gate accepts. Empty when no actor is on ctx, which lets the
// store-level Actor required check produce a typed 400 rather than
// the handler having to short-circuit there too.
func actorIdentifierFromContext(ctx context.Context) string {
	a, ok := identityapi.ActorFromContext(ctx)
	if !ok {
		return ""
	}
	if a.UserID > 0 {
		return "user:" + strconv.FormatInt(a.UserID, 10)
	}
	return ""
}

// writeAppControlErr emits the typed ErrorResponse shape every other
// operator handler in the codebase uses. Code is the
// `application_control.<reason>` token; message is the
// human-readable body for the UI to surface.
func writeAppControlErr(
	ctx context.Context,
	logger *slog.Logger,
	w http.ResponseWriter,
	status int,
	code string,
	message string,
) {
	writeJSON(ctx, logger, w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}
