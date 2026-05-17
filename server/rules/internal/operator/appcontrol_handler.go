package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/appcontrol"
)

// applicationControlReadBodyLimit caps the size of an incoming create-rule request body. The expected payload is a small JSON object
// (a few hundred bytes); 16 KiB is far more than that and stops a hostile client from streaming megabytes through the handler.
const applicationControlReadBodyLimit = 16 * 1024

// internalErrorMessage is the human-readable body the handler writes on every 5xx response that isn't otherwise typed. Extracted to
// one constant so the wire shape stays stable and Sonar's duplicate-literal rule (go:S1192) doesn't fire on the four call sites.
const internalErrorMessage = "internal error"

// Error-code + human-message constants shared by handler error-mapping paths. Each pair (code + msg) is duplicated 3-6x across the
// 8 handler functions; collapsing here keeps the wire shape stable AND silences Sonar's duplicate-literal rule.
const (
	errCodeInvalidPolicyID = "application_control.invalid_policy_id"
	errMsgInvalidPolicyID  = "invalid policy id"
	errCodeInvalidRuleID   = "application_control.invalid_rule_id"
	errMsgInvalidRuleID    = "invalid rule id"
	errCodePolicyNotFound  = "application_control.policy_not_found"
	errMsgPolicyNotFound   = "policy not found"
	errCodeRuleNotFound    = "application_control.rule_not_found"
	errMsgRuleNotFound     = "rule not found"
	errCodeReadBody        = "application_control.read_body"
	errMsgReadBody         = "could not read body"
	errCodeInvalidJSON     = "application_control.invalid_json"
	errMsgInvalidJSON      = "invalid json"
	errCodeDuplicateRule   = "application_control.duplicate_rule"
	errMsgDuplicateRule    = "rule already exists for this identifier"
	errCodeInvalidRule     = "application_control.invalid_rule"
	errCodeInvalidPolicy   = "application_control.invalid_policy"
	errCodeDuplicatePolicy = "application_control.duplicate_policy"
	errMsgDuplicatePolicy  = "a policy with that name already exists"
	errCodePolicyImmutable = "application_control.policy_immutable"
	errMsgPolicyImmutable  = "the seed Default policy cannot be deleted"
	internalErrorCode      = "internal"
	noActorOnContextLogMsg = "appcontrol handler: no actor on ctx despite session middleware"
)

// AppControlHandler serves the rules-context /api/v1/app-control/* admin routes. Separate from the catalog Handler because the
// surface, the dependencies (audit + commands + hosts), and the auth gates don't overlap; folding both into one struct would force the
// catalog handler tests to mock orchestration concerns they have no business touching.
type AppControlHandler struct {
	svc    *appcontrol.Service
	authz  identityapi.AuthZ
	logger *slog.Logger
}

// NewAppControl builds the application-control operator handler. svc + authz are required; logger defaults to slog.Default. A nil
// authz would bypass the role matrix entirely — the same panic-on-nil posture the catalog handler uses.
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

// RegisterRoutes wires the application-control admin routes:
//
//	GET    /api/v1/app-control/policies
//	GET    /api/v1/app-control/policies/{id}
//	POST   /api/v1/app-control/policies
//	PATCH  /api/v1/app-control/policies/{id}
//	DELETE /api/v1/app-control/policies/{id}
//	POST   /api/v1/app-control/policies/{id}/rules
//	PATCH  /api/v1/app-control/rules/{id}
//	DELETE /api/v1/app-control/rules/{id}
//
// Bulk-upsert / cross-policy rule list / host-groups CRUD / assignments POST stay deferred to follow-on PRs. Caller wraps the mux
// in identity Session + CSRF middleware before mounting (the existing operator pattern in cmd/main).
func (h *AppControlHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/app-control/policies", h.handleListPolicies)
	mux.HandleFunc("GET /api/v1/app-control/policies/{id}", h.handleGetPolicy)
	mux.HandleFunc("POST /api/v1/app-control/policies", h.handleCreatePolicy)
	mux.HandleFunc("PATCH /api/v1/app-control/policies/{id}", h.handleUpdatePolicy)
	mux.HandleFunc("DELETE /api/v1/app-control/policies/{id}", h.handleDeletePolicy)
	mux.HandleFunc("POST /api/v1/app-control/policies/{id}/rules", h.handleCreateRule)
	mux.HandleFunc("PATCH /api/v1/app-control/rules/{id}", h.handleUpdateRule)
	mux.HandleFunc("DELETE /api/v1/app-control/rules/{id}", h.handleDeleteRule)
}

func (h *AppControlHandler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlRead,
		identityapi.Resource{Type: "application_control"}) {
		return
	}
	policies, err := h.svc.ListPolicies(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "appcontrol list policies", "err", err)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, map[string]any{"policies": policies})
}

func (h *AppControlHandler) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlRead,
		identityapi.Resource{Type: "application_control"}) {
		return
	}
	policyID, ok := parsePolicyID(r)
	if !ok {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidPolicyID, errMsgInvalidPolicyID)
		return
	}
	policy, err := h.svc.GetPolicyWithRules(ctx, policyID)
	if err != nil {
		if errors.Is(err, api.ErrAppControlPolicyNotFound) {
			writeAppControlErr(ctx, h.logger, w, http.StatusNotFound, errCodePolicyNotFound, errMsgPolicyNotFound)
			return
		}
		h.logger.ErrorContext(ctx, "appcontrol get policy", "err", err, "policy_id", policyID)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, policy)
}

// createRuleRequest is the wire shape POST consumers send. Mirrors api.CreateRuleRequest but excludes the server-supplied
// fields (PolicyID comes from the URL, Actor from the actor on ctx). Keeping the JSON struct local to the handler so the public
// api.CreateRule Request stays a pure server-internal contract that catalog tests keep using without HTTP scaffolding.
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
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlRuleCreate,
		identityapi.Resource{Type: "application_control"}) {
		return
	}
	policyID, ok := parsePolicyID(r)
	if !ok {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidPolicyID, errMsgInvalidPolicyID)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, applicationControlReadBodyLimit))
	if err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeReadBody, errMsgReadBody)
		return
	}
	var req createRuleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidJSON, errMsgInvalidJSON)
		return
	}
	actor, ok := identityapi.ActorFromContext(ctx)
	if !ok {
		// Session middleware guarantees an actor on every request that reaches HTTPGate's allow path; an absent actor here
		// is a wiring bug, not a user error. Surface a 500 so the regression is loud rather than silently let CreateRule fall
		// through to a service-layer guard.
		h.logger.ErrorContext(ctx, noActorOnContextLogMsg)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
		return
	}

	rule, err := h.svc.CreateRule(ctx, api.CreateRuleRequest{
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

// writeCreateRuleError maps an appcontrol.Service.CreateRule error onto the HTTP wire shape. Switching on errors.Is keeps the mapping
// in one place so the handler reads as a happy-path linear function.
func (h *AppControlHandler) writeCreateRuleError(ctx context.Context, w http.ResponseWriter, err error, policyID int64) {
	switch {
	case errors.Is(err, api.ErrAppControlPolicyNotFound):
		writeAppControlErr(ctx, h.logger, w, http.StatusNotFound, errCodePolicyNotFound, errMsgPolicyNotFound)
	case errors.Is(err, api.ErrAppControlDuplicateRule):
		writeAppControlErr(ctx, h.logger, w, http.StatusConflict, errCodeDuplicateRule, errMsgDuplicateRule)
	case api.IsApplicationControlValidationError(err):
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidRule, err.Error())
	default:
		h.logger.ErrorContext(ctx, "appcontrol create rule", "err", err, "policy_id", policyID)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
	}
}

// writeRuleMutationError centralises the rule-update + rule-delete error mapping so the two handlers stay symmetric. RuleNotFound
// → 404; the validator + invalid-request errors → 400; duplicate-rule cannot fire on update/delete today (we never re-write the
// identifier) but the case is included so a Phase B refactor that changes that doesn't leak a 500.
func (h *AppControlHandler) writeRuleMutationError(ctx context.Context, w http.ResponseWriter, action string, err error, ruleID int64) {
	switch {
	case errors.Is(err, api.ErrAppControlRuleNotFound):
		writeAppControlErr(ctx, h.logger, w, http.StatusNotFound, errCodeRuleNotFound, errMsgRuleNotFound)
	case errors.Is(err, api.ErrAppControlDuplicateRule):
		writeAppControlErr(ctx, h.logger, w, http.StatusConflict, errCodeDuplicateRule, errMsgDuplicateRule)
	case api.IsApplicationControlValidationError(err):
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidRule, err.Error())
	default:
		h.logger.ErrorContext(ctx, "appcontrol "+action, "err", err, "rule_id", ruleID)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
	}
}

// writePolicyMutationError centralises the policy-create + policy-update + policy-delete error mapping so the three handlers stay
// symmetric. PolicyNotFound → 404; DuplicatePolicy → 409; PolicyImmutable (DELETE on Default) → 409; validation → 400.
func (h *AppControlHandler) writePolicyMutationError(ctx context.Context, w http.ResponseWriter, action string, err error, policyID int64) {
	switch {
	case errors.Is(err, api.ErrAppControlPolicyNotFound):
		writeAppControlErr(ctx, h.logger, w, http.StatusNotFound, errCodePolicyNotFound, errMsgPolicyNotFound)
	case errors.Is(err, api.ErrAppControlDuplicatePolicy):
		writeAppControlErr(ctx, h.logger, w, http.StatusConflict, errCodeDuplicatePolicy, errMsgDuplicatePolicy)
	case errors.Is(err, api.ErrAppControlPolicyImmutable):
		writeAppControlErr(ctx, h.logger, w, http.StatusConflict, errCodePolicyImmutable, errMsgPolicyImmutable)
	case api.IsApplicationControlValidationError(err):
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidPolicy, err.Error())
	default:
		h.logger.ErrorContext(ctx, "appcontrol "+action, "err", err, "policy_id", policyID)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
	}
}

// updateRuleRequest is the PATCH wire shape. Every mutable field is a pointer so a JSON omit / null is distinguishable from an
// explicit zero (e.g. clearing custom_msg by sending ""). Phase B's Detect-mode change layers an Enforcement field on top of this
// struct; for Phase A the field is unsupported (the schema column carries it, the handler doesn't accept it).
type updateRuleRequest struct {
	Enabled   *bool         `json:"enabled,omitempty"`
	Severity  *api.Severity `json:"severity,omitempty"`
	CustomMsg *string       `json:"custom_msg,omitempty"`
	CustomURL *string       `json:"custom_url,omitempty"`
	Comment   *string       `json:"comment,omitempty"`
	ExpiresAt *time.Time    `json:"expires_at,omitempty"`
	Reason    string        `json:"reason"`
}

func (h *AppControlHandler) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlRuleUpdate,
		identityapi.Resource{Type: "application_control"}) {
		return
	}
	ruleID, ok := parseRuleID(r)
	if !ok {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidRuleID, errMsgInvalidRuleID)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, applicationControlReadBodyLimit))
	if err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeReadBody, errMsgReadBody)
		return
	}
	var req updateRuleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidJSON, errMsgInvalidJSON)
		return
	}
	actor, ok := identityapi.ActorFromContext(ctx)
	if !ok {
		h.logger.ErrorContext(ctx, noActorOnContextLogMsg)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
		return
	}
	rule, err := h.svc.UpdateRule(ctx, api.UpdateRuleRequest{
		RuleID:    ruleID,
		Enabled:   req.Enabled,
		Severity:  req.Severity,
		CustomMsg: req.CustomMsg,
		CustomURL: req.CustomURL,
		Comment:   req.Comment,
		ExpiresAt: req.ExpiresAt,
		Actor:     actorIdentifierFromContext(ctx),
		Reason:    req.Reason,
	}, actor)
	if err != nil {
		h.writeRuleMutationError(ctx, w, "update rule", err, ruleID)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, rule)
}

// deleteRuleRequest carries the audit reason. DELETE bodies are unusual in HTTP norms but JSON-RPC-style admin APIs (which this
// is) commonly send a body to satisfy audit-required-on-mutation policies; documented in the openspec REST surface.
type deleteRuleRequest struct {
	Reason string `json:"reason"`
}

func (h *AppControlHandler) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlRuleDelete,
		identityapi.Resource{Type: "application_control"}) {
		return
	}
	ruleID, ok := parseRuleID(r)
	if !ok {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidRuleID, errMsgInvalidRuleID)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, applicationControlReadBodyLimit))
	if err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeReadBody, errMsgReadBody)
		return
	}
	var req deleteRuleRequest
	// Whitespace-only bodies are normalised to empty so an operator sending a body of just spaces does not get a misleading
	// invalid_json (the typed reason-required validation should fire instead). Copilot flagged this on PR #188.
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidJSON, errMsgInvalidJSON)
			return
		}
	}
	actor, ok := identityapi.ActorFromContext(ctx)
	if !ok {
		h.logger.ErrorContext(ctx, noActorOnContextLogMsg)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
		return
	}
	if err := h.svc.DeleteRule(ctx, api.DeleteRuleRequest{
		RuleID: ruleID,
		Actor:  actorIdentifierFromContext(ctx),
		Reason: req.Reason,
	}, actor); err != nil {
		h.writeRuleMutationError(ctx, w, "delete rule", err, ruleID)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// createPolicyRequest is the POST /policies wire shape. Description is optional; Reason is required for audit.
type createPolicyRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Reason      string `json:"reason"`
}

func (h *AppControlHandler) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlPolicyCreate,
		identityapi.Resource{Type: "application_control"}) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, applicationControlReadBodyLimit))
	if err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeReadBody, errMsgReadBody)
		return
	}
	var req createPolicyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidJSON, errMsgInvalidJSON)
		return
	}
	actor, ok := identityapi.ActorFromContext(ctx)
	if !ok {
		h.logger.ErrorContext(ctx, noActorOnContextLogMsg)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
		return
	}
	policy, err := h.svc.CreatePolicy(ctx, api.CreatePolicyRequest{
		Name:        req.Name,
		Description: req.Description,
		Actor:       actorIdentifierFromContext(ctx),
		Reason:      req.Reason,
	}, actor)
	if err != nil {
		h.writePolicyMutationError(ctx, w, "create policy", err, 0)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusCreated, policy)
}

// updatePolicyRequest is the PATCH /policies/{id} wire shape. Both name and description are pointer-optional.
type updatePolicyRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Reason      string  `json:"reason"`
}

func (h *AppControlHandler) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlPolicyUpdate,
		identityapi.Resource{Type: "application_control"}) {
		return
	}
	policyID, ok := parsePolicyID(r)
	if !ok {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidPolicyID, errMsgInvalidPolicyID)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, applicationControlReadBodyLimit))
	if err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeReadBody, errMsgReadBody)
		return
	}
	var req updatePolicyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidJSON, errMsgInvalidJSON)
		return
	}
	actor, ok := identityapi.ActorFromContext(ctx)
	if !ok {
		h.logger.ErrorContext(ctx, noActorOnContextLogMsg)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
		return
	}
	policy, err := h.svc.UpdatePolicy(ctx, api.UpdatePolicyRequest{
		PolicyID:    policyID,
		Name:        req.Name,
		Description: req.Description,
		Actor:       actorIdentifierFromContext(ctx),
		Reason:      req.Reason,
	}, actor)
	if err != nil {
		h.writePolicyMutationError(ctx, w, "update policy", err, policyID)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, policy)
}

// deletePolicyRequest carries the audit reason for DELETE /policies/{id}.
type deletePolicyRequest struct {
	Reason string `json:"reason"`
}

func (h *AppControlHandler) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionAppControlPolicyDelete,
		identityapi.Resource{Type: "application_control"}) {
		return
	}
	policyID, ok := parsePolicyID(r)
	if !ok {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidPolicyID, errMsgInvalidPolicyID)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, applicationControlReadBodyLimit))
	if err != nil {
		writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeReadBody, errMsgReadBody)
		return
	}
	var req deletePolicyRequest
	// Whitespace-only bodies are normalised to empty so an operator sending a body of just spaces does not get a misleading
	// invalid_json (the typed reason-required validation should fire instead). Copilot flagged this on PR #188.
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeAppControlErr(ctx, h.logger, w, http.StatusBadRequest, errCodeInvalidJSON, errMsgInvalidJSON)
			return
		}
	}
	actor, ok := identityapi.ActorFromContext(ctx)
	if !ok {
		h.logger.ErrorContext(ctx, noActorOnContextLogMsg)
		writeAppControlErr(ctx, h.logger, w, http.StatusInternalServerError, internalErrorCode, internalErrorMessage)
		return
	}
	if err := h.svc.DeletePolicy(ctx, api.DeletePolicyRequest{
		PolicyID: policyID,
		Actor:    actorIdentifierFromContext(ctx),
		Reason:   req.Reason,
	}, actor); err != nil {
		h.writePolicyMutationError(ctx, w, "delete policy", err, policyID)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parsePositiveInt64Path extracts the {id} path value and parses it as a positive int64. Used by parsePolicyID + parseRuleID — both
// of which previously had identical implementations (Sonar S4144). The thin per-route wrappers keep call-site readability ("we're
// pulling a policy id here") while collapsing the implementation to one source of truth.
func parsePositiveInt64Path(r *http.Request) (int64, bool) {
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

// parseRuleID extracts the {id} path value off /rules/{id} as a positive int64. Wrapper around parsePositiveInt64Path so the call
// site reads as "we're pulling a rule id here" and a future schema change that splits the namespace can land on one helper.
func parseRuleID(r *http.Request) (int64, bool) { return parsePositiveInt64Path(r) }

// parsePolicyID extracts the {id} path value off /policies/{id} as a positive int64. Wrapper around parsePositiveInt64Path; see
// parseRuleID for the rationale.
func parsePolicyID(r *http.Request) (int64, bool) { return parsePositiveInt64Path(r) }

// actorIdentifierFromContext returns a stable string identifier the store + audit row use as the "who authored this" tag. The actor's
// email isn't on identityapi.Actor today (Actor carries UserID + Roles but not email; the audit recorder fetches the email separately
// when writing the row), so this helper renders the canonical `user:<id>` shape the store-level "actor is required" gate accepts.
// Empty when no actor is on ctx, which lets the store-level Actor required check produce a typed 400 rather than the handler having to
// short-circuit there too.
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

// writeAppControlErr emits the typed ErrorResponse shape every other operator handler in the codebase uses. Code is the
// `application_control.<reason>` token; message is the human-readable body for the UI to surface.
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
