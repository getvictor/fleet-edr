package operator

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
)

const detectionConfigReadBodyLimit = 16 * 1024

const (
	errCodeDCInvalidJSON  = "detection_config.invalid_json"
	errCodeDCReadBody     = "detection_config.read_body"
	errCodeDCInvalidInput = "detection_config.invalid_input"
	errCodeDCInvalidID    = "detection_config.invalid_id"
	errCodeDCNotFound     = "detection_config.not_found"
	errCodeDCInternal     = "internal"

	// msgDCInternal is the body message for every 500 the handler emits; extracted so the literal isn't duplicated (Sonar go:S1192).
	msgDCInternal = "internal error"
	// msgDCReasonRequired is returned when a mutation omits the audit reason. A blank reason would leave the audit row's governance
	// field empty, defeating the surface's accountability intent, so the handler rejects it with a 400.
	msgDCReasonRequired = "reason is required"
)

// detectionConfigService is the narrow surface the handler consumes; *detectionconfig.Service satisfies it. An interface so handler
// tests can inject a fake returning canned results + errors to exercise the success and error branches without a database.
type detectionConfigService interface {
	ListExclusions(ctx context.Context) ([]api.DetectionExclusion, error)
	ListRuleSettings(ctx context.Context) ([]api.DetectionRuleSetting, error)
	CreateExclusion(ctx context.Context, actor *identityapi.Actor, reason string, in detectionconfig.CreateExclusionInput) (api.DetectionExclusion, error)
	DeleteExclusion(ctx context.Context, actor *identityapi.Actor, reason string, id int64) error
	UpsertRuleSetting(ctx context.Context, actor *identityapi.Actor, reason string, in detectionconfig.UpsertSettingInput) (api.DetectionRuleSetting, error)
}

// userEmailResolver resolves a numeric user id to its display email for the exclusions list's created_by column. Optional: a nil
// resolver (or one that errors / returns "") leaves CreatedByEmail empty so the UI falls back to the raw "user:<id>". cmd/main wires
// it over identity's Service.GetUser; keeping it a func avoids a cross-context import of the identity internals (ADR-0004).
type userEmailResolver func(ctx context.Context, userID int64) (string, error)

// DetectionConfigHandler serves the rules-context /api/v1/detection-config/* admin routes (issue #459): the per-host false-positive
// exclusions and per-rule mode/severity the detection engine consults at evaluation time. Separate from the App Control handler
// because the surface and dependencies do not overlap.
type DetectionConfigHandler struct {
	svc       detectionConfigService
	authz     identityapi.AuthZ
	userEmail userEmailResolver
	logger    *slog.Logger
}

// NewDetectionConfig builds the detection-config operator handler. svc + authz are required; logger defaults to slog.Default. A nil
// authz would bypass the role matrix, so it panics (same posture as the other rules handlers).
func NewDetectionConfig(svc detectionConfigService, authz identityapi.AuthZ, logger *slog.Logger) *DetectionConfigHandler {
	if svc == nil {
		panic("rules operator.NewDetectionConfig: Service must not be nil")
	}
	if authz == nil {
		panic("rules operator.NewDetectionConfig: authz must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DetectionConfigHandler{svc: svc, authz: authz, logger: logger}
}

// SetUserEmailResolver wires the optional directory lookup that resolves an exclusion's created_by ("user:<id>") to a display email.
// Mirrors SetAudit: set post-construction so non-REST consumers and tests that don't need email resolution can skip it.
func (h *DetectionConfigHandler) SetUserEmailResolver(r userEmailResolver) {
	h.userEmail = r
}

// resolveCreatedByEmails fills CreatedByEmail on each exclusion by resolving its "user:<id>" created_by through the directory. A nil
// resolver is a no-op (the UI falls back to the raw identifier). Lookups are memoized per call so N exclusions from the same author
// cost one directory hit; a failed or empty lookup leaves that row's email blank rather than failing the list.
func (h *DetectionConfigHandler) resolveCreatedByEmails(ctx context.Context, exclusions []api.DetectionExclusion) {
	if h.userEmail == nil {
		return
	}
	cache := make(map[int64]string)
	for i := range exclusions {
		id, ok := parseUserActorID(exclusions[i].CreatedBy)
		if !ok {
			continue
		}
		email, seen := cache[id]
		if !seen {
			resolved, err := h.userEmail(ctx, id)
			if err != nil {
				// A deleted user (ErrUserNotFound) is the expected fallback case: the UI shows the raw "user:<id>". Warning on it
				// would spam the log on every list render per missing author, so only genuinely unexpected failures get a WARN.
				if !errors.Is(err, identityapi.ErrUserNotFound) {
					h.logger.WarnContext(ctx, "detectionconfig: resolve created_by email", "user_id", id, "err", err)
				}
				resolved = ""
			}
			email = resolved
			cache[id] = email
		}
		exclusions[i].CreatedByEmail = email
	}
}

// parseUserActorID extracts the numeric id from the "user:<id>" actor identifier the service records as created_by. Returns false for
// any other shape (e.g. a service-account or empty actor) so the caller leaves the email unresolved.
func parseUserActorID(actor string) (int64, bool) {
	rest, ok := strings.CutPrefix(actor, "user:")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// RegisterRoutes wires the detection-config admin routes:
//
//	GET    /api/v1/detection-config/exclusions
//	POST   /api/v1/detection-config/exclusions
//	DELETE /api/v1/detection-config/exclusions/{id}
//	GET    /api/v1/detection-config/rule-settings
//	PUT    /api/v1/detection-config/rule-settings
//
// Caller wraps in the identity Session + CSRF middleware before mounting (the session-protected allowlist auto-derives from what is
// registered here).
func (h *DetectionConfigHandler) RegisterRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/v1/detection-config/exclusions", h.handleListExclusions)
	mux.HandleFunc("POST /api/v1/detection-config/exclusions", h.handleCreateExclusion)
	mux.HandleFunc("DELETE /api/v1/detection-config/exclusions/{id}", h.handleDeleteExclusion)
	mux.HandleFunc("GET /api/v1/detection-config/rule-settings", h.handleListRuleSettings)
	mux.HandleFunc("PUT /api/v1/detection-config/rule-settings", h.handleUpsertRuleSetting)
}

func (h *DetectionConfigHandler) handleListExclusions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionDetectionConfigRead, identityapi.Resource{Type: "detection_config"}) {
		return
	}
	exclusions, err := h.svc.ListExclusions(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "detectionconfig list exclusions", "err", err)
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusInternalServerError, errCodeDCInternal, msgDCInternal)
		return
	}
	h.resolveCreatedByEmails(ctx, exclusions)
	writeJSON(ctx, h.logger, w, http.StatusOK, map[string]any{"exclusions": exclusions})
}

func (h *DetectionConfigHandler) handleListRuleSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionDetectionConfigRead, identityapi.Resource{Type: "detection_config"}) {
		return
	}
	settings, err := h.svc.ListRuleSettings(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "detectionconfig list rule settings", "err", err)
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusInternalServerError, errCodeDCInternal, msgDCInternal)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, map[string]any{"rule_settings": settings})
}

// createExclusionRequest is the POST wire shape. host_group_id defaults to 0 (global). created_by + the audit actor come from the
// session, not the body. reason rides the audit row.
type createExclusionRequest struct {
	RuleID      string                 `json:"rule_id"`
	MatchType   api.ExclusionMatchType `json:"match_type"`
	Value       string                 `json:"value"`
	HostGroupID int64                  `json:"host_group_id,omitempty"`
	Reason      string                 `json:"reason"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
}

func (h *DetectionConfigHandler) handleCreateExclusion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionDetectionConfigWrite, identityapi.Resource{Type: "detection_config"}) {
		return
	}
	var req createExclusionRequest
	if !h.decode(ctx, w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidInput, msgDCReasonRequired)
		return
	}
	actor, ok := h.actor(ctx, w)
	if !ok {
		return
	}
	// Group-scoped entries are accepted by the schema but not yet honored at evaluation time (host-group editing is Phase A
	// immutable; membership wiring lands with editable host groups). Reject a non-global scope now rather than silently create a
	// dead entry.
	if req.HostGroupID != api.GlobalScope {
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidInput,
			"host-group-scoped exclusions are not supported yet; use global scope (host_group_id 0)")
		return
	}
	excl, err := h.svc.CreateExclusion(ctx, actor, req.Reason, detectionconfig.CreateExclusionInput{
		RuleID:      req.RuleID,
		MatchType:   req.MatchType,
		Value:       req.Value,
		HostGroupID: req.HostGroupID,
		Reason:      req.Reason,
		ExpiresAt:   req.ExpiresAt,
	})
	if err != nil {
		h.writeMutationErr(ctx, w, "create exclusion", err)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusCreated, excl)
}

func (h *DetectionConfigHandler) handleDeleteExclusion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionDetectionConfigWrite, identityapi.Resource{Type: "detection_config"}) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidID, "invalid exclusion id")
		return
	}
	// The delete reason rides a query parameter (DELETE carries no body by convention here); it is required for the audit row.
	reason := r.URL.Query().Get("reason")
	if strings.TrimSpace(reason) == "" {
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidInput, msgDCReasonRequired)
		return
	}
	actor, ok := h.actor(ctx, w)
	if !ok {
		return
	}
	if err := h.svc.DeleteExclusion(ctx, actor, reason, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeDetectionConfigErr(ctx, h.logger, w, http.StatusNotFound, errCodeDCNotFound, "exclusion not found")
			return
		}
		h.writeMutationErr(ctx, w, "delete exclusion", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// upsertRuleSettingRequest is the PUT wire shape. The (rule_id, host_group_id) pair is the upsert key.
type upsertRuleSettingRequest struct {
	RuleID           string                `json:"rule_id"`
	HostGroupID      int64                 `json:"host_group_id,omitempty"`
	Mode             api.DetectionRuleMode `json:"mode"`
	SeverityOverride string                `json:"severity_override,omitempty"`
	Reason           string                `json:"reason"`
}

func (h *DetectionConfigHandler) handleUpsertRuleSetting(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionDetectionConfigWrite, identityapi.Resource{Type: "detection_config"}) {
		return
	}
	var req upsertRuleSettingRequest
	if !h.decode(ctx, w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidInput, msgDCReasonRequired)
		return
	}
	actor, ok := h.actor(ctx, w)
	if !ok {
		return
	}
	if req.HostGroupID != api.GlobalScope {
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidInput,
			"host-group-scoped rule settings are not supported yet; use global scope (host_group_id 0)")
		return
	}
	setting, err := h.svc.UpsertRuleSetting(ctx, actor, req.Reason, detectionconfig.UpsertSettingInput{
		RuleID:           req.RuleID,
		HostGroupID:      req.HostGroupID,
		Mode:             req.Mode,
		SeverityOverride: req.SeverityOverride,
	})
	if err != nil {
		h.writeMutationErr(ctx, w, "upsert rule setting", err)
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, setting)
}

// decode reads + unmarshals a JSON body under the size limit, writing the right 400 on failure. Returns false when it has already
// written an error response.
func (h *DetectionConfigHandler) decode(ctx context.Context, w http.ResponseWriter, r *http.Request, dst any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, detectionConfigReadBodyLimit))
	if err != nil {
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCReadBody, "could not read request body")
		return false
	}
	if err := json.Unmarshal(body, dst); err != nil {
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidJSON, "invalid JSON body")
		return false
	}
	return true
}

// actor pulls the session actor off the context. An absent actor on an allow-path request is a wiring bug (the session middleware
// guarantees one), so it surfaces a 500 rather than letting the store's required-actor guard produce a confusing 400.
func (h *DetectionConfigHandler) actor(ctx context.Context, w http.ResponseWriter) (*identityapi.Actor, bool) {
	actor, ok := identityapi.ActorFromContext(ctx)
	if !ok {
		h.logger.ErrorContext(ctx, "detectionconfig handler: no actor on ctx despite session middleware")
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusInternalServerError, errCodeDCInternal, msgDCInternal)
		return nil, false
	}
	return actor, true
}

// writeMutationErr maps a service/store error to the right status: invalid input is a 400, everything else a 500.
func (h *DetectionConfigHandler) writeMutationErr(ctx context.Context, w http.ResponseWriter, op string, err error) {
	if errors.Is(err, detectionconfig.ErrInvalidRequest) {
		writeDetectionConfigErr(ctx, h.logger, w, http.StatusBadRequest, errCodeDCInvalidInput, err.Error())
		return
	}
	h.logger.ErrorContext(ctx, "detectionconfig "+op, "err", err)
	writeDetectionConfigErr(ctx, h.logger, w, http.StatusInternalServerError, errCodeDCInternal, msgDCInternal)
}

func writeDetectionConfigErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code, message string) {
	writeJSON(ctx, logger, w, status, map[string]string{"error": code, "message": message})
}
