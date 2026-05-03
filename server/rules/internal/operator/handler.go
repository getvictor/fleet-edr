package operator

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
)

// Service is the narrow surface the operator handlers need. Today
// satisfied by *rules/internal/service.Service plus a Fanout method
// that lives only on the concrete service. Kept as an interface so
// the handler tests can substitute a fake without spinning up a DB.
type Service interface {
	api.PolicyService
	api.Lister
	Fanout(ctx context.Context, p api.BlocklistPolicy) (totalHosts, failedHosts int, err error)
}

// Handler serves the rules-context operator routes. Construct it with
// the rules service handle; mount via RegisterRoutes.
type Handler struct {
	svc    Service
	audit  identityapi.AuditRecorder
	logger *slog.Logger
}

// New builds an operator handler. Panics if svc is nil.
func New(svc Service, logger *slog.Logger) *Handler {
	if svc == nil {
		panic("rules operator.New: Service must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{svc: svc, logger: logger}
}

// SetAudit installs the operator audit recorder. Optional: when not
// set, policy updates still apply but no audit row is written.
func (h *Handler) SetAudit(rec identityapi.AuditRecorder) { h.audit = rec }

// RegisterRoutes wires the four operator routes onto the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/policy", h.handleGetPolicy)
	mux.HandleFunc("PUT /api/policy", h.handlePutPolicy)
	mux.HandleFunc("GET /api/rules", h.handleListRules)
	mux.HandleFunc("GET /api/attack-coverage", h.handleATTACKCoverage)
}

// putPolicyRequest is the body shape accepted by PUT /api/policy.
// Actor + Reason are required for audit. Paths + Hashes are optional
// individually but the effective blocklist must be one of those two
// forms; a completely empty PUT is still accepted so operators have a
// fast "clear everything" path.
type putPolicyRequest struct {
	Paths  []string `json:"paths"`
	Hashes []string `json:"hashes"`
	Actor  string   `json:"actor"`
	Reason string   `json:"reason"`
}

// putPolicyBodyCap caps the JSON body size for PUT /api/policy. 64 KiB
// is generous for a blocklist; multi-MB pushes are a public DoS
// vector even on a session-gated route.
const putPolicyBodyCap = 64 << 10

func (h *Handler) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := h.svc.Get(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "rules get policy", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, p)
}

// handlePutPolicy is the end-to-end policy push: upsert the policy
// row, then fan out a set_blocklist command to every active host. A
// non-zero fan-out failure count logs a warning but still reports
// 200 -- the policy row is authoritative; the fan-out is best-effort
// and the next enroll/admin-push catches up.
func (h *Handler) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body putPolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, putPolicyBodyCap)).Decode(&body); err != nil {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "bad_body")
		return
	}
	if strings.TrimSpace(body.Actor) == "" || strings.TrimSpace(body.Reason) == "" {
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "actor_reason_required")
		return
	}

	p, err := h.svc.Update(ctx, api.UpdateRequest{
		Name:   api.DefaultPolicyName,
		Paths:  body.Paths,
		Hashes: body.Hashes,
		Actor:  body.Actor,
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "rules put policy", "err", err)
		// Validation errors map to 400; everything else stays 500.
		if api.IsValidationError(err) {
			writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_blocklist")
			return
		}
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	fanoutHosts, fanoutFailed, fanoutErr := h.svc.Fanout(ctx, p)
	fanoutErrText := ""
	if fanoutErr != nil {
		// Listing hosts failed AFTER the policy update committed. The row
		// is authoritative; the fan-out is best-effort. Log loud + carry
		// on so the operator's PUT still returns 200 with the new row.
		// Capture the error string so the audit log distinguishes "0
		// failures because we never got to fan out" from "0 failures
		// because the host list was empty".
		fanoutErrText = fanoutErr.Error()
		h.logger.ErrorContext(ctx, "rules put policy fan-out", "err", fanoutErr)
	}

	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String(attrkeys.AdminAction, "policy_update"),
		attribute.String(attrkeys.AdminActor, body.Actor),
		attribute.Int64("edr.policy.version", p.Version),
		attribute.Int("edr.policy.path_count", len(p.Blocklist.Paths)),
		attribute.Int("edr.policy.hash_count", len(p.Blocklist.Hashes)),
		attribute.Int("edr.policy.fanout_hosts", fanoutHosts),
		attribute.Int("edr.policy.fanout_failed", fanoutFailed),
	)
	// WARN on partial fan-out OR a fatal pre-loop error so SOC dashboards
	// can tell a healthy push apart from one that didn't reach all hosts.
	logFn := h.logger.InfoContext
	if fanoutFailed > 0 || fanoutErr != nil {
		logFn = h.logger.WarnContext
	}
	logArgs := []any{
		attrkeys.AdminAction, "policy_update",
		attrkeys.AdminActor, body.Actor,
		attrkeys.AdminReason, body.Reason,
		"edr.policy.version", p.Version,
		"edr.policy.path_count", len(p.Blocklist.Paths),
		"edr.policy.hash_count", len(p.Blocklist.Hashes),
		"edr.policy.fanout_hosts", fanoutHosts,
		"edr.policy.fanout_failed", fanoutFailed,
	}
	if fanoutErrText != "" {
		logArgs = append(logArgs, "edr.policy.fanout_error", fanoutErrText)
	}
	logFn(ctx, "rules policy updated", logArgs...)

	h.recordPolicyAudit(r, body, p.Version, fanoutHosts, fanoutFailed, fanoutErrText)
	writeJSON(ctx, h.logger, w, http.StatusOK, p)
}

// recordPolicyAudit emits one audit row for the just-committed policy
// update. The body.Actor + body.Reason go in the payload because they
// carry operator-supplied attribution that the session userID alone
// does not (an operator may be running an automation script that
// signs the change with a different label). Soft-fail on audit error.
func (h *Handler) recordPolicyAudit(r *http.Request, body putPolicyRequest, version int64, fanoutHosts, fanoutFailed int, fanoutErrText string) {
	if h.audit == nil {
		return
	}
	ctx := r.Context()
	uid, _ := identityapi.UserIDFromContext(ctx)
	var userID *int64
	if uid > 0 {
		u := uid
		userID = &u
	}
	payload := map[string]any{
		"version":       version,
		"path_count":    len(body.Paths),
		"hash_count":    len(body.Hashes),
		"actor":         body.Actor,
		"reason":        body.Reason,
		"fanout_hosts":  fanoutHosts,
		"fanout_failed": fanoutFailed,
	}
	if fanoutErrText != "" {
		payload["fanout_error"] = fanoutErrText
	}
	if err := h.audit.Record(ctx, identityapi.AuditEvent{
		UserID:     userID,
		Action:     identityapi.AuditPolicyUpdate,
		TargetType: "policy",
		TargetID:   api.DefaultPolicyName,
		RemoteAddr: httpserver.ClientIP(r),
		Payload:    payload,
	}); err != nil {
		h.logger.WarnContext(ctx, "audit record",
			"err", err, "action", string(identityapi.AuditPolicyUpdate),
		)
	}
}

// handleListRules returns the structured per-rule documentation for
// every registered detection rule. Used by the UI's rule-detail page
// and the tools/gen-rule-docs markdown generator. Order is the
// engine's registration order so the response is deterministic and
// snapshot-testable.
//
// Stable wire shape -- the UI's RuleDetail.tsx and the generator
// both depend on this; field renames here ripple through both. Add
// new fields, don't remove or rename existing ones.
func (h *Handler) handleListRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	type ruleResponse struct {
		ID         string            `json:"id"`
		Techniques []string          `json:"techniques"`
		Doc        api.Documentation `json:"doc"`
	}
	rules := h.svc.List()
	out := make([]ruleResponse, 0, len(rules))
	for _, rm := range rules {
		out = append(out, ruleResponse{
			ID:         rm.ID,
			Techniques: rm.Techniques,
			Doc:        rm.Doc,
		})
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, map[string]any{"rules": out})
}

// handleATTACKCoverage returns a MITRE ATT&CK Navigator layer document
// that enumerates the techniques covered by the registered detection
// rules. The output is dropped directly into
// https://mitre-attack.github.io/attack-navigator/ to render as a
// heatmap on the matrix. Score is 1 for "any rule covers it"; the
// list of covering rule IDs is in the technique's `comment`.
func (h *Handler) handleATTACKCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rules := h.svc.List()

	// technique -> rule IDs that cover it.
	coverage := make(map[string][]string)
	for _, rule := range rules {
		for _, t := range rule.Techniques {
			coverage[t] = append(coverage[t], rule.ID)
		}
	}

	type navigatorTechnique struct {
		TechniqueID string `json:"techniqueID"`
		Score       int    `json:"score"`
		Color       string `json:"color,omitempty"`
		Comment     string `json:"comment,omitempty"`
	}
	type navigatorLayer struct {
		Name        string               `json:"name"`
		Versions    map[string]string    `json:"versions"`
		Domain      string               `json:"domain"`
		Description string               `json:"description"`
		Techniques  []navigatorTechnique `json:"techniques"`
	}

	// Emit techniques + per-technique rule lists in sorted order so the
	// JSON is byte-identical across requests. This makes the endpoint
	// safe to ETag, diff, and snapshot-test. Dedup rule IDs so a rule
	// declaring the same technique twice doesn't produce a noisy
	// "Covered by: X, X" comment.
	techniqueIDs := make([]string, 0, len(coverage))
	for tid := range coverage {
		techniqueIDs = append(techniqueIDs, tid)
	}
	slices.Sort(techniqueIDs)

	techniques := make([]navigatorTechnique, 0, len(techniqueIDs))
	for _, tid := range techniqueIDs {
		ruleIDs := slices.Clone(coverage[tid])
		slices.Sort(ruleIDs)
		ruleIDs = slices.Compact(ruleIDs)
		techniques = append(techniques, navigatorTechnique{
			TechniqueID: tid,
			Score:       1,
			Color:       "#31a354",
			Comment:     "Covered by: " + strings.Join(ruleIDs, ", "),
		})
	}

	layer := navigatorLayer{
		Name:        "Fleet EDR coverage",
		Versions:    map[string]string{"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
		Domain:      "enterprise-attack",
		Description: "MITRE ATT&CK techniques covered by currently-registered Fleet EDR detection rules.",
		Techniques:  techniques,
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, layer)
}

func writeJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	httpserver.NoStoreJSON(ctx, logger, w, status, body)
}

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
