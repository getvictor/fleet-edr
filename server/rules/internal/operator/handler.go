package operator

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
)

// Service is the narrow surface the operator handlers need. Today
// satisfied by *rules/internal/service.Service. Kept as an interface
// so the handler tests can substitute a fake without spinning up a DB.
type Service interface {
	api.Lister
}

// Handler serves the rules-context operator routes. Construct it with
// the rules service handle and the authorization chokepoint; mount
// via RegisterRoutes.
type Handler struct {
	svc    Service
	authz  identityapi.AuthZ
	audit  identityapi.AuditRecorder
	logger *slog.Logger
}

// New builds an operator handler. Panics if svc or authz is nil.
// Authorization is enforced before each privileged route's side
// effect; a nil authz would bypass the role matrix entirely.
func New(svc Service, authz identityapi.AuthZ, logger *slog.Logger) *Handler {
	if svc == nil {
		panic("rules operator.New: Service must not be nil")
	}
	if authz == nil {
		panic("rules operator.New: authz must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{svc: svc, authz: authz, logger: logger}
}

// SetAudit installs the operator audit recorder. Optional: today no
// route under this handler emits audit rows; the setter is retained
// because cmd/main wires it unconditionally and follow-on changes
// (application control) will plug into it.
func (h *Handler) SetAudit(rec identityapi.AuditRecorder) { h.audit = rec }

// RegisterRoutes wires the operator routes onto the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/rules", h.handleListRules)
	mux.HandleFunc("GET /api/attack-coverage", h.handleATTACKCoverage)
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
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionAlertRead, identityapi.Resource{TenantID: identityapi.ActorTenantID(ctx), Type: "alert"}) {
		return
	}
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
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionAlertRead, identityapi.Resource{TenantID: identityapi.ActorTenantID(ctx), Type: "alert"}) {
		return
	}
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
