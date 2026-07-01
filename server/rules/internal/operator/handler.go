package operator

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
)

// Service is the narrow surface the operator handlers need. Today satisfied by *rules/internal/service.Service. Kept as an interface
// so the handler tests can substitute a fake without spinning up a DB.
type Service interface {
	api.Lister
}

// Handler serves the rules-context operator routes. Construct it with the rules service handle and the authorization chokepoint;
// mount via RegisterRoutes.
type Handler struct {
	svc    Service
	authz  identityapi.AuthZ
	audit  identityapi.AuditRecorder
	logger *slog.Logger
}

// New builds an operator handler. Panics if svc or authz is nil. Authorization is enforced before each privileged route's side effect;
// a nil authz would bypass the role matrix entirely.
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

// SetAudit installs the operator audit recorder. Optional: today no route under this handler emits audit rows; the setter is retained
// because cmd/main wires it unconditionally and follow-on changes (application control) will plug into it.
func (h *Handler) SetAudit(rec identityapi.AuditRecorder) { h.audit = rec }

// RegisterRoutes wires the operator routes onto the given mux.
func (h *Handler) RegisterRoutes(mux httpserver.Router) {
	mux.HandleFunc("GET /api/rules", h.handleListRules)
	mux.HandleFunc("GET /api/attack-coverage", h.handleATTACKCoverage)
}

// handleListRules returns the structured per-rule documentation for
// every registered detection rule. Used by the UI's rule-detail page
// and the tools/gen-rule-docs markdown generator. Order is the
// engine's registration order so the response is deterministic and
// snapshot-testable.
//
// Stable wire shape: the UI's RuleDetail.tsx and the generator
// both depend on this; field renames here ripple through both. Add
// new fields, don't remove or rename existing ones.
func (h *Handler) handleListRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionAlertRead, identityapi.Resource{Type: "alert"}) {
		return
	}
	type ruleResponse struct {
		ID         string            `json:"id"`
		Techniques []string          `json:"techniques"`
		Doc        api.Documentation `json:"doc"`
		// SupportedExclusionMatchTypes lets the admin UI's exclusion editor offer only the match types the rule actually consults
		// (issue #520). Always a JSON array (never null) so the UI can iterate without a nil guard: a rule that consults no exclusions
		// serializes []. Additive field; the existing consumers (RuleDetail.tsx, gen-rule-docs) ignore it.
		SupportedExclusionMatchTypes []api.ExclusionMatchType `json:"supported_exclusion_match_types"`
	}
	rules := h.svc.List()
	out := make([]ruleResponse, 0, len(rules))
	for _, rm := range rules {
		matchTypes := rm.SupportedExclusionMatchTypes
		if matchTypes == nil {
			matchTypes = []api.ExclusionMatchType{}
		}
		out = append(out, ruleResponse{
			ID:                           rm.ID,
			Techniques:                   rm.Techniques,
			Doc:                          rm.Doc,
			SupportedExclusionMatchTypes: matchTypes,
		})
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, map[string]any{"rules": out})
}

// handleATTACKCoverage returns a MITRE ATT&CK Navigator layer document that enumerates the techniques covered by the registered
// detection rules. The output is dropped directly into https://mitre-attack.github.io/attack-navigator/ to render as a heatmap on the
// matrix. The layer is assembled by api.BuildNavigatorLayer, the same builder tools/gen-attack-layer uses to produce the committed
// docs/attack-navigator-layer.json artifact, so the live endpoint and the checked-in file cannot drift.
func (h *Handler) handleATTACKCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionAlertRead, identityapi.Resource{Type: "alert"}) {
		return
	}
	writeJSON(ctx, h.logger, w, http.StatusOK, api.BuildNavigatorLayer(h.svc.List()))
}

func writeJSON(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, body any) {
	httpserver.NoStoreJSON(ctx, logger, w, status, body)
}
