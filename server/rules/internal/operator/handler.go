package operator

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/fleetdm/edr/server/httpserver"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/catalog"
	"github.com/fleetdm/edr/server/rules/internal/export"
)

// Service is the narrow surface the operator handlers need. Today satisfied by *rules/internal/service.Service. Kept as an interface
// so the handler tests can substitute a fake without spinning up a DB.
type Service interface {
	api.Lister
	// Exportable is what the export route needs: the rule itself alongside its metadata, since a rule's own document is not
	// metadata, and both from one snapshot of the active set so the two cannot describe different generations.
	Exportable(id string) (api.RuleMetadata, api.Rule, bool)
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
	mux.HandleFunc("GET /api/rules/{id}/export", h.handleExportRule)
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
		// Platforms lists the operating systems the rule applies to (ADR-0018). Always a JSON array (never null) so the UI can iterate
		// without a nil guard. Additive field; existing consumers ignore it.
		Platforms []api.Platform `json:"platforms"`
		// DefaultMode is the mode the rule runs in when no setting applies to it (issue #764), always one of alert, monitor or
		// disabled rather than sometimes empty. It is here because the rule-settings surface lists only settings an OPERATOR
		// created, so a rule left at its own default appears nowhere on it: without this, a detection that does not alert is
		// indistinguishable from one that does. This is the rule's default, NOT a resolved per-host mode, which depends on a host.
		// Additive field; existing consumers ignore it.
		DefaultMode api.DetectionRuleMode `json:"default_mode"`
		// Mode is the mode the rule RUNS IN at global scope, and ModeSource says whether a setting or the rule's own declaration
		// produced it. The spec requires a rule an operator has disabled to stay listed here "with its mode indicated"; before
		// these fields the response carried only what the rule declares, which a setting overrides, so a disabled rule was listed
		// looking exactly like a rule that alerts. Global scope because the listing names no host: a per-host mode is a question
		// this response cannot answer. Additive fields; existing consumers ignore them.
		Mode       api.DetectionRuleMode `json:"mode"`
		ModeSource api.RuleModeSource    `json:"mode_source"`
		// Origin credits a vendored rule's upstream project and author, names this project for a rule it wrote, and names the
		// deployment for one the operator wrote themselves. The vendored corpus is under DRL 1.1 and those rules are served
		// unmodified, so attribution travels with the rule itself; this carries it onto the surface an operator actually reads.
		//
		// No omitempty, and the schema marks it required: api.OriginOf never returns "" (issue #765), so omitting on empty could
		// only ever fire if the value were lost in transit, which is exactly the case a consumer wants to see rather than have
		// silently smoothed into an absent field.
		Origin string `json:"origin"`
	}
	rules := h.svc.List()
	out := make([]ruleResponse, 0, len(rules))
	for _, rm := range rules {
		matchTypes := rm.SupportedExclusionMatchTypes
		if matchTypes == nil {
			matchTypes = []api.ExclusionMatchType{}
		}
		platforms := rm.Platforms
		if platforms == nil {
			platforms = []api.Platform{}
		}
		out = append(out, ruleResponse{
			ID:                           rm.ID,
			Techniques:                   rm.Techniques,
			Doc:                          rm.Doc,
			SupportedExclusionMatchTypes: matchTypes,
			Platforms:                    platforms,
			DefaultMode:                  rm.DefaultMode,
			Mode:                         rm.Mode,
			ModeSource:                   rm.ModeSource,
			Origin:                       rm.Origin,
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

// writeOperatorErr writes the two-field operator error envelope ({"error": code, "message": message}) used by every operator mutation
// surface. Centralizes the envelope shape so the per-surface writers (writeAppControlErr, writeDetectionConfigErr) share one copy of
// it; the single-field variant lives in httpserver.WriteJSONError for the identity admin surfaces.
func writeOperatorErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code, message string) {
	writeJSON(ctx, logger, w, status, map[string]string{"error": code, "message": message})
}

// handleExportRule returns one registered detection rendered as a declarative rule file (issue #757).
//
// Served as YAML rather than JSON because the response IS the artifact: an operator saves it, reads it, and eventually hands it
// to another tool. Wrapping it in a JSON envelope would make the caller unwrap it before it was useful.
//
// A non-detection is not exportable and returns 404, the same answer as a rule id that names nothing. That is deliberate: from
// the catalog's point of view they are equally absent, and a distinct status would leak the existence of rules the catalog
// deliberately does not describe (#775).
func (h *Handler) handleExportRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !identityapi.HTTPGate(ctx, w, h.authz, h.logger, identityapi.ActionAlertRead, identityapi.Resource{Type: "alert"}) {
		return
	}
	id := r.PathValue("id")
	// The rule and its metadata come from one snapshot, so the document served and the metadata describing it cannot be from
	// different generations of the rule set (see Service.Exportable).
	rm, rule, ok := h.svc.Exportable(id)
	if !ok {
		writeJSON(ctx, h.logger, w, http.StatusNotFound, map[string]any{"error": "rule_not_found"})
		return
	}

	// A rule that came from a document exports as that document, byte for byte (issue #764). Re-rendering it would hand back a
	// second description of a rule whose authoritative description already exists, and the document is the more useful artifact
	// anyway: for a vendored rule it is what an operator diffs against SigmaHQ, and for one they wrote themselves it is what they
	// wrote.
	//
	// Asked of the rule that is RUNNING, not by looking the id up in the corpus this build embeds. A rule's identity is its file
	// stem (#873), so an operator storing their own version of a shipped detection keeps its id, and the embedded lookup went on
	// answering with the shipped document: bytes the deployment was not running and they had not written (#879).
	// An operator's OWN rule document is rule content, and #767 put reading that behind rule_content.read, which is admin or
	// senior analyst. Until this change the route could only return the product's own content, so alert.read was the whole gate;
	// serving an operator's document under it would hand their rule to an analyst or auditor, who are denied it on the route that
	// exists for rule content. Widening the gate for every rule instead would take export away from those roles for the shipped
	// ones, which they can already read on the catalog.
	//
	// The refusal reveals only that this rule is locally authored, which GET /api/rules already reports to the same roles on every
	// rule's Origin field, so gating this way leaks nothing the catalog does not.
	if api.OriginOf(rule) == api.LocalOrigin && !identityapi.HTTPGate(ctx, w, h.authz, h.logger,
		identityapi.ActionRuleContentRead, identityapi.Resource{Type: "rule_content"}) {
		return
	}

	body, fromDocument := api.SourceOf(rule)
	if !fromDocument {
		rendered, err := export.Rule(rm, catalog.AuthoredFor(rm.ID))
		if err != nil {
			h.logger.ErrorContext(ctx, "render rule file", "rule", id, "err", err)
			writeJSON(ctx, h.logger, w, http.StatusInternalServerError, map[string]any{"error": "export_failed"})
			return
		}
		body = rendered
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.yml"`)
	// A rule document can now be content an operator wrote, so this is the first version of this route whose body is not fixed at
	// build time. Sniffing is what would make that reachable: a browser that ignored the declared type and decided a YAML document
	// looked like HTML would execute whatever it found. The declared type plus the attachment disposition already say what this
	// is; nosniff is what stops a browser overruling them, and apidocs sets it on the same reasoning.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// This URL now answers "what is this deployment running", and the answer changes when rule content is reloaded. A cached copy
	// would keep serving a generation that is no longer running, which is the same wrong answer the fix removed from the server
	// side. The rule-content routes set this for the same reason.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	// G705 flags this because the rule id reaching Exportable comes from the path, so taint analysis marks what it returns. The
	// body is the stored rule document, never the id, and it is served as an attachment of a declared non-HTML type with sniffing
	// off. Escaping it is not an option either: the response IS the artifact, and an escaped YAML document is not one.
	if _, err := w.Write(body); err != nil { //nolint:gosec // G705: see above
		h.logger.WarnContext(ctx, "write rule file", "rule", id, "err", err)
	}
}
