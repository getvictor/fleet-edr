package service

import (
	"log/slog"

	"github.com/fleetdm/edr/server/rules/api"
)

// Service is the rules orchestrator. Today it wraps the in-memory rule catalog and exposes it as the api.Lister + api.RuleProvider
// surfaces. The application-control subsystem will plug new fields in here as it lands; for now the struct holds only the rule slice.
type Service struct {
	rules []api.Rule
	// modes resolves each rule's globally configured mode for List. Nil is the docs-generator path (CatalogOnly), which has no
	// database and therefore no settings to resolve; every rule then reports its own declared default.
	modes  api.GlobalRuleModeResolver
	logger *slog.Logger
}

// New builds a Service. The rule slice may be empty (zero-rule deployments are unusual but accepted, e.g. the docs-generator path that
// asks for the catalog without running rules).
//
// modes is a constructor parameter rather than a post-construction setter, unlike the optional collaborators on the handlers. A
// forgotten setter here would not fail: List would keep returning every rule's declared default, so GET /api/rules would report
// modes that quietly ignore the operator's own settings. The compiler is a better guard against that than a convention.
func New(rules []api.Rule, modes api.GlobalRuleModeResolver, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if rules == nil {
		rules = []api.Rule{}
	}
	return &Service{
		rules:  rules,
		modes:  modes,
		logger: logger,
	}
}

// --- api.Lister + api.RuleProvider --------------------------------------------

// List returns the DETECTIONS' RuleMetadata in registration order. Used by the operator endpoints (/api/rules,
// /api/attack-coverage) and the docs generator.
//
// Each entry carries both the mode the rule DECLARES and the mode it currently RUNS IN at global scope. The two were the same field
// until settings could override a declaration, and reporting only the declaration left the catalog unable to answer the question the
// spec asks it to: a rule an operator has disabled must stay listed "with its mode indicated", and the mode indicated has to be the
// one in force, not the one the rule was written with.
//
// Registered rules that declare themselves non-detections (api.NonDetection) are omitted. These surfaces describe detections an
// operator reads, tunes and reasons about, and a rule with no detection logic, no tuning surface and no adversary claim misleads
// on each count; in the ATT&CK case it also inflates a coverage figure read during procurement. The omission is confined to this
// method: ActiveRules below still returns every registered rule, so evaluation and alert persistence are unchanged.
func (s *Service) List() []api.RuleMetadata {
	out := make([]api.RuleMetadata, 0, len(s.rules))
	for _, r := range s.rules {
		if !api.IsDetection(r) {
			continue
		}
		declared := api.DefaultModeOf(r)
		global := api.GlobalRuleModeOf(s.modes, r.ID(), declared)
		out = append(out, api.RuleMetadata{
			ID:                           r.ID(),
			Techniques:                   r.Techniques(),
			Doc:                          r.Doc(),
			SupportedExclusionMatchTypes: r.SupportedExclusionMatchTypes(),
			Platforms:                    r.Platforms(),
			Algorithm:                    api.AlgorithmNameOf(r),
			DefaultMode:                  declared,
			Mode:                         global.Mode,
			ModeSource:                   global.Source,
			Origin:                       api.OriginOf(r),
		})
	}
	return out
}

// ActiveRules returns the in-memory rule set, identical to the constructor input. Hot-reload is a future extension point.
//
// This deliberately includes non-detections, unlike List: a projection or a health signal is registered, evaluated and persisted
// exactly like any other rule, and only its presence on the operator-facing catalog surfaces differs.
func (s *Service) ActiveRules() []api.Rule {
	return s.rules
}
