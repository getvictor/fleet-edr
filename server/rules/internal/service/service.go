package service

import (
	"log/slog"
	"sync/atomic"

	"github.com/fleetdm/edr/server/rules/api"
)

// Service is the rules orchestrator. It wraps the in-memory rule catalog and exposes it as the api.Lister + api.RuleProvider
// surfaces, resolving each rule's globally configured mode for the listing. The application-control subsystem will plug new fields
// in here as it lands.
type Service struct {
	// active is the rule set in force, replaced wholesale rather than mutated. Content can be reloaded from storage while the
	// server runs (issue #766), and the readers below are called from concurrent request and evaluation paths, so the set is
	// swapped atomically and every reader takes ONE snapshot of it. Mutating a live set in place is the defect #846 removed from
	// the engine; the same reasoning applies here.
	active atomic.Pointer[ruleSet]
	// modes resolves each rule's globally configured mode for List. Nil is the docs-generator path (CatalogOnly), which has no
	// database and therefore no settings to resolve; every rule then reports its own declared default.
	modes  api.GlobalRuleModeResolver
	logger *slog.Logger
}

// ruleSet is one immutable generation of the rule set, together with the corpus version it was built from.
//
// The version travels WITH the rules rather than in its own field because the two answer one question together: a reader asking
// what is running needs the version that produced it, and two fields swapped separately can disagree for as long as it takes to
// write the second one. Version 0 means the set did not come from stored content (the corpus embedded in the build, or the
// docs-generator path), which is distinguishable from any stored corpus because the store seeds its counter at 0 and every
// replacement bumps it before the documents land.
type ruleSet struct {
	rules   []api.Rule
	version int64
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
	svc := &Service{
		modes:  modes,
		logger: logger,
	}
	svc.Swap(rules, 0)
	return svc
}

// Swap replaces the rule set in force, reporting the number of rules now active.
//
// version is the corpus version the rules were built from, or 0 when they did not come from stored content. The caller's slice is
// copied, so a later mutation of it cannot reach into a set a concurrent List or ActiveRules is already reading.
//
// Callers must treat this as one of THREE places a new rule set has to reach: the exclusion-support map the detection-config
// service validates against, and the detection engine's own derived indices, are both built from the rule set and both go stale
// silently when only this one is updated. rules/bootstrap owns that fan-out.
func (s *Service) Swap(rules []api.Rule, version int64) int {
	next := make([]api.Rule, len(rules))
	copy(next, rules)
	s.active.Store(&ruleSet{rules: next, version: version})
	return len(next)
}

// ActiveVersion returns the corpus version the rule set in force was built from, or 0 when it did not come from stored content.
//
// Its one caller is the refresh gate, which compares it against the stored counter to decide whether the content needs re-reading;
// that comparison is the whole reason the version travels with the rules. It is NOT an operator surface. Reporting the running
// generation to an operator is deferred with the rest of that work, and this returning a number is not the same as answering it.
func (s *Service) ActiveVersion() int64 { return s.active.Load().version }

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
	rules := s.active.Load().rules
	out := make([]api.RuleMetadata, 0, len(rules))
	for _, r := range rules {
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

// ActiveRules returns the rule set in force. Reloaded from stored content while the server runs (issue #766), so a caller holding
// the result holds one generation of it and a later reload does not change what it is looking at.
//
// This deliberately includes non-detections, unlike List: a projection or a health signal is registered, evaluated and persisted
// exactly like any other rule, and only its presence on the operator-facing catalog surfaces differs.
func (s *Service) ActiveRules() []api.Rule {
	return s.active.Load().rules
}
