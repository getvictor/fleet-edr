package service

import (
	"log/slog"

	"github.com/fleetdm/edr/server/rules/api"
)

// Service is the rules orchestrator. Today it wraps the in-memory rule
// catalog and exposes it as the api.Lister + api.RuleProvider surfaces.
// The application-control subsystem will plug new fields in here as it
// lands; for now the struct holds only the rule slice.
type Service struct {
	rules  []api.Rule
	logger *slog.Logger
}

// New builds a Service. The rule slice may be empty (zero-rule
// deployments are unusual but accepted, e.g. the docs-generator path
// that asks for the catalog without running rules).
func New(rules []api.Rule, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if rules == nil {
		rules = []api.Rule{}
	}
	return &Service{
		rules:  rules,
		logger: logger,
	}
}

// --- api.Lister + api.RuleProvider --------------------------------------------

// List returns RuleMetadata in registration order. Used by the
// operator endpoints (/api/rules, /api/attack-coverage) and the docs
// generator.
func (s *Service) List() []api.RuleMetadata {
	out := make([]api.RuleMetadata, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, api.RuleMetadata{
			ID:         r.ID(),
			Techniques: r.Techniques(),
			Doc:        r.Doc(),
		})
	}
	return out
}

// ActiveRules returns the in-memory rule set, identical to the
// constructor input. Hot-reload is a future extension point.
func (s *Service) ActiveRules() []api.Rule {
	return s.rules
}
