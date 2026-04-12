package detection

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/fleetdm/edr/server/store"
)

// Engine manages a set of rules and evaluates them against event batches.
type Engine struct {
	rules  []Rule
	store  *store.Store
	logger *slog.Logger
}

// NewEngine creates a detection engine backed by the given store.
func NewEngine(s *store.Store, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{store: s, logger: logger}
}

// Register adds a detection rule to the engine.
func (e *Engine) Register(r Rule) {
	e.rules = append(e.rules, r)
}

// Evaluate runs all registered rules against the event batch.
// Findings are persisted as alerts. Rule evaluation failures are logged and skipped,
// but alert persistence failures are returned so the caller can retry the batch.
func (e *Engine) Evaluate(ctx context.Context, events []store.Event) error {
	for _, rule := range e.rules {
		findings, err := rule.Evaluate(ctx, events, e.store)
		if err != nil {
			e.logger.WarnContext(ctx, "detection rule evaluation failed", "rule", rule.ID(), "err", err)
			continue
		}

		for _, f := range findings {
			_, created, err := e.store.InsertAlert(ctx, store.Alert{
				HostID:      f.HostID,
				RuleID:      f.RuleID,
				Severity:    f.Severity,
				Title:       f.Title,
				Description: f.Description,
				ProcessID:   f.ProcessID,
			}, f.EventIDs)
			if err != nil {
				return fmt.Errorf("persist detection alert for rule %s on host %s: %w", f.RuleID, f.HostID, err)
			}
			if created {
				e.logger.InfoContext(ctx, "detection alert created",
					"rule", f.RuleID, "host", f.HostID, "severity", f.Severity, "title", f.Title)
			}
		}
	}
	return nil
}
