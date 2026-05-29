package catalog

import (
	"context"

	"github.com/fleetdm/edr/server/rules/api"
)

// evalEachEvent runs a per-event evaluator over a batch and collects the non-nil findings. Shared by rules whose
// Evaluate is a plain per-event fan-out (privilege_launchd_plist_write, sudoers_tamper, ...) so the identical loop
// lives in one place instead of being copy-pasted per rule.
func evalEachEvent(
	ctx context.Context,
	events []api.Event,
	s api.GraphReader,
	eval func(context.Context, api.Event, api.GraphReader) (*api.Finding, error),
) ([]api.Finding, error) {
	var findings []api.Finding
	for _, evt := range events {
		f, err := eval(ctx, evt, s)
		if err != nil {
			return nil, err
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}
