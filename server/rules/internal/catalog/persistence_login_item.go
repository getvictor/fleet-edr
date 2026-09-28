package catalog

import (
	"context"
	"fmt"

	"github.com/fleetdm/edr/server/rules/api"
)

// PersistenceLoginItem fires when an app registers a login item with Background Task Management whose helper is not an Apple
// platform binary, not MDM-managed, and not excluded: persistence that starts at every login (T1547.015). It shares its gate with
// the LaunchAgent and LaunchDaemon rules (untrustedRegistration).
//
// A login item is a helper app bundle inside the registering app (Contents/Library/LoginItems/), registered through SMAppService.
// BTM reports no executable for it, so the agent signs the helper bundle itself and resolves the item's path against the app
// (issue #1167). A registration from an agent that predates that has no signature and a relative path, and is skipped.
type PersistenceLoginItem struct {
	// Exclusions is the per-host false-positive resolver, consulted for the helper's signature and its bundle path. Nil excludes
	// nothing.
	Exclusions api.ExclusionResolver
}

func (r *PersistenceLoginItem) ID() string { return "persistence_login_item" }

// AlgorithmName names the evaluator that decides this rule, for the exported rule file. The same verdict as the launchd rules'.
func (r *PersistenceLoginItem) AlgorithmName() string { return "btm_item_signing_verdict" }

// SupportedExclusionMatchTypes lists what an operator can waive a registration by: the helper's team or team-qualified signing
// identifier, which a planted helper cannot claim, or the helper bundle's path.
func (r *PersistenceLoginItem) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{api.ExclusionMatchTeamID, api.ExclusionMatchSigningID, api.ExclusionMatchPathGlob}
}

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *PersistenceLoginItem) DisplayName() string { return "Login item persistence" }

// Techniques returns T1547.015 (Boot or Logon Autostart Execution: Login Items).
func (r *PersistenceLoginItem) Techniques() []string { return []string{"T1547.015"} }

// Doc surfaces the operator-facing description in /api/rules and the generated docs/detection-rules.md.
func (r *PersistenceLoginItem) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags a login item whose helper is not an Apple platform binary, not MDM-managed, and not excluded.",
		Description: "Detects login-item persistence on macOS (T1547.015): an app registering a helper with Background Task " +
			"Management, which launches it at every login.\n\n" +
			"The decision keys on the HELPER's code signature, not on the app that registered it. A helper that is an Apple " +
			"platform binary or that MDM manages is skipped; an ad-hoc, unsigned or unknown-vendor helper fires. Paired with " +
			"`persistence_launchagent` and `privilege_launchd_plist_write` for launchd items.",
		Severity:   api.SeverityMedium,
		EventTypes: []string{"btm_launch_item_add"},
		FalsePositives: []string{
			"Apps that start a helper at login (a menu-bar utility, a sync client, an updater). Exclude a vendor by `team_id`, or by " +
				"`signing_id` for one of its helpers rather than all of them. Either survives upgrades and cannot be claimed by a " +
				"planted helper.",
			"An in-house or unsigned app. Prefer signing it; failing that, a path-glob exclusion on its helper's bundle, with an " +
				"expiry, since anyone who can write that path inherits the exclusion.",
		},
		Limitations: []string{
			"Covers login items an app registers through SMAppService. A login item added in System Settings, or by a script " +
				"through System Events, is a different kind of registration and is not judged.",
			"A registration whose helper's code signature cannot be read (absent or unreadable when registered) is skipped to " +
				"stay high-precision.",
		},
	}
}

func (r *PersistenceLoginItem) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return evalEachEvent(ctx, events, s, r.evalEvent)
}

// evalEvent ignores ctx and the graph: like the launchd rules, the decision rides the payload alone and the alert is
// process-optional, since the helper has no live process at registration and the instigator is Apple's smd.
func (r *PersistenceLoginItem) evalEvent(_ context.Context, evt api.Event, _ api.GraphReader) (*api.Finding, error) {
	p, ok := untrustedRegistration(evt, "login_item")
	if !ok {
		return nil, nil
	}
	helper := btmItemPath(p.ItemPath)
	if r.Exclusions != nil && (signatureExcluded(r.Exclusions, r.ID(), *p.ExecutableCodeSigning, evt.HostID) ||
		r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, helper, evt.HostID)) {
		return nil, nil
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityMedium,
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("Untrusted helper %s registered as a login item", helper),
		Subject:     btmItemSubject("loginitem", helper),
		EventIDs:    []string{evt.EventID},
	}, nil
}
