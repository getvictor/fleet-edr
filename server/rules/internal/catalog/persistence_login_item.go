package catalog

import (
	"context"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/rules/api"
)

// PersistenceLoginItem fires when Background Task Management registers a login item whose app is not an Apple platform binary,
// not MDM-managed, and not excluded: persistence that starts at every login (T1547.015). It shares its gate with the LaunchAgent
// and LaunchDaemon rules (untrustedRegistration).
//
// BTM reports two shapes, both captured on a VM (issue #1167). A login_item is a helper app bundle inside the registering app
// (Contents/Library/LoginItems/), registered through SMAppService. An app is the app itself, added to the user's login items by
// SMAppService or through the legacy login-items list. BTM reports no executable for either, so the agent signs the bundle the item
// names, and resolves a helper's path against its app. A registration from an agent that predates that has no signature, and is
// skipped.
type PersistenceLoginItem struct {
	// Exclusions is the per-host false-positive resolver, consulted for the app's signature and its bundle path. Nil excludes
	// nothing.
	Exclusions api.ExclusionResolver
}

func (r *PersistenceLoginItem) ID() string { return "persistence_login_item" }

// AlgorithmName names the evaluator that decides this rule, for the exported rule file. The same verdict as the launchd rules'.
func (r *PersistenceLoginItem) AlgorithmName() string { return "btm_item_signing_verdict" }

// SupportedExclusionMatchTypes lists what an operator can waive a registration by: the app's team or team-qualified signing
// identifier, which a planted app cannot claim, or its bundle's path.
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
		Summary: "Flags a login item whose app is not an Apple platform binary, not MDM-managed, and not excluded.",
		Description: "Detects login-item persistence on macOS (T1547.015): an app that Background Task Management launches at " +
			"every login. That is either a helper an app registers from inside its own bundle, or an app added to the user's " +
			"login items, by itself or through the legacy login-items list.\n\n" +
			"The decision keys on the code signature of the app that will launch, not on the process that registered it. One " +
			"that is an Apple platform binary or that MDM manages is skipped; an ad-hoc, unsigned or unknown-vendor app fires. " +
			"Paired with `persistence_launchagent` and `privilege_launchd_plist_write` for launchd items.",
		Severity:   api.SeverityMedium,
		EventTypes: []string{"btm_launch_item_add"},
		FalsePositives: []string{
			"Apps that start at login, or start a helper at login (a menu-bar utility, a sync client, an updater). Exclude a vendor " +
				"by `team_id`, or by `signing_id` for one of its apps rather than all of them. Either survives upgrades and cannot " +
				"be claimed by a planted app.",
			"An in-house or unsigned app. Prefer signing it; failing that, a path-glob exclusion on its bundle, with an expiry, " +
				"since anyone who can write that path inherits the exclusion.",
		},
		Limitations: []string{
			"A registration BTM reports as a user item is not judged. No route to adding a login item that was tested produces " +
				"one.",
			"A registration whose app's code signature cannot be read (absent or unreadable when registered) is skipped to stay " +
				"high-precision.",
		},
	}
}

func (r *PersistenceLoginItem) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return evalEachEvent(ctx, events, s, r.evalEvent)
}

// evalEvent ignores ctx and the graph: like the launchd rules, the decision rides the payload alone and the alert is
// process-optional, since the app has no live process at registration and the instigator is not the attacker.
func (r *PersistenceLoginItem) evalEvent(_ context.Context, evt api.Event, _ api.GraphReader) (*api.Finding, error) {
	p, ok := untrustedRegistration(evt, "login_item", "app")
	if !ok {
		return nil, nil
	}
	app := strings.TrimSuffix(btmItemPath(p.ItemPath), "/")
	if r.Exclusions != nil && (signatureExcluded(r.Exclusions, r.ID(), *p.ExecutableCodeSigning, evt.HostID) ||
		r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, app, evt.HostID)) {
		return nil, nil
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityMedium,
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("Untrusted app %s registered as a login item", app),
		Subject:     btmItemSubject("loginitem", app),
		EventIDs:    []string{evt.EventID},
	}, nil
}
