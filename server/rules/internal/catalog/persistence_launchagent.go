package catalog

import (
	"context"
	"fmt"

	"github.com/fleetdm/edr/server/rules/api"
)

// PersistenceLaunchAgent fires when a LaunchAgent is registered with Background Task Management (BTM) whose REGISTERED EXECUTABLE is
// not an Apple platform binary, not MDM-managed, and not excluded: user-domain persistence (T1543.001). It is the agent-domain twin
// of privilege_launchd_plist_write and shares its gate (untrustedRegistration).
//
// It used to match `launchctl load` on the command line, which could only decide on the plist path string and so could only offer a
// path exclusion, the weakest kind: an attacker who knows an excluded path drops a file there. It also never saw a plist that
// becomes active without launchctl, at the next login. BTM sees every registration and carries the executable's signature, which
// is what an operator can trust (issue #1156).
type PersistenceLaunchAgent struct {
	// Exclusions is the per-host false-positive resolver, consulted for the registered executable's signature and for the plist's
	// path. Nil excludes nothing.
	Exclusions api.ExclusionResolver
}

func (r *PersistenceLaunchAgent) ID() string { return "persistence_launchagent" }

// AlgorithmName names the evaluator that decides this rule, for the exported rule file. The same verdict as the daemon rule's.
func (r *PersistenceLaunchAgent) AlgorithmName() string { return "btm_item_signing_verdict" }

// SupportedExclusionMatchTypes lists what an operator can waive a registration by. team_id and signing_id name the registered
// executable, which a planted binary cannot claim. path_glob names the plist and is kept so exclusions saved when the rule matched on
// the launchctl command line keep their meaning: that path was the plist's then, and is the plist's now.
func (r *PersistenceLaunchAgent) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{api.ExclusionMatchTeamID, api.ExclusionMatchSigningID, api.ExclusionMatchPathGlob}
}

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *PersistenceLaunchAgent) DisplayName() string { return "LaunchAgent persistence" }

// Techniques returns T1543.001 (Create or Modify System Process: Launch Agent).
func (r *PersistenceLaunchAgent) Techniques() []string { return []string{"T1543.001"} }

// Doc surfaces the operator-facing description in /api/rules and the generated docs/detection-rules.md.
func (r *PersistenceLaunchAgent) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags a LaunchAgent whose registered executable is not an Apple platform binary, not MDM-managed, and not excluded.",
		Description: "Detects user-domain persistence on macOS (T1543.001): a LaunchAgent registered with Background Task " +
			"Management, which runs its program at every login.\n\n" +
			"Keyed on the registration rather than on `launchctl`, so a plist that becomes active at the next login without " +
			"anyone running `launchctl` is caught, as is one loaded by any other means.\n\n" +
			"The decision keys on the REGISTERED EXECUTABLE's code signature, not on who registered it. An agent whose program " +
			"is an Apple platform binary or that MDM manages is skipped; an ad-hoc, unsigned or unknown-vendor program fires. " +
			"Paired with `privilege_launchd_plist_write` for LaunchDaemons.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"btm_launch_item_add"},
		FalsePositives: []string{
			"Vendor software that installs its own LaunchAgent (an updater, a sync client, a security tool). Exclude it by `team_id`, " +
				"or by `signing_id` for one of a vendor's programs rather than all of them. Either survives upgrades and cannot be " +
				"claimed by a planted binary.",
			"An in-house or unsigned tool. Prefer signing it; failing that, a path-glob exclusion on its plist, with an expiry, " +
				"since anyone who can write that path inherits the exclusion.",
		},
		Limitations: []string{
			"Registration is reported when launchd learns of the item, not when the plist is written. A plist written and never " +
				"loaded surfaces at the next login.",
			"A registration whose program's code signature cannot be read (absent or unreadable when registered) is skipped to " +
				"stay high-precision.",
		},
	}
}

func (r *PersistenceLaunchAgent) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return evalEachEvent(ctx, events, s, r.evalEvent)
}

// evalEvent ignores ctx and the graph: like the daemon rule, the decision rides the payload alone and the alert is process-optional,
// since the registered program has no live process at registration and the instigator is not the attacker.
func (r *PersistenceLaunchAgent) evalEvent(_ context.Context, evt api.Event, _ api.GraphReader) (*api.Finding, error) {
	p, ok := untrustedRegistration(evt, "agent")
	if !ok {
		return nil, nil
	}
	plist := btmItemPath(p.ItemPath)
	if r.Exclusions != nil && (signatureExcluded(r.Exclusions, r.ID(), *p.ExecutableCodeSigning, evt.HostID) ||
		r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, plist, evt.HostID)) {
		return nil, nil
	}
	executable := p.ExecutablePath
	if executable == "" {
		executable = "(unknown executable)"
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("Untrusted executable %s registered as LaunchAgent %s", executable, plist),
		Subject:     btmItemSubject("launchagent", plist),
		EventIDs:    []string{evt.EventID},
	}, nil
}
