package catalog

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fleetdm/edr/server/rules/api"
)

// TccSensitiveGrant fires when an app that is not Apple's is granted a TCC permission that lets it read or control the whole Mac:
// Full Disk Access, Accessibility, Screen Recording, Input Monitoring, or posting input events (T1548.006). Infostealers and
// remote-access tools need these to work, and getting one granted, usually by talking the user into it, is an early and telling
// step.
//
// It reads `tcc_modify` events (issue #1185), with the granted app's code signature the agent attaches from its bundle on disk. A
// grant made by an MDM configuration profile is the managed way to deploy these permissions and is skipped, as is one to an app
// whose signature could not be read.
type TccSensitiveGrant struct {
	// Exclusions is the per-host false-positive resolver, consulted for the granted app's team, team-qualified signing identifier
	// and path. Nil excludes nothing.
	Exclusions api.ExclusionResolver
}

// tccSensitiveServices names each permission the rule judges, as tccd spells the service without its kTCCService prefix, with the
// words System Settings uses for it.
var tccSensitiveServices = map[string]string{
	"SystemPolicyAllFiles": "Full Disk Access",
	"Accessibility":        "Accessibility",
	"ScreenCapture":        "Screen Recording",
	"ListenEvent":          "Input Monitoring",
	"PostEvent":            "control of input events",
}

// tccModifyPayload mirrors the tcc_modify payload the rule reads (schema/events.json), including the fields the agent adds.
type tccModifyPayload struct {
	Service             string           `json:"service"`
	Identity            string           `json:"identity"`
	IdentityType        string           `json:"identity_type"`
	UpdateType          string           `json:"update_type"`
	Right               string           `json:"right"`
	Reason              string           `json:"reason"`
	IdentityPath        string           `json:"identity_path,omitempty"`
	IdentityCodeSigning *codeSigningJSON `json:"identity_code_signing,omitempty"`
}

func (r *TccSensitiveGrant) ID() string { return "tcc_sensitive_grant" }

// AlgorithmName names the evaluator that decides this rule, for the exported rule file.
func (r *TccSensitiveGrant) AlgorithmName() string { return "tcc_grant_signing_verdict" }

// SupportedExclusionMatchTypes lists what an operator can waive a grant by: the app's team or team-qualified signing identifier,
// which another app cannot claim, or its path.
func (r *TccSensitiveGrant) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{api.ExclusionMatchTeamID, api.ExclusionMatchSigningID, api.ExclusionMatchPathGlob}
}

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *TccSensitiveGrant) DisplayName() string { return "Sensitive permission granted" }

// Techniques returns T1548.006 (Abuse Elevation Control Mechanism: TCC Manipulation).
func (r *TccSensitiveGrant) Techniques() []string { return []string{"T1548.006"} }

// Doc surfaces the operator-facing description in /api/rules and the generated docs/detection-rules.md.
func (r *TccSensitiveGrant) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags an app that is not Apple's being granted Full Disk Access, Accessibility, Screen Recording or Input Monitoring.",
		Description: "Detects abuse of macOS privacy permissions (T1548.006). Full Disk Access, Accessibility, Screen Recording, " +
			"Input Monitoring and the right to post input events let an app read every file, control other apps, watch the " +
			"screen or log keystrokes. Infostealers and remote-access tools need one to work, and a user talked into granting " +
			"it is the usual way they get it.\n\n" +
			"Fires when one of these permissions is granted to an app that is not an Apple platform binary, whether through a " +
			"prompt or System Settings. A grant made by an MDM configuration profile is the managed way to deploy these " +
			"permissions and is not reported.",
		Severity:   api.SeverityMedium,
		EventTypes: []string{"tcc_modify"},
		FalsePositives: []string{
			"Legitimate tools that need these permissions: backup and security software (Full Disk Access), window managers and " +
				"automation tools (Accessibility), screen sharing and recording (Screen Recording). Exclude a vendor by `team_id`, " +
				"or deploy the permission through an MDM configuration profile, which is not reported.",
		},
		Limitations: []string{
			"A grant to an app whose code signature cannot be read when the grant is made is not reported.",
			"A permission granted by writing the TCC database directly, bypassing tccd, raises no TCC event and is not reported.",
		},
	}
}

func (r *TccSensitiveGrant) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return evalEachEvent(ctx, events, s, r.evalEvent)
}

// evalEvent ignores ctx and the graph: the decision rides the payload alone, and the finding is process-less, since the process
// that recorded the grant is Apple's own and the app granted it is not necessarily running.
func (r *TccSensitiveGrant) evalEvent(_ context.Context, evt api.Event, _ api.GraphReader) (*api.Finding, error) {
	if evt.EventType != "tcc_modify" {
		return nil, nil
	}
	var p tccModifyPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return nil, nil
	}
	permission, sensitive := tccSensitiveServices[p.Service]
	granted := p.Right == "allowed" && (p.UpdateType == "create" || p.UpdateType == "modify")
	if !sensitive || !granted || p.Reason == "mdm_policy" || p.IdentityCodeSigning == nil || p.IdentityCodeSigning.IsPlatformBinary {
		return nil, nil
	}
	if r.Exclusions != nil && (signatureExcluded(r.Exclusions, r.ID(), *p.IdentityCodeSigning, evt.HostID) ||
		(p.IdentityPath != "" && r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, p.IdentityPath, evt.HostID))) {
		return nil, nil
	}
	app := p.Identity
	if p.IdentityPath != "" && p.IdentityPath != p.Identity {
		app = fmt.Sprintf("%s (%s)", p.Identity, p.IdentityPath)
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityMedium,
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("%s was granted %s: TCC permission abuse (MITRE T1548.006)", app, permission),
		// Process-less: one alert per app and permission, so a grant toggled off and on again does not repeat.
		Subject:  pathSubject("tccgrant", p.Service+":"+p.Identity),
		EventIDs: []string{evt.EventID},
	}, nil
}
