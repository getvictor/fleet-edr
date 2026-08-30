package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
)

// PersistenceLaunchAgent fires when a process calls `launchctl load` or
// `launchctl bootstrap` referencing a plist under `~/Library/LaunchAgents/` or
// `/Library/LaunchAgents/`, the canonical macOS persistence mechanism. Operators can
// silence expected plists with a path-glob exclusion via the detection-config surface.
//
// MITRE ATT&CK: T1543.001 (Create or Modify System Process: Launch Agent)
type PersistenceLaunchAgent struct {
	// Exclusions is the per-host false-positive resolver. The rule skips a finding whose target plist path matches an exclusion
	// (match type path_glob). Nil excludes nothing (the empty-config default).
	Exclusions api.ExclusionResolver
}

func (r *PersistenceLaunchAgent) ID() string { return "persistence_launchagent" }

// SupportedExclusionMatchTypes lists the match types this rule consults: the LaunchAgent plist writer path glob (issue #520).
func (r *PersistenceLaunchAgent) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{api.ExclusionMatchPathGlob}
}

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *PersistenceLaunchAgent) DisplayName() string { return "LaunchAgent persistence" }

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1543.001 (Create or Modify System Process → Launch Agent). The rule
// fires on `launchctl load` of user LaunchAgent plists, which is exactly this sub-technique's scope.
func (r *PersistenceLaunchAgent) Techniques() []string { return []string{"T1543.001"} }

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *PersistenceLaunchAgent) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags `launchctl load` / `launchctl bootstrap` of a plist under ~/Library/LaunchAgents or /Library/LaunchAgents.",
		Description: "Detects the canonical user-domain persistence step on macOS: an attacker drops a plist into a " +
			"LaunchAgents directory and then activates it via `launchctl load <plist>` or `launchctl bootstrap " +
			"gui/<uid> <plist>`. We catch the activation rather than the file write so the alert ties to the moment " +
			"the persistence becomes effective.\n\n" +
			"Argument parsing handles launch-domain specifiers (`gui/501`) preceding the plist path and tolerates " +
			"flag-like args between `load` and the plist (`-w`, `-F`, etc.).",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"exec"},
		FalsePositives: []string{
			"MDM- or installer-provisioned LaunchAgents (Munki, Kandji, JumpCloud) loaded at deploy time. Add a path-glob exclusion for their plist paths via the detection-config surface.",
			"Developer tools that register helper agents (Docker Desktop, Backblaze, etc.) on first launch.",
		},
		Limitations: []string{
			"Does not cover `launchctl bootout` or `launchctl unload`: those undo persistence rather than create it.",
			"Does not catch direct plist writes that never get activated; pair with the privilege_launchd_plist_write rule for system-domain coverage.",
		},
	}
}

// launchctlPaths covers the common macOS launchctl binary locations.

// launchAgentPath matches arguments that reference a plist under a LaunchAgents directory. We accept both system-wide
// (/Library/LaunchAgents) and per-user (~ / /Users/<u>/Library) locations: an attacker-planted plist at either is a persistence
// mechanism.
var launchAgentPath = regexp.MustCompile(`(?i)(^|/)(Users/[^/]+/)?Library/LaunchAgents/[^/]+\.plist$`)

// launchAgentDetection is the rule's logic, compiled from the detection block in its pack file.
var launchAgentDetection = sync.OnceValue(func() *sigma.Rule { return detectionFor("persistence_launchagent") })

type persistenceLaunchCtlPayload struct {
	PID  int      `json:"pid"`
	PPID int      `json:"ppid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func (r *PersistenceLaunchAgent) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return evalEachEvent(ctx, events, s, r.evalEvent)
}

// evalEvent returns a finding for a single event, or nil when the event doesn't match.
func (r *PersistenceLaunchAgent) evalEvent(ctx context.Context, evt api.Event, s api.GraphReader) (*api.Finding, error) {
	if evt.EventType != "exec" {
		return nil, nil
	}
	var p persistenceLaunchCtlPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return nil, nil
	}
	se, err := sigmabind.NewEvent(evt)
	if err != nil {
		return nil, nil
	}
	if !launchAgentDetection().Matches(se) {
		return nil, nil
	}
	// Read back the values the detection matched on, so the alert names the job that was registered.
	subcommand := firstField(se, "Subcommand")
	plistPath := firstMatching(se, "CommandArguments", launchAgentPath.MatchString)
	if r.excluded(plistPath, evt.HostID) {
		return nil, nil
	}
	// Look up the process row so the alert can link to the process detail view. A young miss raises the retryable
	// ErrProcessNotYetMaterialized so the batch is re-evaluated once the processor lands the row; a stale miss skips. Safer than
	// firing an alert we can't pivot from.
	proc, err := resolveSubjectProcess(ctx, s, evt, p.PID)
	if err != nil {
		return nil, err
	}
	if proc == nil {
		return nil, nil
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("launchctl %s %s", subcommand, plistPath),
		ProcessID:   proc.ID,
		EventIDs:    []string{evt.EventID},
	}, nil
}

func (r *PersistenceLaunchAgent) excluded(path, hostID string) bool {
	return r.Exclusions != nil && r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, path, hostID)
}
