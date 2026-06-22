package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/fleetdm/edr/server/rules/api"
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

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1543.001 (Create or Modify System Process → Launch Agent). The rule
// fires on `launchctl load` of user LaunchAgent plists, which is exactly this sub-technique's scope.
func (r *PersistenceLaunchAgent) Techniques() []string { return []string{"T1543.001"} }

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *PersistenceLaunchAgent) Doc() api.Documentation {
	return api.Documentation{
		Title:   "LaunchAgent persistence (launchctl load/bootstrap)",
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
var launchctlPaths = map[string]bool{
	"/bin/launchctl":     true,
	"/usr/bin/launchctl": true,
}

// launchAgentPath matches arguments that reference a plist under a LaunchAgents directory. We accept both system-wide
// (/Library/LaunchAgents) and per-user (~ / /Users/<u>/Library) locations: an attacker-planted plist at either is a persistence
// mechanism.
var launchAgentPath = regexp.MustCompile(`(?i)(^|/)(Users/[^/]+/)?Library/LaunchAgents/[^/]+\.plist$`)

type persistenceLaunchCtlPayload struct {
	PID  int      `json:"pid"`
	PPID int      `json:"ppid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func (r *PersistenceLaunchAgent) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	var findings []api.Finding
	for _, evt := range events {
		f, err := r.evalEvent(ctx, evt, s)
		if err != nil {
			return nil, err
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
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
	if !launchctlPaths[p.Path] {
		return nil, nil
	}
	subcommand, plistPath := extractLaunchctlSubcommand(p.Args)
	if subcommand != "load" && subcommand != "bootstrap" {
		return nil, nil
	}
	if plistPath == "" || !launchAgentPath.MatchString(plistPath) || r.excluded(plistPath, evt.HostID) {
		return nil, nil
	}
	// Look up the process row so the alert can link to the process detail view. If it's not yet materialised we skip; the next batch
	// re-evaluates once the processor lands the row. Safer than firing an alert we can't pivot from.
	proc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return nil, fmt.Errorf("get process pid %d: %w", p.PID, err)
	}
	if proc == nil {
		return nil, nil
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       "LaunchAgent persistence attempt",
		Description: fmt.Sprintf("launchctl %s %s", subcommand, plistPath),
		ProcessID:   proc.ID,
		EventIDs:    []string{evt.EventID},
	}, nil
}

func (r *PersistenceLaunchAgent) excluded(path, hostID string) bool {
	return r.Exclusions != nil && r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, path, hostID)
}

// extractLaunchctlSubcommand pulls the subcommand (`load`, `bootstrap`, `unload`, etc.) and
// the first LaunchAgents plist argument out of an argv. argv[0] is the binary path; we look
// for the first non-flag token for the subcommand and then keep walking until we find an
// arg that looks like an actual LaunchAgents plist.
//
// Why "keep walking" rather than "first arg with /": `launchctl bootstrap gui/501
// /Users/alice/Library/LaunchAgents/evil.plist` puts the launch-domain specifier
// ("gui/501") before the plist path. A naive "first slash-containing arg" grab catches
// the domain and then the rule drops the event entirely. Matching on `launchAgentPath`
// keeps the scan going past launch domains so the plist is the thing we return.
//
// Example inputs:
//
//	[]string{"/bin/launchctl", "load", "/Users/alice/Library/LaunchAgents/evil.plist"}
//	  → ("load", "/Users/alice/Library/LaunchAgents/evil.plist")
//	[]string{"/bin/launchctl", "load", "-w", "/Library/LaunchAgents/foo.plist"}
//	  → ("load", "/Library/LaunchAgents/foo.plist")
//	[]string{"/bin/launchctl", "bootstrap", "gui/501", "/Users/alice/Library/LaunchAgents/evil.plist"}
//	  → ("bootstrap", "/Users/alice/Library/LaunchAgents/evil.plist")
func extractLaunchctlSubcommand(args []string) (subcommand, plistPath string) {
	for i := 1; i < len(args); i++ {
		if args[i] == "" || strings.HasPrefix(args[i], "-") {
			continue
		}
		if subcommand == "" {
			subcommand = args[i]
			continue
		}
		if launchAgentPath.MatchString(args[i]) {
			return subcommand, args[i]
		}
	}
	return subcommand, ""
}
