package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/store"
)

// PersistenceLaunchAgent fires when a process calls `launchctl load` or
// `launchctl bootstrap` referencing a plist under `~/Library/LaunchAgents/` or
// `/Library/LaunchAgents/` — the canonical macOS persistence mechanism. Operators can
// silence expected plists via `EDR_LAUNCHAGENT_ALLOWLIST` (comma-separated absolute paths).
//
// MITRE ATT&CK: T1547.011 (Boot or Logon Autostart Execution: Launch Agent)
type PersistenceLaunchAgent struct {
	// AllowedPlists is the set of plist paths the operator has pre-blessed. The rule
	// skips findings whose target plist matches any entry (exact string match).
	AllowedPlists map[string]struct{}
}

func (r *PersistenceLaunchAgent) ID() string { return "persistence_launchagent" }

// Techniques: T1543.001 (Create or Modify System Process → Launch Agent).
// The rule fires on `launchctl load` of user LaunchAgent plists, which is
// exactly this sub-technique's scope.
func (r *PersistenceLaunchAgent) Techniques() []string { return []string{"T1543.001"} }

// launchctlPaths covers the common macOS launchctl binary locations.
var launchctlPaths = map[string]bool{
	"/bin/launchctl":     true,
	"/usr/bin/launchctl": true,
}

// launchAgentPath matches arguments that reference a plist under a LaunchAgents directory.
// We accept both system-wide (/Library/LaunchAgents) and per-user (~ / /Users/<u>/Library)
// locations — an attacker-planted plist at either is a persistence mechanism.
var launchAgentPath = regexp.MustCompile(`(?i)(^|/)(Users/[^/]+/)?Library/LaunchAgents/[^/]+\.plist$`)

type persistenceLaunchCtlPayload struct {
	PID  int      `json:"pid"`
	PPID int      `json:"ppid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func (r *PersistenceLaunchAgent) Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]detection.Finding, error) {
	var findings []detection.Finding
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
func (r *PersistenceLaunchAgent) evalEvent(ctx context.Context, evt store.Event, s *store.Store) (*detection.Finding, error) {
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
	if plistPath == "" || !launchAgentPath.MatchString(plistPath) || r.allowed(plistPath) {
		return nil, nil
	}
	// Look up the process row so the alert can link to the process detail view. If it's
	// not yet materialised we skip — the next batch re-evaluates once the processor
	// lands the row. Safer than firing an alert we can't pivot from.
	proc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return nil, fmt.Errorf("get process pid %d: %w", p.PID, err)
	}
	if proc == nil {
		return nil, nil
	}
	return &detection.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    detection.SeverityHigh,
		Title:       "LaunchAgent persistence attempt",
		Description: fmt.Sprintf("launchctl %s %s", subcommand, plistPath),
		ProcessID:   proc.ID,
		EventIDs:    []string{evt.EventID},
	}, nil
}

func (r *PersistenceLaunchAgent) allowed(path string) bool {
	if r.AllowedPlists == nil {
		return false
	}
	_, ok := r.AllowedPlists[path]
	return ok
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
