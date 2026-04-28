package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/store"
)

// ShellFromOffice fires when a shell (/bin/sh, /bin/bash, /bin/zsh, etc.) is spawned
// whose parent process is one of the Microsoft Office apps. VBA/Word-macro payloads
// frequently shell out to bootstrap a second-stage; modern macOS keeps the Office
// binaries in /Applications/Microsoft {Word,Excel,PowerPoint,Outlook}.app/.
//
// MITRE ATT&CK: T1566.001 (Phishing: Spearphishing Attachment) + T1059 (Shell)
type ShellFromOffice struct{}

func (r *ShellFromOffice) ID() string { return "shell_from_office" }

// Techniques returns the MITRE ATT&CK IDs this rule covers — T1566.001
// (Phishing → Spearphishing Attachment) + T1059.004 (Command and Scripting
// Interpreter → Unix Shell). The chain "Office app → shell" is a textbook
// post-phish execution step.
func (r *ShellFromOffice) Techniques() []string { return []string{"T1566.001", "T1059.004"} }

// Doc surfaces the operator-facing description in /api/v1/admin/rules and
// the generated docs/detection-rules.md.
func (r *ShellFromOffice) Doc() detection.Documentation {
	return detection.Documentation{
		Title:   "Shell spawned by Microsoft Office",
		Summary: "Flags any /bin/sh, /bin/bash, /bin/zsh (etc.) whose parent is Word, Excel, PowerPoint, or Outlook.",
		Description: "Detects the textbook post-phishing execution step: a macro-laden Office document opens, the macro " +
			"shells out, and the second stage takes off from there. The match is on the parent process being one of " +
			"the four standard macOS Office binaries (full path, not substring) and the child being a known shell.\n\n" +
			"Office apps almost never need to shell out in normal use; when they do, it's an admin-side automation " +
			"that's worth surfacing anyway.",
		Severity:   detection.SeverityHigh,
		EventTypes: []string{"exec"},
		FalsePositives: []string{
			"Office's internal `Get Started` first-run flow has historically shelled out to fetch help content. Confirm by inspecting argv on the alert.",
			"Admin-driven user-environment scripts that template Office settings via shell.",
		},
		Limitations: []string{
			"Does not catch non-shell payloads (osascript, python, ruby) launched directly from Office. Pair with osascript_network_exec for the AppleScript variant.",
			"Office binary path matching is exact: `/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word`. Apps installed elsewhere (e.g. on an external volume) are missed by design.",
		},
	}
}

// officeBinaries is the set of macOS Office executable paths that, as a parent, make a
// shell exec suspicious. We match full paths, not substrings, so a user-named file
// like `/tmp/Microsoft Word` cannot accidentally silence or spoof a finding.
var officeBinaries = map[string]bool{
	"/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word":             true,
	"/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel":           true,
	"/Applications/Microsoft PowerPoint.app/Contents/MacOS/Microsoft PowerPoint": true,
	"/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook":       true,
}

type shellFromOfficePayload struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Path string `json:"path"`
}

func (r *ShellFromOffice) Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]detection.Finding, error) {
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
// Splitting this out of Evaluate keeps the per-event short-circuits (non-exec, bad JSON,
// non-shell path, non-Office parent) from stacking cognitive complexity on the caller.
func (r *ShellFromOffice) evalEvent(ctx context.Context, evt store.Event, s *store.Store) (*detection.Finding, error) {
	if evt.EventType != "exec" {
		return nil, nil
	}
	var p shellFromOfficePayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return nil, nil
	}
	if !shellPaths[p.Path] {
		return nil, nil
	}

	parent, err := s.GetProcessByPID(ctx, evt.HostID, p.PPID, evt.TimestampNs)
	if err != nil {
		return nil, fmt.Errorf("get parent pid %d: %w", p.PPID, err)
	}
	// Parent not yet materialised, or not an Office binary. The processor marks the
	// whole batch processed after Evaluate returns, so a re-feed does not happen
	// automatically — missing-parent cases are accepted for Phase 2; a deferred retry
	// queue is Phase 4 scope (see claude/mvp/plan.md).
	if parent == nil || !officeBinaries[parent.Path] {
		return nil, nil
	}

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
		Title:       "Shell spawned from Office app",
		Description: fmt.Sprintf("%s → %s", prettyOfficeParent(parent.Path), p.Path),
		ProcessID:   proc.ID,
		EventIDs:    []string{evt.EventID},
	}, nil
}

// prettyOfficeParent strips the /Applications/… prefix so the alert description stays
// legible ("Microsoft Word → /bin/bash" rather than the full bundle path).
func prettyOfficeParent(p string) string {
	const prefix = "/Applications/"
	if !strings.HasPrefix(p, prefix) {
		return p
	}
	// Trim prefix + `.app/Contents/MacOS/...` tail. Any unexpected shape falls back to
	// the raw path.
	rest := p[len(prefix):]
	if idx := strings.Index(rest, ".app"); idx > 0 {
		return rest[:idx]
	}
	return p
}
