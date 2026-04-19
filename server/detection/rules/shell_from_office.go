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
		if evt.EventType != "exec" {
			continue
		}
		var p shellFromOfficePayload
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			continue
		}
		if !shellPaths[p.Path] {
			continue
		}

		parent, err := s.GetProcessByPID(ctx, evt.HostID, p.PPID, evt.TimestampNs)
		if err != nil {
			return nil, fmt.Errorf("get parent pid %d: %w", p.PPID, err)
		}
		if parent == nil {
			// Parent not yet materialised — skip; the processor will re-feed this event in
			// the next batch once the parent row lands.
			continue
		}
		if !officeBinaries[parent.Path] {
			continue
		}

		proc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
		if err != nil {
			return nil, fmt.Errorf("get process pid %d: %w", p.PID, err)
		}
		if proc == nil {
			continue
		}

		findings = append(findings, detection.Finding{
			HostID:      evt.HostID,
			RuleID:      r.ID(),
			Severity:    detection.SeverityHigh,
			Title:       "Shell spawned from Office app",
			Description: fmt.Sprintf("%s → %s", prettyOfficeParent(parent.Path), p.Path),
			ProcessID:   proc.ID,
			EventIDs:    []string{evt.EventID},
		})
	}
	return findings, nil
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
