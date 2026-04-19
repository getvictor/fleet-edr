package rules

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/store"
)

// OsascriptNetworkExec fires when `osascript` (or its alias `/usr/bin/osascript`) is the
// root of a 30-second process tree that both downloads something (a `curl` or `wget`
// child) AND launches a binary out of a temp directory. This matches the
// "AppleScript → curl → stage 2 from /tmp" chain seen across macOS commodity droppers.
//
// We deliberately fire on the combination (download + temp-exec), not on each individually,
// so the false-positive rate is manageable — osascript by itself is normal on managed
// fleets, and /tmp exec alone is already covered by suspicious_exec.
//
// MITRE ATT&CK: T1059.002 (AppleScript) + T1105 (Ingress Tool Transfer)
type OsascriptNetworkExec struct{}

func (r *OsascriptNetworkExec) ID() string { return "osascript_network_exec" }

var osascriptPaths = map[string]bool{
	"/usr/bin/osascript": true,
}

var downloadBinaries = map[string]bool{
	"/usr/bin/curl":          true,
	"/usr/bin/wget":          true,
	"/opt/homebrew/bin/curl": true,
	"/opt/homebrew/bin/wget": true,
}

type osascriptPayload struct {
	PID  int      `json:"pid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func (r *OsascriptNetworkExec) Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]detection.Finding, error) {
	const windowNs = int64(30_000_000_000) // 30 seconds
	var findings []detection.Finding
	for _, evt := range events {
		if evt.EventType != "exec" {
			continue
		}
		var p osascriptPayload
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			continue
		}
		if !osascriptPaths[p.Path] {
			continue
		}

		tr := store.TimeRange{FromNs: evt.TimestampNs, ToNs: evt.TimestampNs + windowNs}
		children, err := s.GetChildProcesses(ctx, evt.HostID, p.PID, tr)
		if err != nil {
			return nil, fmt.Errorf("get osascript children pid %d: %w", p.PID, err)
		}
		if len(children) == 0 {
			continue
		}

		// Chain detection: at least one download child AND at least one exec out of a
		// suspicious path (same allowlist as suspicious_exec, via isSuspiciousPath).
		var downloader *store.Process
		var tempExec *store.Process
		for i := range children {
			c := &children[i]
			if downloadBinaries[c.Path] {
				downloader = c
			}
			if isSuspiciousPath(c.Path) {
				tempExec = c
			}
		}
		if downloader == nil || tempExec == nil {
			continue
		}

		// The finding links to the temp-path process — that's the thing responders need
		// to investigate first. The download child + the osascript itself are both in the
		// event_ids so the alert detail view can render the full chain.
		osaProc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
		if err != nil {
			return nil, fmt.Errorf("get osascript process pid %d: %w", p.PID, err)
		}
		if osaProc == nil {
			continue
		}

		findings = append(findings, detection.Finding{
			HostID:   evt.HostID,
			RuleID:   r.ID(),
			Severity: detection.SeverityCritical,
			Title:    "osascript download-and-exec chain",
			Description: fmt.Sprintf(
				"osascript → %s → %s",
				downloader.Path, tempExec.Path,
			),
			ProcessID: tempExec.ID,
			EventIDs:  []string{evt.EventID},
		})
	}
	return findings, nil
}
