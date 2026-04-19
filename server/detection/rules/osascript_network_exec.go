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
		descendants, err := collectDescendants(ctx, s, evt.HostID, p.PID, tr)
		if err != nil {
			return nil, err
		}
		if len(descendants) == 0 {
			continue
		}

		// Chain detection: at least one downloader AND at least one exec out of a
		// suspicious path (same allowlist as suspicious_exec, via isSuspiciousPath).
		// Walk the full descendant set because real droppers often route through an
		// intermediate shell (`osascript → sh → curl → /tmp/stage2`) and a direct-
		// children-only scan misses those.
		var downloader *store.Process
		var tempExec *store.Process
		for i := range descendants {
			c := &descendants[i]
			if downloader == nil && downloadBinaries[c.Path] {
				downloader = c
			}
			if tempExec == nil && isSuspiciousPath(c.Path) {
				tempExec = c
			}
			if downloader != nil && tempExec != nil {
				break
			}
		}
		if downloader == nil || tempExec == nil {
			continue
		}

		// The finding links to the temp-path process — that's the thing responders need
		// to investigate first. EventIDs includes just the triggering osascript exec
		// because that is the event this detector saw in the batch; child exec events
		// are reachable from the linked ProcessID via the process tree query and the
		// server-side alert detail view renders the full chain from there.
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

// collectDescendants runs a bounded breadth-first traversal rooted at rootPID, returning
// every process whose ancestry within the given time range terminates at rootPID. The
// traversal is capped by `maxDescendants` to keep pathological fork-bomb trees from
// blowing up memory; real dropper chains land in single digits, so a 500-node cap is
// generous without being abusable.
const maxDescendants = 500

func collectDescendants(ctx context.Context, s *store.Store, hostID string, rootPID int, tr store.TimeRange) ([]store.Process, error) {
	var all []store.Process
	queue := []int{rootPID}
	seen := map[int]struct{}{rootPID: {}}

	for len(queue) > 0 && len(all) < maxDescendants {
		parent := queue[0]
		queue = queue[1:]

		children, err := s.GetChildProcesses(ctx, hostID, parent, tr)
		if err != nil {
			return nil, fmt.Errorf("get children of pid %d: %w", parent, err)
		}
		for _, c := range children {
			if _, dupe := seen[c.PID]; dupe {
				continue
			}
			seen[c.PID] = struct{}{}
			all = append(all, c)
			if len(all) >= maxDescendants {
				break
			}
			queue = append(queue, c.PID)
		}
	}
	return all, nil
}
