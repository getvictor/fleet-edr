package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/store"
)

// OsascriptNetworkExec fires when the rule sees a temp-path exec whose process
// tree has an osascript ancestor AND a curl/wget sibling within the osascript's
// 30-second descendant window. This is the canonical macOS commodity-dropper
// shape: AppleScript fetches a stage-2 over the network and runs it from a
// tempdir.
//
// Why we trigger on the temp-exec event rather than the osascript event: the
// processor pipeline runs `builder.ProcessBatch` then `detection.Evaluate` on
// each POST individually. The agent flushes events in roughly 1-second batches.
// A real chain completes in ~150ms, so when the agent flushes mid-chain the
// osascript exec lands in batch N while its descendants land in batch N+1.
// Forward-direction matching (osascript → look for descendants) misses the
// chain entirely in that case because descendants aren't in the store yet
// when batch N evaluates, and the osascript event isn't in batch N+1 to
// re-trigger evaluation. Reverse-direction matching is race-immune: by the
// time the temp-exec event lands, every ancestor (osascript, the intermediate
// shell, the curl sibling) has already been ingested and materialised.
//
// The rule still requires both halves of the chain (curl ancestor's sibling +
// temp-exec) to be present, so download-only or temp-exec-only flows do not
// fire — those overlap with other rules (suspicious_exec, network_exec_*).
//
// MITRE ATT&CK: T1059.002 (AppleScript) + T1105 (Ingress Tool Transfer).
type OsascriptNetworkExec struct{}

func (r *OsascriptNetworkExec) ID() string { return "osascript_network_exec" }

// Techniques returns the MITRE ATT&CK IDs this rule covers — T1059.002
// (Command and Scripting Interpreter → AppleScript) + T1105 (Ingress Tool
// Transfer). The rule specifically flags osascript invoking a curl/wget
// that stages an executable to /tmp — the exact shape of a T1105 dropper.
func (r *OsascriptNetworkExec) Techniques() []string {
	return []string{"T1059.002", "T1105"}
}

var osascriptPaths = map[string]bool{
	"/usr/bin/osascript": true,
}

var downloadBinaries = map[string]bool{
	"/usr/bin/curl":          true,
	"/usr/bin/wget":          true,
	"/opt/homebrew/bin/curl": true,
	"/opt/homebrew/bin/wget": true,
}

// shebangShellPaths is the set of shells the kernel transparently exec()s
// when running a `#!/bin/sh`-style script. The exec event's path field is
// the SHELL path (because that's what the kernel actually called exec on),
// not the script path; the script path lives in argv[1]. Without this
// detour the rule would miss the canonical "osascript → sh /tmp/stage2.sh"
// chain even though the data is right there in the descendant's args.
var shebangShellPaths = map[string]bool{
	"/bin/sh":       true,
	"/bin/bash":     true,
	"/bin/zsh":      true,
	"/bin/dash":     true,
	"/usr/bin/zsh":  true,
	"/usr/bin/bash": true,
	"/usr/bin/dash": true,
}

const (
	// osascriptWindowNs bounds the descendant walk from the osascript exec.
	// Real droppers stage and run within a couple of seconds; 30s is a
	// generous ceiling that keeps slow networks in-bound without making the
	// rule a sliding-window fish-hook.
	osascriptWindowNs = int64(30_000_000_000)

	// maxAncestorWalkSteps caps the parent-chain traversal so a runaway
	// process tree (or a malformed event with a self-referential ppid)
	// can't loop. Real chains go osascript → sh → maybe-one-more → temp-exec,
	// so any depth beyond a handful is suspicious in itself.
	maxAncestorWalkSteps = 16
)

type osascriptPayload struct {
	PID  int      `json:"pid"`
	PPID int      `json:"ppid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func (r *OsascriptNetworkExec) Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]detection.Finding, error) {
	// One osascript chain commonly produces multiple temp-exec descendants
	// — the kernel re-execs sh→bash, the chain runs more than one stage, etc.
	// Track which osascript ancestor PIDs we've already fired on within this
	// batch so we emit one finding per chain, not one per descendant row.
	seenOsa := map[int]struct{}{}
	var findings []detection.Finding
	for _, evt := range events {
		f, osaPID, err := r.evalEvent(ctx, evt, s, seenOsa)
		if err != nil {
			return nil, err
		}
		if f != nil {
			findings = append(findings, *f)
			seenOsa[osaPID] = struct{}{}
		}
	}
	return findings, nil
}

// evalEvent inspects a single event and returns (finding, osaPID, err) on a
// match. osaPID is the PID of the osascript ancestor that triggered the
// finding; the caller uses it for batch-level dedupe.
func (r *OsascriptNetworkExec) evalEvent(
	ctx context.Context, evt store.Event, s *store.Store, seenOsa map[int]struct{},
) (*detection.Finding, int, error) {
	if evt.EventType != "exec" {
		return nil, 0, nil
	}
	var p osascriptPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return nil, 0, nil
	}
	if !looksLikeTempExec(p) {
		return nil, 0, nil
	}

	osa, err := r.findOsascriptAncestor(ctx, s, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return nil, 0, err
	}
	if osa == nil {
		return nil, 0, nil
	}
	if _, dupe := seenOsa[osa.PID]; dupe {
		return nil, 0, nil
	}

	// Anchor the descendant window on the osascript exec time, not on the
	// triggering temp-exec event time, since the curl sibling may have run
	// before the temp-exec.
	osaExecTs := osa.ForkTimeNs
	if osa.ExecTimeNs != nil {
		osaExecTs = *osa.ExecTimeNs
	}
	tr := store.TimeRange{FromNs: osaExecTs, ToNs: osaExecTs + osascriptWindowNs}
	descendants, err := collectDescendants(ctx, s, evt.HostID, osa.PID, tr)
	if err != nil {
		return nil, 0, err
	}
	var downloader *store.Process
	for i := range descendants {
		if downloadBinaries[descendants[i].Path] {
			downloader = &descendants[i]
			break
		}
	}
	if downloader == nil {
		return nil, 0, nil
	}

	tempExecProc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return nil, 0, fmt.Errorf("get temp-exec pid %d: %w", p.PID, err)
	}
	if tempExecProc == nil {
		// Defensive: race against materialisation. Same shape as
		// credential_keychain_dump and friends.
		return nil, 0, nil
	}

	return &detection.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    detection.SeverityCritical,
		Title:       "osascript download-and-exec chain",
		Description: fmt.Sprintf("osascript → %s → %s", downloader.Path, displayTempExec(p)),
		ProcessID:   tempExecProc.ID,
		EventIDs:    []string{evt.EventID},
	}, osa.PID, nil
}

// findOsascriptAncestor walks the parent chain upward from startPID looking
// for an osascript process within `maxAncestorWalkSteps` hops. Returns nil if
// no osascript ancestor exists or the chain bottoms out at launchd (PPID 1).
func (r *OsascriptNetworkExec) findOsascriptAncestor(
	ctx context.Context, s *store.Store, hostID string, startPID int, asOfNs int64,
) (*store.Process, error) {
	current, err := s.GetProcessByPID(ctx, hostID, startPID, asOfNs)
	if err != nil {
		return nil, fmt.Errorf("get pid %d: %w", startPID, err)
	}
	for steps := 0; current != nil && steps < maxAncestorWalkSteps; steps++ {
		if osascriptPaths[current.Path] {
			return current, nil
		}
		if current.PPID <= 1 {
			return nil, nil
		}
		next, err := s.GetProcessByPID(ctx, hostID, current.PPID, asOfNs)
		if err != nil {
			return nil, fmt.Errorf("get ppid %d: %w", current.PPID, err)
		}
		current = next
	}
	return nil, nil
}

// shebangScriptArg returns the script path argument from a shebang-shell
// invocation (`/bin/sh /tmp/stage2.sh`), or "" if the argv shape is
// `-c <command>` / flags-only / empty / non-shell. Both the gating
// predicate (looksLikeTempExec) and the description renderer
// (displayTempExec) derive from this so they cannot disagree about which
// argv slot the analyst sees.
//
// `sh -c <command>` returns "" on purpose because the next argv slot is
// a command string, not a path — running isSuspiciousPath against it
// false-positives on arbitrary text containing `..`.
func shebangScriptArg(p osascriptPayload) string {
	if !shebangShellPaths[p.Path] {
		return ""
	}
	for i := 1; i < len(p.Args); i++ {
		a := p.Args[i]
		if a == "-c" {
			return ""
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// looksLikeTempExec reports whether the exec event represents a binary
// running out of /tmp (or one of the other temp-prefix paths) OR a shell
// invoked with a `#!/bin/sh`-style script path in argv[1+]. Both shapes
// signal the same intent: stage-2 from a tempdir. Reading argv directly
// off the event payload (rather than the materialised process record)
// avoids a race against args being persisted to the processes table.
func looksLikeTempExec(p osascriptPayload) bool {
	if isSuspiciousPath(p.Path) {
		return true
	}
	script := shebangScriptArg(p)
	return script != "" && isSuspiciousPath(script)
}

// displayTempExec renders the operator-friendly path for the finding's
// description. For a binary stage-2, this is just the binary path. For a
// shebang-shell exec, it's `<shell> <script-path>` so the responder can see
// the script that actually ran rather than just "/bin/sh".
func displayTempExec(p osascriptPayload) string {
	if isSuspiciousPath(p.Path) {
		return p.Path
	}
	if script := shebangScriptArg(p); script != "" && isSuspiciousPath(script) {
		return fmt.Sprintf("%s %s", p.Path, script)
	}
	return p.Path
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
