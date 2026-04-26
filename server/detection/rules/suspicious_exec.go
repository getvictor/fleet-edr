// Package rules contains concrete detection rule implementations.
package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/store"
)

// Known shell paths.
var shellPaths = map[string]bool{
	"/bin/sh":       true,
	"/bin/bash":     true,
	"/bin/zsh":      true,
	"/bin/dash":     true,
	"/usr/bin/sh":   true,
	"/usr/bin/bash": true,
	"/usr/bin/zsh":  true,
	"/usr/bin/dash": true,
}

// Suspicious path prefixes where legitimate binaries should not execute from.
var suspiciousPrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/private/tmp/",
	"/dev/shm/",
}

// SuspiciousExec detects two related shapes that share a single attribution
// chain: non-shell-process spawned a shell, and within 30 seconds the shell
// (or its descendants) either exec'd a binary from a temp directory OR made
// an outbound network connection.
//
// Triggering: the rule fires on the LAST link of the chain (the temp-exec
// event or the outbound network_connect event) rather than on the shell's
// exec event. Forward-direction triggering — fire when the shell exec is
// seen, then look forward for descendants — is unreliable in production
// because the processor pipeline runs `builder.ProcessBatch` then
// `detection.Evaluate` per agent POST and the agent flushes events in
// roughly 1-second batches. A real chain completes in ~150ms, so when the
// cadence boundary lands mid-chain the shell exec arrives in batch N while
// the temp-binary exec arrives in batch N+1 — at batch N's Evaluate the
// descendants haven't been materialised, and the shell event isn't in
// batch N+1 to re-trigger evaluation. Reverse-direction triggering is
// race-immune because by the time the trigger event lands, every ancestor
// (the shell, the non-shell that spawned it) has already been ingested
// and materialised by an earlier batch.
//
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1204 (User Execution).
type SuspiciousExec struct {
	// AllowedNonShellParents is the set of non-shell parent paths the rule
	// should treat as benign roots even when they spawn a shell that runs
	// a temp-path binary. The canonical case is `/usr/libexec/sshd-session`
	// — admins SSH in, run a script from /tmp/, leave; the chain matches
	// the rule's shape verbatim but is operationally normal.
	//
	// The trade-off is real: an attacker who pivots into the host via a
	// compromised SSH credential follows the same chain shape, so
	// allowlisting sshd-session reduces noise but also blinds the rule
	// to that one attacker pattern. Empty by default — operators opt in
	// via EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST for the fleets where the
	// noise reduction matters more than the residual attacker coverage.
	// On servers where interactive SSH is unusual, leaving this empty is
	// the right call.
	AllowedNonShellParents map[string]struct{}
}

func (r *SuspiciousExec) ID() string { return "suspicious_exec" }

// Techniques returns the MITRE ATT&CK IDs this rule covers — T1059
// (Command and Scripting Interpreter) + T1105 (Ingress Tool Transfer).
func (r *SuspiciousExec) Techniques() []string {
	return []string{"T1059", "T1105"}
}

const (
	// suspiciousExecWindowNs bounds the temporal distance between the shell
	// exec and the trigger event (temp-exec or network_connect). Real chains
	// complete in seconds; 30s is a generous ceiling that matches the
	// original forward-direction rule.
	suspiciousExecWindowNs = int64(30_000_000_000)

	// maxSuspiciousAncestorWalkSteps caps the parent-chain traversal so a
	// pathological process tree (or a malformed event with self-referential
	// ppid) can't loop. Real chains go non-shell -> shell -> temp, and
	// shell-to-shell layering rarely exceeds two or three hops.
	maxSuspiciousAncestorWalkSteps = 16
)

// execPayload is the subset of exec event payload fields needed for detection.
// Args carries argv so the rule can detect shebang-shell execs where the
// kernel resolves `#!/bin/sh` to /bin/sh and the actual script path lives
// in argv[1] — the rule must consider those temp-path execs even though
// the exec event's `path` field is /bin/sh, not /tmp/whatever.
type execPayload struct {
	PID  int      `json:"pid"`
	PPID int      `json:"ppid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

// networkConnectPayload is the subset of network_connect event fields needed
// for detection. PID identifies the process making the connection — the rule
// walks UP from there looking for a shell ancestor with a non-shell parent.
type networkConnectPayload struct {
	PID           int    `json:"pid"`
	Direction     string `json:"direction"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
}

func (r *SuspiciousExec) Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]detection.Finding, error) {
	// Two-pass evaluation. Pass 1 handles temp-exec triggers (preferred); Pass 2
	// handles outbound network_connect triggers as a fallback. Splitting the
	// passes preserves the original rule's "prefer the path-based finding when
	// both signals exist for the same shell" semantics — which would otherwise
	// be order-dependent on event arrival within a single pass.
	seenShell := map[int]struct{}{}
	var findings []detection.Finding

	for _, evt := range events {
		if evt.EventType != "exec" {
			continue
		}
		f, shellPID, err := r.evalExec(ctx, evt, s, events, seenShell)
		if err != nil {
			return nil, err
		}
		if f != nil {
			findings = append(findings, *f)
			seenShell[shellPID] = struct{}{}
		}
	}

	for _, evt := range events {
		if evt.EventType != "network_connect" {
			continue
		}
		f, shellPID, err := r.evalNetwork(ctx, evt, s, events, seenShell)
		if err != nil {
			return nil, err
		}
		if f != nil {
			findings = append(findings, *f)
			seenShell[shellPID] = struct{}{}
		}
	}

	return findings, nil
}

// findShellExecEventID scans the current batch for an exec event matching the
// shell's PID and host so the finding's EventIDs can include the shell-stage
// event when it happens to be in the same batch as the trigger. Best-effort:
// when the shell exec is in an earlier batch it isn't findable here and
// EventIDs simply omits it. The trigger's own event ID is excluded to avoid
// duplicates in the arm-2 (re-exec) case where shell and temp share a PID.
func findShellExecEventID(events []store.Event, hostID string, shellPID int, excludeEventID string) string {
	for _, e := range events {
		if e.EventType != "exec" || e.HostID != hostID || e.EventID == excludeEventID {
			continue
		}
		var p execPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			continue
		}
		if p.PID != shellPID {
			continue
		}
		if !shellPaths[p.Path] {
			continue
		}
		return e.EventID
	}
	return ""
}

// evalExec inspects a single exec event. Returns (finding, shellPID, err) on a
// match. The shellPID is the PID of the attributed shell ancestor — the caller
// uses it for batch-level dedupe so multiple temp-exec children of one shell
// produce one finding rather than one per child.
func (r *SuspiciousExec) evalExec(
	ctx context.Context, evt store.Event, s *store.Store, batch []store.Event, seenShell map[int]struct{},
) (*detection.Finding, int, error) {
	var p execPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return nil, 0, nil
	}
	tempPath, ok := suspiciousTempPath(p)
	if !ok {
		return nil, 0, nil
	}

	// We need the temp-exec process record either way — for the finding's
	// ProcessID link, and (in the arm-2 case) to walk its re-exec chain.
	tempProc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return nil, 0, fmt.Errorf("get temp-exec pid %d: %w", p.PID, err)
	}
	if tempProc == nil {
		return nil, 0, nil
	}

	// Arm 1: walk the PPID chain up looking for a shell ancestor whose own
	// parent is non-shell. This catches the canonical fork+exec dropper
	// shape where the temp-binary is a SEPARATE process from the shell. We
	// start the walk at the temp-exec's own PID; the loop's first check is
	// `shellPaths[current.Path]` which is false for the temp-binary, so it
	// trivially advances to PPID — the actual candidate parent.
	shell, parent, err := r.findShellWithNonShellAncestor(ctx, s, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return nil, 0, err
	}
	if shell != nil {
		if _, dupe := seenShell[shell.PID]; dupe {
			return nil, 0, nil
		}
		if !shellWithinWindow(shell, evt.TimestampNs) {
			return nil, 0, nil
		}
		if r.parentAllowed(parent) {
			return nil, 0, nil
		}
		return r.makeExecFinding(evt, parent, shell, tempProc, tempPath, batch), shell.PID, nil
	}

	// Arm 2: same-PID re-exec optimisation. `sh -c "/tmp/foo"` is commonly
	// implemented by execve(/tmp/foo) at the shell's PID, leaving no fork
	// boundary between the shell and the payload. The latest exec record at
	// this PID is /tmp/foo (which is what got us here); the shell stage is
	// reachable via the previous_exec_id chain. Without this branch the
	// PPID walk above misses re-exec chains entirely because temp.PPID is
	// the shell's parent (a non-shell) and the shell itself is on the
	// re-exec history of the same PID, not in the parent chain.
	chain, err := s.GetExecChain(ctx, *tempProc)
	if err != nil {
		return nil, 0, fmt.Errorf("walk exec chain pid %d: %w", p.PID, err)
	}
	for i := range chain {
		prior := &chain[i]
		if !shellPaths[prior.Path] {
			continue
		}
		priorParent, err := r.lookupAncestor(ctx, s, evt.HostID, prior.PPID, evt.TimestampNs)
		if err != nil {
			return nil, 0, err
		}
		if priorParent != nil && shellPaths[priorParent.Path] {
			continue
		}
		if _, dupe := seenShell[prior.PID]; dupe {
			return nil, 0, nil
		}
		if !shellWithinWindow(prior, evt.TimestampNs) {
			return nil, 0, nil
		}
		if r.parentAllowed(priorParent) {
			return nil, 0, nil
		}
		return r.makeExecFinding(evt, priorParent, prior, tempProc, tempPath, batch), prior.PID, nil
	}
	return nil, 0, nil
}

// evalNetwork inspects an outbound network_connect event and walks UP from the
// connecting process looking for a shell ancestor whose parent is non-shell.
// The connecting process itself can be the shell (curl|sh case) or any
// descendant of it (shell spawned curl); the inclusive walk handles both.
func (r *SuspiciousExec) evalNetwork(
	ctx context.Context, evt store.Event, s *store.Store, batch []store.Event, seenShell map[int]struct{},
) (*detection.Finding, int, error) {
	var c networkConnectPayload
	if err := json.Unmarshal(evt.Payload, &c); err != nil {
		return nil, 0, nil
	}
	if c.Direction != "outbound" {
		return nil, 0, nil
	}
	shell, parent, err := r.findShellWithNonShellAncestor(ctx, s, evt.HostID, c.PID, evt.TimestampNs)
	if err != nil {
		return nil, 0, err
	}
	if shell == nil {
		return nil, 0, nil
	}
	if _, dupe := seenShell[shell.PID]; dupe {
		return nil, 0, nil
	}
	if !shellWithinWindow(shell, evt.TimestampNs) {
		return nil, 0, nil
	}
	if r.parentAllowed(parent) {
		return nil, 0, nil
	}

	// Resolve the connecting process so the finding links there rather than
	// at the shell. That's what an analyst clicking the alert wants to land on.
	conn, err := s.GetProcessByPID(ctx, evt.HostID, c.PID, evt.TimestampNs)
	if err != nil {
		return nil, 0, fmt.Errorf("get conn pid %d: %w", c.PID, err)
	}
	if conn == nil {
		return nil, 0, nil
	}
	parentPath := "(unknown)"
	if parent != nil {
		parentPath = parent.Path
	}
	eventIDs := []string{evt.EventID}
	if shellEventID := findShellExecEventID(batch, evt.HostID, shell.PID, evt.EventID); shellEventID != "" {
		eventIDs = append([]string{shellEventID}, eventIDs...)
	}
	return &detection.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    detection.SeverityHigh,
		Title:       "Shell spawn with outbound network connection",
		Description: fmt.Sprintf("%s → %s → outbound %s:%d", parentPath, shell.Path, c.RemoteAddress, c.RemotePort),
		ProcessID:   conn.ID,
		EventIDs:    eventIDs,
	}, shell.PID, nil
}

// findShellWithNonShellAncestor walks the PPID chain inclusively starting at
// startPID looking for a shell process whose own parent is non-shell. Returns
// the matched shell and its non-shell parent (parent may be nil if the shell's
// parent is launchd / unmaterialised — that still counts as a match because
// launchd is non-shell).
//
// The walk is "inclusive" — startPID itself is the first candidate. Callers
// that pass the temp-exec's own PID get the trivial first-iteration skip
// (temp-binary fails shellPaths) and the walk proceeds to the actual
// candidate parent on the next step.
func (r *SuspiciousExec) findShellWithNonShellAncestor(
	ctx context.Context, s *store.Store, hostID string, startPID int, asOfNs int64,
) (*store.Process, *store.Process, error) {
	current, err := s.GetProcessByPID(ctx, hostID, startPID, asOfNs)
	if err != nil {
		return nil, nil, fmt.Errorf("get pid %d: %w", startPID, err)
	}
	for steps := 0; current != nil && steps < maxSuspiciousAncestorWalkSteps; steps++ {
		if shellPaths[current.Path] {
			parent, err := r.lookupAncestor(ctx, s, hostID, current.PPID, asOfNs)
			if err != nil {
				return nil, nil, err
			}
			if parent == nil || !shellPaths[parent.Path] {
				return current, parent, nil
			}
			// Shell-to-shell layering is normal (sudo bash, su -c bash, ...).
			// Keep climbing — the outermost shell will eventually surface a
			// non-shell parent (or the chain hits launchd, which also counts).
			current = parent
			continue
		}
		if current.PPID <= 1 {
			return nil, nil, nil
		}
		next, err := s.GetProcessByPID(ctx, hostID, current.PPID, asOfNs)
		if err != nil {
			return nil, nil, fmt.Errorf("get ppid %d: %w", current.PPID, err)
		}
		current = next
	}
	return nil, nil, nil
}

// lookupAncestor returns nil for PIDs at or below launchd (PPID 1) and
// passes through to GetProcessByPID otherwise.
func (r *SuspiciousExec) lookupAncestor(
	ctx context.Context, s *store.Store, hostID string, pid int, asOfNs int64,
) (*store.Process, error) {
	if pid <= 1 {
		return nil, nil
	}
	p, err := s.GetProcessByPID(ctx, hostID, pid, asOfNs)
	if err != nil {
		return nil, fmt.Errorf("get pid %d: %w", pid, err)
	}
	return p, nil
}

// shellWithinWindow reports whether the trigger event's timestamp falls within
// the 30-second window after the shell's exec. Anchored on the shell's
// exec_time_ns when set (preferred — that's the kernel's actual exec moment)
// and falls back to fork_time_ns otherwise (defensive — should always be set
// for a fully-materialised process).
func shellWithinWindow(shell *store.Process, triggerTs int64) bool {
	anchor := shell.ForkTimeNs
	if shell.ExecTimeNs != nil {
		anchor = *shell.ExecTimeNs
	}
	return triggerTs >= anchor && triggerTs <= anchor+suspiciousExecWindowNs
}

// makeExecFinding builds the temp-path finding shared by arm 1 and arm 2.
// In the arm-2 re-exec case tempProc and shell share a PID; the finding
// still links to tempProc so the analyst lands on the temp-stage record
// (the re-exec'd row), not the earlier shell-stage row.
func (r *SuspiciousExec) makeExecFinding(
	evt store.Event, parent, shell, tempProc *store.Process, tempPath string, batch []store.Event,
) *detection.Finding {
	parentPath := "(unknown)"
	if parent != nil {
		parentPath = parent.Path
	}
	eventIDs := []string{evt.EventID}
	if shellEventID := findShellExecEventID(batch, evt.HostID, shell.PID, evt.EventID); shellEventID != "" {
		eventIDs = append([]string{shellEventID}, eventIDs...)
	}
	return &detection.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    detection.SeverityHigh,
		Title:       "Suspicious exec from temp path",
		Description: fmt.Sprintf("%s → %s → %s", parentPath, shell.Path, tempPath),
		ProcessID:   tempProc.ID,
		EventIDs:    eventIDs,
	}
}

// parentAllowed reports whether the given non-shell parent process is on the
// operator's allowlist. A nil parent (shell parented at launchd, or parent
// not yet materialised) never matches — those are the cases the rule must
// continue to flag because there's no human-attested entry point.
func (r *SuspiciousExec) parentAllowed(parent *store.Process) bool {
	if r.AllowedNonShellParents == nil || parent == nil {
		return false
	}
	_, ok := r.AllowedNonShellParents[parent.Path]
	return ok
}

func isSuspiciousPath(path string) bool {
	for _, prefix := range suspiciousPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	// Path traversal.
	if strings.Contains(path, "..") {
		return true
	}
	return false
}

// suspiciousTempPath reports whether an exec event is a temp-path exec and
// returns the operator-friendly path string for the finding's description.
// Two recognised shapes:
//
//  1. Binary stage-2: payload.path itself is under a temp prefix (the
//     classic Mach-O dropper). Returned path is just the binary path.
//  2. Shebang stage-2: payload.path is a shell (the kernel resolved
//     `#!/bin/sh` for us) and the first non-flag argv[1+] is a temp-path
//     script. Returned path renders as `<shell> <script>` so the
//     analyst sees what the shell was actually told to run.
//
// `sh -c <command>` deliberately does NOT count as shebang: the kernel
// rejects multi-token shebang lines, so any argv with `-c` was injected
// by a caller (typically a parent shell wrapper) and the next argv slot
// is a command string, not a path. shebangShellPaths is defined in
// osascript_network_exec.go since both rules share the recognition logic.
func suspiciousTempPath(p execPayload) (string, bool) {
	if isSuspiciousPath(p.Path) {
		return p.Path, true
	}
	if !shebangShellPaths[p.Path] {
		return "", false
	}
	for i := 1; i < len(p.Args); i++ {
		a := p.Args[i]
		if a == "-c" {
			// `sh -c <command>` — argv[i+1] is a command string, not a
			// script path. This argv shape is not a shebang invocation.
			return "", false
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if isSuspiciousPath(a) {
			return fmt.Sprintf("%s %s", p.Path, a), true
		}
		return "", false
	}
	return "", false
}
