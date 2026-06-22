package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/fleetdm/edr/server/rules/api"
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
// exec event. Forward-direction triggering (fire when the shell exec is
// seen, then look forward for descendants) is unreliable in production
// because the processor pipeline runs `builder.ProcessBatch` then
// `detection.Evaluate` per agent POST and the agent flushes events in
// roughly 1-second batches. A real chain completes in ~150ms, so when the
// cadence boundary lands mid-chain the shell exec arrives in batch N while
// the temp-binary exec arrives in batch N+1. At batch N's Evaluate the
// descendants haven't been materialised, and the shell event isn't in
// batch N+1 to re-trigger evaluation. Reverse-direction triggering is
// race-immune because by the time the trigger event lands, every ancestor
// (the shell, the non-shell that spawned it) has already been ingested
// and materialised by an earlier batch.
//
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1204 (User Execution).
type SuspiciousExec struct {
	// Exclusions is the per-host false-positive resolver. The rule consults it (match type parent_path_glob, value = the non-shell
	// parent path) before firing on EITHER arm, so a trusted parent like `/usr/libexec/sshd-session` or a version-stamped developer
	// tool (`*/claude/versions/*`) is suppressed. Nil excludes nothing (the empty-config default). The both-arms trade-off and the
	// over-broad-glob caveat (`*/git` would also match `/tmp/evil/git`) are documented on the detection-config surface (issue #459).
	Exclusions api.ExclusionResolver
}

func (r *SuspiciousExec) ID() string { return "suspicious_exec" }

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1059
// (Command and Scripting Interpreter) + T1105 (Ingress Tool Transfer).
func (r *SuspiciousExec) Techniques() []string {
	return []string{"T1059", "T1105"}
}

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *SuspiciousExec) Doc() api.Documentation {
	return api.Documentation{
		Title:   "Suspicious exec chain (non-shell → shell → temp/network)",
		Summary: "Flags a non-shell process that spawns a shell which, within 30 seconds, execs from /tmp or makes an outbound network connection.",
		Description: "Detects two related chain shapes that share a single attribution chain:\n\n" +
			"1. non-shell parent → shell child → temp-directory exec (e.g. `/tmp/payload`)\n" +
			"2. non-shell parent → shell child → outbound network_connect\n\n" +
			"The rule fires on the LAST link of the chain (the temp-exec or the network_connect) rather than the " +
			"shell's exec. That makes it race-immune across the agent's flush boundaries: a chain that completes " +
			"in ~150ms but straddles a 1-second flush boundary still resolves cleanly because the entire ancestor " +
			"chain has already been ingested by the time the trigger event lands.\n\n" +
			"30 seconds is the temporal cap between the shell exec and the trigger event.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"exec", "network_connect"},
		FalsePositives: []string{
			"Interactive SSH where an admin runs a script from /tmp and/or curls a tool. Add a parent-path-glob exclusion for `/usr/libexec/sshd-session` via the detection-config surface if that's a routine workflow on the host class.",
			"Developer tooling that shells out and connects (Claude Code, lefthook git hooks, git, IDEs). These install under version-stamped paths, so add a parent-path-glob exclusion such as `*/claude/versions/*` or `*/lefthook_*` that survives upgrades.",
			"Some Apple-signed installer-postflight scripts shell out to /tmp/ during package install.",
		},
		Limitations: []string{
			"30s window is hard-coded; long-tail post-shell activity is missed by design.",
			"A parent-path-glob exclusion silences BOTH arms of the rule for that parent.",
			"An outbound DNS lookup (port 53) to a local-resolver-class address (loopback, RFC1918, link-local, CGNAT 100.64.0.0/10, IPv6 ULA/link-local) is treated as name resolution and does not trigger the network arm; a DNS lookup to a publicly routable resolver still fires.",
		},
	}
}

const (
	// suspiciousExecWindowNs bounds the temporal distance between the shell exec and the trigger event (temp-exec or network_connect).
	// Real chains complete in seconds; 30s is a generous ceiling that matches the original forward-direction rule.
	suspiciousExecWindowNs = int64(30_000_000_000)

	// maxSuspiciousAncestorWalkSteps caps the parent-chain traversal so a pathological process tree (or a malformed event with
	// self-referential ppid) can't loop. Real chains go non-shell -> shell -> temp, and shell-to-shell layering rarely exceeds two or
	// three hops.
	maxSuspiciousAncestorWalkSteps = 16
)

// execPayload is the subset of exec event payload fields needed for detection. Args carries argv so the rule can detect shebang-shell
// execs where the kernel resolves `#!/bin/sh` to /bin/sh and the actual script path lives in argv[1]. The rule must consider those
// temp-path execs even though the exec event's `path` field is /bin/sh, not /tmp/whatever.
type execPayload struct {
	PID  int      `json:"pid"`
	PPID int      `json:"ppid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

// networkConnectPayload is the subset of network_connect event fields needed for detection. PID identifies the process making the
// connection. The rule walks UP from there looking for a shell ancestor with a non-shell parent.
type networkConnectPayload struct {
	PID           int    `json:"pid"`
	Direction     string `json:"direction"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
	// PIDVersion is the source process's kernel PID generation (audit_token_to_pidversion), when the agent provided it. Lets a
	// correlation rule resolve the connecting process by exact (host, pid, pidversion) identity instead of a time window. Nil for
	// legacy agents or flows whose audit token was unavailable (issue #403).
	PIDVersion *uint32 `json:"pidversion"`
}

func (r *SuspiciousExec) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	// Two-pass evaluation. Pass 1 handles temp-exec triggers (preferred); Pass 2 handles outbound network_connect triggers as a fallback.
	// Splitting the passes preserves the original rule's "prefer the path-based finding when both signals exist for the same shell"
	// semantics, which would otherwise be order-dependent on event arrival within a single pass.
	seenShell := map[int]struct{}{}
	var findings []api.Finding

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

// findShellExecEventID scans the current batch for an exec event matching the shell's PID and host so the finding's EventIDs can
// include the shell-stage event when it happens to be in the same batch as the trigger. Best-effort: when the shell exec is in an
// earlier batch it isn't findable here and EventIDs simply omits it. The trigger's own event ID is excluded to avoid duplicates in the
// arm-2 (re-exec) case where shell and temp share a PID.
func findShellExecEventID(events []api.Event, hostID string, shellPID int, excludeEventID string) string {
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

// evalExec inspects a single exec event. Returns (finding, shellPID, err) on a match. The shellPID is the PID of the attributed shell
// ancestor. The caller uses it for batch-level dedupe so multiple temp-exec children of one shell produce one finding rather than one
// per child.
func (r *SuspiciousExec) evalExec(
	ctx context.Context, evt api.Event, s api.GraphReader, batch []api.Event, seenShell map[int]struct{},
) (*api.Finding, int, error) {
	var p execPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return nil, 0, nil
	}
	tempPath, ok := suspiciousTempPath(p)
	if !ok {
		return nil, 0, nil
	}

	// We need the temp-exec process record either way: for the finding's
	// ProcessID link, and (in the arm-2 case) to walk its re-exec chain.
	tempProc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return nil, 0, fmt.Errorf("get temp-exec pid %d: %w", p.PID, err)
	}
	if tempProc == nil {
		return nil, 0, nil
	}

	in := &execMatchInputs{
		evt: evt, batch: batch, seenShell: seenShell, p: p,
		tempProc: tempProc, tempPath: tempPath,
	}
	if f, shellPID, err := r.evalExecArm1(ctx, s, in); err != nil || f != nil {
		return f, shellPID, err
	}
	return r.evalExecArm2(ctx, s, in)
}

// execMatchInputs bundles the per-event evaluation state shared by both exec arms. Sonar's go:S107 caps function signatures at 7
// parameters; passing these through individually pushed both arms over the limit. Bundling reads cleaner anyway: every field below is
// "inputs about this single exec event" and they always travel together.
type execMatchInputs struct {
	evt       api.Event
	batch     []api.Event
	seenShell map[int]struct{}
	p         execPayload
	tempProc  *api.Process
	tempPath  string
}

// evalExecArm1 handles the canonical fork+exec dropper shape: the temp-binary is a SEPARATE process from the shell, so the shell
// sits at the temp-binary's PPID (or higher, through possible shell-to-shell layering). The walk starts at the temp-exec's own PID;
// the loop's first check is `shellPaths[..]` which is false for the temp-binary, so it trivially advances to PPID on the next step.
func (r *SuspiciousExec) evalExecArm1(
	ctx context.Context, s api.GraphReader, in *execMatchInputs,
) (*api.Finding, int, error) {
	shell, parent, err := r.findShellWithNonShellAncestor(ctx, s, in.evt.HostID, in.p.PID, in.evt.TimestampNs)
	if err != nil {
		return nil, 0, err
	}
	if shell == nil {
		return nil, 0, nil
	}
	if !r.shouldFire(in.seenShell, shell, parent, in.evt.TimestampNs, in.evt.HostID) {
		return nil, 0, nil
	}
	return r.makeExecFinding(in.evt, parent, shell, in.tempProc, in.tempPath, in.batch), shell.PID, nil
}

// evalExecArm2 handles the same-PID re-exec optimisation. `sh -c "/tmp/foo"` is commonly implemented by execve(/tmp/foo) at the
// shell's PID, leaving no fork boundary between the shell and the payload. The latest exec record at this PID is /tmp/foo (which
// is what got us here); the shell stage is reachable via the previous_exec_id chain. Without this branch the PPID walk above misses
// re-exec chains entirely because temp.PPID is the shell's parent (a non-shell) and the shell itself is on the re-exec history of the
// same PID, not in the parent chain.
func (r *SuspiciousExec) evalExecArm2(
	ctx context.Context, s api.GraphReader, in *execMatchInputs,
) (*api.Finding, int, error) {
	chain, err := s.GetExecChain(ctx, *in.tempProc)
	if err != nil {
		return nil, 0, fmt.Errorf("walk exec chain pid %d: %w", in.p.PID, err)
	}
	for i := range chain {
		prior := &chain[i]
		if !shellPaths[prior.Path] {
			continue
		}
		priorParent, err := r.lookupAncestor(ctx, s, in.evt.HostID, prior.PPID, in.evt.TimestampNs)
		if err != nil {
			return nil, 0, err
		}
		if priorParent != nil && shellPaths[priorParent.Path] {
			continue
		}
		if !r.shouldFire(in.seenShell, prior, priorParent, in.evt.TimestampNs, in.evt.HostID) {
			return nil, 0, nil
		}
		return r.makeExecFinding(in.evt, priorParent, prior, in.tempProc, in.tempPath, in.batch), prior.PID, nil
	}
	return nil, 0, nil
}

// shouldFire is the common gate shared by both exec arms (and evalNetwork): a candidate shell only produces a finding when (a) we
// haven't already fired on it in this batch, (b) the trigger event falls within the shell's 30-second window, and (c) the shell's
// non-shell parent isn't excluded for hostID. Returning false means "skip this candidate, continue / give up"; the callers handle
// the `nil, 0, nil` reply.
func (r *SuspiciousExec) shouldFire(
	seenShell map[int]struct{}, shell, parent *api.Process, triggerTS int64, hostID string,
) bool {
	if _, dupe := seenShell[shell.PID]; dupe {
		return false
	}
	if !shellWithinWindow(shell, triggerTS) {
		return false
	}
	if r.parentExcluded(parent, hostID) {
		return false
	}
	return true
}

// evalNetwork inspects an outbound network_connect event and walks UP from the connecting process looking for a shell ancestor whose
// parent is non-shell. The connecting process itself can be the shell (curl|sh case) or any descendant of it (shell spawned curl);
// the inclusive walk handles both.
func (r *SuspiciousExec) evalNetwork(
	ctx context.Context, evt api.Event, s api.GraphReader, batch []api.Event, seenShell map[int]struct{},
) (*api.Finding, int, error) {
	var c networkConnectPayload
	if err := json.Unmarshal(evt.Payload, &c); err != nil {
		return nil, 0, nil
	}
	if c.Direction != "outbound" {
		return nil, 0, nil
	}
	// DNS de-noising: a name-resolution lookup to the host's own resolver is not a meaningful "outbound network connection"
	// for this rule. The meaningful signal is the connection to the RESOLVED address that follows, which this arm still sees.
	// Gate on destination CLASS (port 53 to a local-resolver-class address), never on a specific resolver IP, so a DNS query to
	// a publicly routable resolver on :53 (potential DNS tunnelling) still fires. Arm-scoped: the temp-exec arm is untouched.
	if isLocalResolverDest(c.RemoteAddress, c.RemotePort) {
		return nil, 0, nil
	}
	shell, parent, err := r.findShellWithNonShellAncestor(ctx, s, evt.HostID, c.PID, evt.TimestampNs)
	if err != nil {
		return nil, 0, err
	}
	if shell == nil {
		return nil, 0, nil
	}
	if !r.shouldFire(seenShell, shell, parent, evt.TimestampNs, evt.HostID) {
		return nil, 0, nil
	}

	// Resolve the connecting process so the finding links there rather than at the shell. That's what an analyst clicking the
	// alert wants to land on. Prefer exact (host, pid, pidversion) identity when the flow carried a pidversion so the finding
	// attributes to the right generation across PID reuse, falling back to the event-time window otherwise (issue #403). The
	// ancestor walk above still uses the window for shell/parent generations; making parent edges identity-aware is out of scope.
	conn, err := resolveFlowProcess(ctx, s, evt.HostID, c.PID, c.PIDVersion, evt.TimestampNs)
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
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       "Shell spawn with outbound network connection",
		Description: fmt.Sprintf("%s → %s → outbound %s:%d", parentPath, shell.Path, c.RemoteAddress, c.RemotePort),
		ProcessID:   conn.ID,
		EventIDs:    eventIDs,
	}, shell.PID, nil
}

// findShellWithNonShellAncestor walks the PPID chain inclusively starting at
// startPID looking for a shell process whose own parent is non-shell. Returns
// the matched shell and its non-shell parent. The parent return value is nil
// only when the shell's parent is launchd (PPID <= 1): that still counts as
// a match because launchd is structurally non-shell. PPID > 1 with a missing
// parent record means "ancestry incomplete, defer rather than fire". This
// keeps the rule from alerting on partial data and, in particular, keeps the
// parent exclusion effective when the entry-point process
// hasn't been materialised yet.
//
// The walk is "inclusive": startPID itself is the first candidate. Callers
// that pass the temp-exec's own PID get the trivial first-iteration skip
// (temp-binary fails shellPaths) and the walk proceeds to the actual
// candidate parent on the next step.
func (r *SuspiciousExec) findShellWithNonShellAncestor(
	ctx context.Context, s api.GraphReader, hostID string, startPID int, asOfNs int64,
) (*api.Process, *api.Process, error) {
	current, err := s.GetProcessByPID(ctx, hostID, startPID, asOfNs)
	if err != nil {
		return nil, nil, fmt.Errorf("get pid %d: %w", startPID, err)
	}
	for steps := 0; current != nil && steps < maxSuspiciousAncestorWalkSteps; steps++ {
		shell, parent, advance, err := r.examineCandidate(ctx, s, hostID, current, asOfNs)
		if err != nil {
			return nil, nil, err
		}
		if shell != nil {
			return shell, parent, nil
		}
		if advance == nil {
			return nil, nil, nil
		}
		current = advance
	}
	return nil, nil, nil
}

// examineCandidate is the per-step decision for findShellWithNonShellAncestor.
// It returns one of three terminal shapes:
//
//   - (shell, parent, nil, nil) means match: `current` is a shell whose own
//     parent is non-shell (parent==nil means "shell parented at launchd",
//     which counts as a match).
//   - (nil, nil, advance, nil) means keep walking; `advance` is the next
//     ancestor to examine.
//   - (nil, nil, nil, nil) means terminate without a match: ran out of
//     ancestry (PPID<=1 with no shell yet) or the parent record is
//     missing (defer rather than alert on incomplete data).
//
// Splitting this out keeps findShellWithNonShellAncestor's loop body small
// enough that gocognit / Sonar's cognitive-complexity gates stay green.
func (r *SuspiciousExec) examineCandidate(
	ctx context.Context, s api.GraphReader, hostID string, current *api.Process, asOfNs int64,
) (shell, parent, advance *api.Process, err error) {
	if !shellPaths[current.Path] {
		// Not a shell. Walk up if there's an ancestor to walk to.
		if current.PPID <= 1 {
			return nil, nil, nil, nil
		}
		next, err := s.GetProcessByPID(ctx, hostID, current.PPID, asOfNs)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("get ppid %d: %w", current.PPID, err)
		}
		return nil, nil, next, nil
	}
	// `current` is a shell. Distinguish "launchd parent" (match) from "parent record missing" (defer) from "non-shell parent" (match) from
	// "shell parent" (continue walking up).
	if current.PPID <= 1 {
		return current, nil, nil, nil
	}
	candidate, err := s.GetProcessByPID(ctx, hostID, current.PPID, asOfNs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get ppid %d: %w", current.PPID, err)
	}
	if candidate == nil {
		return nil, nil, nil, nil
	}
	if !shellPaths[candidate.Path] {
		return current, candidate, nil, nil
	}
	// Shell-to-shell layering (sudo bash, su -c bash, ...). Keep climbing.
	return nil, nil, candidate, nil
}

// lookupAncestor returns nil for PIDs at or below launchd (PPID 1) and
// passes through to GetProcessByPID otherwise.
func (r *SuspiciousExec) lookupAncestor(
	ctx context.Context, s api.GraphReader, hostID string, pid int, asOfNs int64,
) (*api.Process, error) {
	if pid <= 1 {
		return nil, nil
	}
	p, err := s.GetProcessByPID(ctx, hostID, pid, asOfNs)
	if err != nil {
		return nil, fmt.Errorf("get pid %d: %w", pid, err)
	}
	return p, nil
}

// shellWithinWindow reports whether the trigger event's timestamp falls within the 30-second window after the shell's exec. Anchored
// on the shell's exec_time_ns when set (preferred: that's the kernel's actual exec moment) and falls back to fork_time_ns otherwise
// (defensive: should always be set for a fully-materialised process).
func shellWithinWindow(shell *api.Process, triggerTS int64) bool {
	anchor := shell.ForkTimeNs
	if shell.ExecTimeNs != nil {
		anchor = *shell.ExecTimeNs
	}
	return triggerTS >= anchor && triggerTS <= anchor+suspiciousExecWindowNs
}

// makeExecFinding builds the temp-path finding shared by arm 1 and arm 2. In the arm-2 re-exec case tempProc and shell share a PID;
// the finding still links to tempProc so the analyst lands on the temp-stage record (the re-exec'd row), not the earlier shell-stage
// row.
func (r *SuspiciousExec) makeExecFinding(
	evt api.Event, parent, shell, tempProc *api.Process, tempPath string, batch []api.Event,
) *api.Finding {
	parentPath := "(unknown)"
	if parent != nil {
		parentPath = parent.Path
	}
	eventIDs := []string{evt.EventID}
	if shellEventID := findShellExecEventID(batch, evt.HostID, shell.PID, evt.EventID); shellEventID != "" {
		eventIDs = append([]string{shellEventID}, eventIDs...)
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       "Suspicious exec from temp path",
		Description: fmt.Sprintf("%s → %s → %s", parentPath, shell.Path, tempPath),
		ProcessID:   tempProc.ID,
		EventIDs:    eventIDs,
	}
}

// parentExcluded reports whether the given non-shell parent process is excluded for hostID (match type parent_path_glob, value = the
// parent path). A nil parent (shell parented at launchd, or parent not yet materialised) never matches: those are the cases the rule
// must continue to flag because there's no human-attested entry point. Glob semantics live in the resolver (api.GlobMatch).
func (r *SuspiciousExec) parentExcluded(parent *api.Process, hostID string) bool {
	if r.Exclusions == nil || parent == nil {
		return false
	}
	return r.Exclusions.Excluded(r.ID(), api.ExclusionMatchParentPathGlob, parent.Path, hostID)
}

// dnsPort is the well-known DNS port. An outbound connection to it to a local-resolver-class address is name resolution against the
// host's own resolver, which the network arm de-noises (see isLocalResolverDest).
const dnsPort = 53

// cgnatPrefix is the RFC 6598 carrier-grade-NAT shared address space (100.64.0.0/10). netip.Addr.IsPrivate does NOT cover it (it is
// RFC1918 + IPv6 ULA only), but it is not publicly routable, and Tailscale's MagicDNS resolver lives at 100.100.100.100 inside it, so a
// local-resolver classifier must include it explicitly. MustParsePrefix on a constant literal cannot fail.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isLocalResolverDest reports whether an outbound connection targets the host's own DNS resolver: port 53 to a local-resolver-class
// address. Such a lookup is not a meaningful "outbound network connection" for suspicious_exec; the connection to the resolved address
// that follows is what the rule cares about. A connection to port 53 at a publicly routable address is NOT local-resolver traffic and
// stays eligible to trigger (it can be DNS tunnelling to an external resolver).
func isLocalResolverDest(remoteAddress string, remotePort int) bool {
	return remotePort == dnsPort && isLocalResolverIP(remoteAddress)
}

// isLocalResolverIP reports whether addr parses as a non-publicly-routable address of the class a host's local resolver uses: loopback,
// RFC1918 private (and IPv6 ULA, both via IsPrivate), IPv4/IPv6 link-local, or the CGNAT range Tailscale MagicDNS occupies. A value
// that does not parse as an IP (a hostname, an empty string) is not classifiable as local and returns false so the rule still fires.
//
// netip.ParseAddr (not net.ParseIP) is deliberate: the agent's network telemetry carries scoped IPv6 literals with a zone suffix
// (e.g. `fe80::1%en0`, present in the demo corpus for mDNS on :53), which net.ParseIP rejects but netip.ParseAddr accepts. Without zone
// support those link-local DNS lookups would slip past the de-noiser and re-fire the network arm. The CGNAT membership test is IPv4
// only, so a zoned IPv6 address never reaches it; the link-local branch covers the zoned case.
func isLocalResolverIP(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		cgnatPrefix.Contains(ip)
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
			// `sh -c <command>`: argv[i+1] is a command string, not a
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
