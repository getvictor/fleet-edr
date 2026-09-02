package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
)

// shellPaths is the shared unix_shells list (pack/lists.yml). Shared rather than a param of this rule because shell_from_office
// matches against the same set; one definition read by both cannot drift (issue #759).
var shellPaths = sync.OnceValue(func() map[string]bool { return sharedSet("unix_shells") })

// suspiciousPrefixes is the shared world_writable_prefixes list (pack/lists.yml). Read through isSuspiciousPath by three rules
// (this one, dns_c2_beacon and osascript_network_exec), which is why it is a shared list rather than any rule's param.
var suspiciousPrefixes = sync.OnceValue(func() []string { return sharedList("world_writable_prefixes") })

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

// AlgorithmName names the evaluator that decides this rule, for the exported rule file (issue #757). Walks the ancestor chain for a shell
// under a non-shell parent, then matches the trigger against world-writable path prefixes, following the re-exec chain so a shell that
// exec'd its payload in place is still found.
func (r *SuspiciousExec) AlgorithmName() string { return "ancestor_walk_path_prefix" }

// SupportedExclusionMatchTypes lists the match types parentExcluded consults: the non-shell parent's path glob plus its code-signing
// identity (team_id / signing_id / cdhash), so an operator can exclude a benign signed parent (e.g. a Developer-ID developer tool) by
// its non-spoofable signature rather than a path glob a writable-directory attacker can land inside (issue #520).
func (r *SuspiciousExec) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{
		api.ExclusionMatchParentPathGlob,
		api.ExclusionMatchTeamID,
		api.ExclusionMatchSigningID,
		api.ExclusionMatchCDHash,
	}
}

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519). Both trigger arms (the
// temp-path exec and the outbound network_connect) emit this one title; which arm fired lives in the finding Description, so the
// alert maps 1:1 to the one rule an operator can look up (SIEM/Sigma catalog convention) rather than forking into two titles.
func (r *SuspiciousExec) DisplayName() string { return "Suspicious exec chain" }

// exclusionResolver and window satisfy shellChainRule, which is how the shared ancestor walk in shellchain.go reaches this rule's
// resolver and its own tuning. Keyed on this rule's id, so the exclusions operators saved before issue #776 split the rules keep
// applying to this arm and do not leak onto shell_network_connect.
func (r *SuspiciousExec) exclusionResolver() api.ExclusionResolver { return r.Exclusions }

func (r *SuspiciousExec) window() int64 { return suspiciousExecWindow() }

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1059
// (Command and Scripting Interpreter) + T1105 (Ingress Tool Transfer).
func (r *SuspiciousExec) Techniques() []string {
	return []string{"T1059", "T1105"}
}

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *SuspiciousExec) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags a non-shell process that spawns a shell which, within 30 seconds, execs a binary from a world-writable directory.",
		Description: "Detects the chain shape: non-shell parent → shell child → temp-directory exec (e.g. `/tmp/payload`).\n\n" +
			"The rule fires on the LAST link of the chain (the temp exec) rather than the shell's exec. That makes it " +
			"race-immune across the agent's flush boundaries: a chain that completes in ~150ms but straddles a 1-second " +
			"flush boundary still resolves cleanly because the entire ancestor chain has already been ingested by the " +
			"time the trigger event lands.\n\n" +
			"Until issue #776 this rule also fired on the same chain making an outbound connection. That shape is now " +
			"`shell_network_connect`, which ships in monitor: a chain doing both raises one alert here and records a match " +
			"there, and raises one alert per rule once that rule is promoted.\n\n" +
			"30 seconds is the temporal cap between the shell exec and the temp exec.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"exec"},
		FalsePositives: []string{
			"Interactive SSH where an admin runs a script from /tmp. Add a parent-path-glob exclusion for `/usr/libexec/sshd-session` via the detection-config surface if that's a routine workflow on the host class.",
			"Developer tooling that shells out to a versioned install (Claude Code, lefthook git hooks, git, IDEs). These install under version-stamped paths, so add a parent-path-glob exclusion such as `*/claude/versions/*` or `*/lefthook_*` that survives upgrades.",
			"Some Apple-signed installer-postflight scripts shell out to /tmp/ during package install.",
		},
		Limitations: []string{
			"The window bounds how long after the shell exec a temp exec still counts; long-tail post-shell activity is missed by design. Set in x-engine.params.window.",
			"Exclusions are keyed by rule id, so one saved here does not silence `shell_network_connect` on the same parent, and vice versa. Before issue #776 split the rules, a single exclusion silenced both shapes.",
		},
	}
}

const (

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

func (r *SuspiciousExec) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	seenShell := map[int]struct{}{}
	var findings []api.Finding
	// One event whose process row is still missing defers the batch without ending the pass, so it cannot mask a finding another
	// event in the same batch would produce (issue #661).
	var miss pendingMiss

	// One pass. This was two until issue #776, the second handling outbound connections as a fallback so that a shell exhibiting
	// both signals produced the path-based finding rather than whichever event happened to arrive first. That precedence lived in
	// a seenShell shared across the passes, and it is exactly what the split gives up: shell_network_connect now owns the connect
	// shape and carries its own dedup, so a chain doing both raises one alert per rule.
	for _, evt := range events {
		if evt.EventType != "exec" {
			continue
		}
		f, shellPID, err := r.evalExec(ctx, evt, s, events, seenShell)
		if fatal := miss.absorb(err); fatal != nil {
			return nil, fatal
		}
		if f != nil {
			findings = append(findings, *f)
			seenShell[shellPID] = struct{}{}
		}
	}
	return findings, miss.err
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
	tempProc, err := resolveSubjectProcess(ctx, s, evt, p.PID)
	if err != nil {
		return nil, 0, err
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
// the loop's first check is `shellPaths()[..]` which is false for the temp-binary, so it trivially advances to PPID on the next step.
func (r *SuspiciousExec) evalExecArm1(
	ctx context.Context, s api.GraphReader, in *execMatchInputs,
) (*api.Finding, int, error) {
	shell, parent, err := findShellWithNonShellAncestor(ctx, s, in.evt.HostID, in.p.PID, in.evt.TimestampNs)
	if err != nil {
		return nil, 0, err
	}
	if shell == nil {
		return nil, 0, nil
	}
	if !shouldFire(r, in.seenShell, shell, parent, in.evt.TimestampNs, in.evt.HostID) {
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
	// One walk, shared with the outbound-connect rule (issue #829). This used to be a second copy, and the copies had diverged in
	// two ways that both mattered.
	//
	// It walked the chain OLDEST-first. For `zsh -c 'bash -c "..."'`, where both shells exec in place at one PID, the oldest
	// generation is the one most likely to sit outside the window, so the arm gave up on a chain whose newer shell would have
	// matched. And it fired on a shell whose parent was absent from the graph, producing an alert whose parent reads "(unknown)":
	// a parent exclusion matches on the parent's PATH, so an operator who had correctly configured one still received that alert,
	// every time, with no way to suppress it short of disabling the rule.
	//
	// The shared walk takes the newest suitable generation and defers on incomplete ancestry. Both changes are the connect arm's
	// existing behaviour; this arm simply stops disagreeing with it.
	prior, priorParent, err := findShellOnExecChain(ctx, s, in.evt.HostID, in.tempProc)
	if err != nil {
		return nil, 0, err
	}
	if prior == nil {
		return nil, 0, nil
	}
	if !shouldFire(r, in.seenShell, prior, priorParent, in.evt.TimestampNs, in.evt.HostID) {
		return nil, 0, nil
	}
	return r.makeExecFinding(in.evt, priorParent, prior, in.tempProc, in.tempPath, in.batch), prior.PID, nil
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
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("%s → %s → %s", parentPath, shell.Path, tempPath),
		ProcessID:   tempProc.ID,
		EventIDs:    eventIDs,
	}
}

func isSuspiciousPath(path string) bool {
	for _, prefix := range suspiciousPrefixes() {
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
	if !shebangShellPaths()[p.Path] {
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

// suspiciousExecWindow is the shell-to-trigger bound, from the rule's pack file (issue #758). The shell and world-writable-prefix
// sets this rule also matches against are shared with other rules and so live in pack/lists.yml rather than in this rule's params.
var suspiciousExecWindow = sync.OnceValue(func() int64 {
	return paramsFor("suspicious_exec").Duration("window").Nanoseconds()
})
