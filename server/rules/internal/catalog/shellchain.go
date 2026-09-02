// Shared ancestor-walk machinery for the two rules that key on a shell running under a non-shell parent: suspicious_exec (the
// temp-path arm) and shell_network_connect (the outbound-connection arm).
//
// Issue #776 split those arms into separate rules so each can be tuned, promoted and silenced on its own. It deliberately did NOT
// split this code: both arms answer the same question, "is there a shell in this process's ancestry, under a non-shell parent,
// within the window", and two copies of a graph walk would drift. #713 is what that drift looks like in practice: the exec-chain
// walk existed on one arm and not the other, and a `zsh -c 'curl ...'` payload was invisible for it.
//
// The helpers are free functions over shellChainRule rather than methods on a shared struct because both rule types are used as
// their zero value in forty-odd places, and embedding a struct that needs a rule id and a window would have broken every one.
package catalog

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fleetdm/edr/server/rules/api"
)

// shellChainRule is what the shared walk needs from whichever rule is driving it: an identity to key exclusions on, the resolver
// to consult, and that rule's own window. Each is per-rule on purpose. Keying exclusions on the caller's id is what lets
// suspicious_exec keep the exclusions operators already saved while shell_network_connect starts unfiltered (issue #776), and the
// separate windows are the independent tuning the split exists to allow.
type shellChainRule interface {
	ID() string
	exclusionResolver() api.ExclusionResolver
	window() int64
}

// shouldFire is the common gate shared by both exec arms (and evalNetwork): a candidate shell only produces a finding when (a) we
// haven't already fired on it in this batch, (b) the trigger event falls within the shell's 30-second window, and (c) the shell's
// non-shell parent isn't excluded for hostID. Returning false means "skip this candidate, continue / give up"; the callers handle
// the `nil, 0, nil` reply.
func shouldFire(
	r shellChainRule, seenShell map[int]struct{}, shell, parent *api.Process, triggerTS int64, hostID string,
) bool {
	if _, dupe := seenShell[shell.PID]; dupe {
		return false
	}
	if !shellWithinWindow(r, shell, triggerTS) {
		return false
	}
	if parentExcluded(r, parent, hostID) {
		return false
	}
	return true
}

// findShellOnExecChain looks for the shell on the connecting PID's own exec chain, which is where it lives when the shell exec'd its
// payload in place rather than forking it. It is the network arm's counterpart to evalExecArm2, and its absence was issue #713.
//
// A same-PID re-exec closes the prior generation (insertReExec stamps its exit at the re-exec instant), and GetProcessByPID brackets
// on that exit, so at the flow's timestamp the shell generation is simply not visible by PID. The PPID walk therefore steps straight
// past it to whatever is above, usually the interactive login shell, whose own exec is minutes or hours old and so fails the window.
// The rule then reported nothing, and which shell the attacker picked decided whether the payload was seen at all: measured on macOS
// 26.6.1, zsh replaces itself with the payload while bash and sh fork it, so `zsh -c 'curl ...'` was invisible and the identical bash
// form was detected.
//
// The chain is nil for a PID that never re-exec'd, which is nearly all of them, so this costs a field check on the hot path and
// only walks where a chain exists.
// The third return distinguishes "no shell on this chain" from "a shell was there and was declined because its parent had no
// record". Only the caller knows which rule it is speaking for, so the reason is reported rather than counted here, which also
// keeps this walk free of any observability dependency.
func findShellOnExecChain(
	ctx context.Context, s api.GraphReader, hostID string, conn *api.Process,
) (shell, parent *api.Process, incompleteAncestry bool, err error) {
	chain, err := s.GetExecChain(ctx, *conn)
	if err != nil {
		return nil, nil, false, fmt.Errorf("walk exec chain pid %d: %w", conn.PID, err)
	}
	// A PID that never re-exec'd has no chain, which is nearly all of them, so this is the hot path and it exits here.
	if len(chain) == 0 {
		return nil, nil, false, nil
	}
	// Newest generation first. GetExecChain returns the chain OLDEST-first (it recurses backwards through previous_exec_id and
	// orders by descending depth), and the shell that ran this payload is the one closest to it, not the first one this PID ever
	// held. Walking forward would hand back the stalest shell in the chain, and for `zsh -c 'bash -c "curl ..."'`, where both
	// shells exec in place at one PID, that is the one most likely to fail the window and drop the alert.
	for i := len(chain) - 1; i >= 0; i-- {
		prior := &chain[i]
		if !shellPaths()[prior.Path] {
			continue
		}
		// lookupParentOf, not lookupAncestor at the trigger timestamp. Its own doc a few functions below states the invariant
		// this used to break: a parent edge has an answer only at the instant the child forked, and resolving it at "the
		// timestamp of a network flow made much later by a descendant" asks who holds that PID NOW. If the real parent exited
		// and its PID was reused before the connection, the old form attributed the chain to the unrelated replacement.
		priorParent, err := lookupParentOf(ctx, s, hostID, prior)
		if err != nil {
			return nil, nil, false, err
		}
		// Ancestry incomplete: the shell claims a parent with no record, so report nothing. Firing here would produce a finding
		// whose parent reads "(unknown)", and an operator's parent exclusion cannot suppress a parent that was never resolved, so
		// the alert would recur past a rule they had deliberately configured, with no way to silence it short of disabling the
		// rule. Giving up this one class of chain keeps the rest tunable.
		//
		// This DROPS the chain; it does not defer it. Ancestor and parent-chain lookups keep skip semantics by design (the
		// canonical retry contract covers the pid an event is ABOUT, not its ancestry), so returning nil here acknowledges the
		// batch and no later parent record brings the detection back. Earlier wording here said "defer", which read as
		// recoverable and is not (issue #829 review). A shell parented at launchd (PPID <= 1) is a genuine no-parent case rather
		// than a missing record, and still counts.
		if priorParent == nil && prior.PPID > 1 {
			return nil, nil, true, nil
		}
		// A shell whose own parent is a shell is shell-to-shell layering, not the boundary this rule fires on; keep walking the
		// chain for one whose parent is not a shell, exactly as the exec arm does.
		if priorParent != nil && shellPaths()[priorParent.Path] {
			continue
		}
		return prior, priorParent, false, nil
	}
	return nil, nil, false, nil
}

// findShellWithNonShellAncestor walks the PPID chain inclusively starting at
// startPID looking for a shell process whose own parent is non-shell. Returns
// the matched shell and its non-shell parent. The parent return value is nil
// only when the shell's parent is launchd (PPID <= 1): that still counts as
// a match because launchd is structurally non-shell. PPID > 1 with a missing
// parent record means "ancestry incomplete, report nothing". This
// keeps the rule from alerting on partial data and, in particular, keeps the
// parent exclusion effective when the entry-point process
// hasn't been materialised yet.
//
// The walk is "inclusive": startPID itself is the first candidate. Callers
// that pass the temp-exec's own PID get the trivial first-iteration skip
// (temp-binary fails shellPaths) and the walk proceeds to the actual
// candidate parent on the next step.
func findShellWithNonShellAncestor(
	ctx context.Context, s api.GraphReader, hostID string, startPID int, asOfNs int64,
) (*api.Process, *api.Process, error) {
	current, err := s.GetProcessByPID(ctx, hostID, startPID, asOfNs)
	if err != nil {
		return nil, nil, fmt.Errorf("get pid %d: %w", startPID, err)
	}
	return findShellFromResolvedProcess(ctx, s, hostID, current)
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
//     missing (report nothing rather than alert on incomplete data).
//
// Splitting this out keeps findShellWithNonShellAncestor's loop body small
// enough that gocognit / Sonar's cognitive-complexity gates stay green.
func examineCandidate(
	ctx context.Context, s api.GraphReader, hostID string, current *api.Process,
) (shell, parent, advance *api.Process, err error) {
	if !shellPaths()[current.Path] {
		// Not a shell. Walk up if there's an ancestor to walk to.
		if current.PPID <= 1 {
			return nil, nil, nil, nil
		}
		next, err := lookupParentOf(ctx, s, hostID, current)
		if err != nil {
			return nil, nil, nil, err
		}
		return nil, nil, next, nil
	}
	// `current` is a shell. Distinguish "launchd parent" (match) from "parent record missing" (no report) from "non-shell parent" (match) from
	// "shell parent" (continue walking up).
	if current.PPID <= 1 {
		return current, nil, nil, nil
	}
	candidate, err := lookupParentOf(ctx, s, hostID, current)
	if err != nil {
		return nil, nil, nil, err
	}
	if candidate == nil {
		return nil, nil, nil, nil
	}
	if !shellPaths()[candidate.Path] {
		return current, candidate, nil, nil
	}
	// Shell-to-shell layering (sudo bash, su -c bash, ...). Keep climbing.
	return nil, nil, candidate, nil
}

// lookupParentOf is the ONLY parent-edge lookup in this file. There used to be a second, lookupAncestor, taking an arbitrary
// `asOf` instant, and both of its callers passed the trigger timestamp: exactly the misuse the paragraph below forbids. It was
// removed with those call sites (issue #776 review) rather than left available, so the wrong instant is no longer reachable.
//
// lookupParentOf resolves the generation that held child's PPID when CHILD FORKED, which is the only instant at which that question
// has an answer. Resolving a parent edge at an unrelated instant, such as the timestamp of a network flow made much later by a
// descendant, asks "who holds this PID now", and PIDs are reused.
//
// This is deliberately NOT skew-padded, and the pad would be actively harmful here. A parent may legitimately have exited before its
// descendant connected, so a miss at the child's fork time is not evidence of a late stamp, and widening the bound forward would let a
// generation that forked AFTER the child answer as its parent, fabricating an ancestor chain out of a recycled PID. The store
// documents the same rule for the inherited-path lookup (issue #714).
//
// The pad is not needed either, because both timestamps come from the same event stream: a child's fork and its parent's fork are both
// stamped by the agent's process-event path, so they run late together and their ORDER survives. The skew this rule has to absorb is
// between that stream and the network flow that triggers it, which is why the tolerance belongs at the trigger comparison rather than
// on the edges of the ancestry.
func lookupParentOf(
	ctx context.Context, s api.GraphReader, hostID string, child *api.Process,
) (*api.Process, error) {
	if child.PPID <= 1 {
		return nil, nil
	}
	p, err := s.GetProcessByPID(ctx, hostID, child.PPID, child.ForkTimeNs)
	if err != nil {
		return nil, fmt.Errorf("get ppid %d: %w", child.PPID, err)
	}
	return p, nil
}

// findShellFromResolvedProcess walks up from a connecting process that has ALREADY been resolved, rather than resolving its PID again
// at the raw event timestamp. Two things follow from that.
//
// The first hop no longer re-resolves what the caller just resolved, and it starts from the generation the caller identified, which
// for a flow carrying a pidversion is an exact identity match rather than a time-window guess.
//
// The ancestors above it are resolved by lookupParentOf, at each child's own fork time rather than at the trigger, so PID reuse
// cannot substitute a later generation for a real parent. That lookup takes no skew pad, deliberately: see its doc for why a pad
// would be actively harmful on a parent edge. A parent genuinely absent from the graph ends the walk and reports nothing (#710).
func findShellFromResolvedProcess(
	ctx context.Context, s api.GraphReader, hostID string, start *api.Process,
) (*api.Process, *api.Process, error) {
	current := start
	for steps := 0; current != nil && steps < maxSuspiciousAncestorWalkSteps; steps++ {
		shell, parent, advance, err := examineCandidate(ctx, s, hostID, current)
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

// parentExcluded reports whether the given non-shell parent process is excluded for hostID. It matches four dimensions of the parent
// (issue #520): the path glob (match type parent_path_glob) and the parent's already-persisted code-signing identity (team_id,
// signing_id, cdhash). The signature dimensions let an operator exclude a benign signed parent (e.g. a Developer-ID developer tool
// such as Claude Code) by a non-spoofable identifier rather than a path glob an attacker who can write to /tmp can land inside. A nil
// parent (shell parented at launchd, or parent not yet materialised) never matches: those are the cases the rule must continue to
// flag because there's no human-attested entry point. Glob semantics live in the resolver (api.GlobMatch).
func parentExcluded(r shellChainRule, parent *api.Process, hostID string) bool {
	if r.exclusionResolver() == nil || parent == nil {
		return false
	}
	if r.exclusionResolver().Excluded(r.ID(), api.ExclusionMatchParentPathGlob, parent.Path, hostID) {
		return true
	}
	if len(parent.CodeSigning) > 0 {
		var cs codeSigningJSON
		// A malformed blob is unexpected (the agent writes it), so a decode error just means "no signature to match on" rather than a
		// rule failure: fall through to the cdhash check.
		if err := json.Unmarshal(parent.CodeSigning, &cs); err == nil {
			if cs.TeamID != "" && r.exclusionResolver().Excluded(r.ID(), api.ExclusionMatchTeamID, cs.TeamID, hostID) {
				return true
			}
			if cs.SigningID != "" && r.exclusionResolver().Excluded(r.ID(), api.ExclusionMatchSigningID, cs.SigningID, hostID) {
				return true
			}
		}
	}
	return parent.CDHash != nil && *parent.CDHash != "" &&
		r.exclusionResolver().Excluded(r.ID(), api.ExclusionMatchCDHash, *parent.CDHash, hostID)
}

// shellWithinWindow reports whether the trigger event's timestamp falls inside the rule's window around the shell's exec. Anchored on
// the shell's exec_time_ns when set (preferred: that's the kernel's actual exec moment) and falls back to fork_time_ns otherwise
// (defensive: should always be set for a fully-materialised process).
//
// The window is deliberately asymmetric. It runs the CALLING RULE's own window forward from the shell, which is the real limit on
// how long after a shell that rule still attributes activity to it, and agentStampSkewPadNs backward, which is not a limit but an
// allowance for the shell's own stamp arriving late (see agentStampSkewPadNs).
//
// The forward bound comes from r.window() rather than a package constant because the two rules sharing this walk tune separately
// (issue #776); naming one rule's constant here would have re-coupled them through the helper they share.
func shellWithinWindow(r shellChainRule, shell *api.Process, triggerTS int64) bool {
	anchor := shell.ForkTimeNs
	if shell.ExecTimeNs != nil {
		anchor = *shell.ExecTimeNs
	}
	// The lower bound is padded because a trigger CANNOT causally precede the shell that produced it, so a small negative delta is
	// evidence of a late stamp rather than of no relationship. An agent that stamps at handler time rather than kernel time records
	// an exec after its own child's network connection, measured at 701ms on a busy host (issue #710), and an unpadded lower bound
	// reads that as "the trigger came first" and drops the finding. The upper bound is not padded: that direction is a real
	// temporal limit on how long after a shell the rule still attributes activity to it.
	return triggerTS >= anchor-agentStampSkewPadNs && triggerTS <= anchor+r.window()
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
		if !shellPaths()[p.Path] {
			continue
		}
		return e.EventID
	}
	return ""
}
