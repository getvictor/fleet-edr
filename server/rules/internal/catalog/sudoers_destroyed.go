package catalog

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

// SudoersDestroyed fires when a file sudo will parse as policy is emptied or removed.
//
// Separate from sudoers_tamper rather than folded into it, and the reason is the ATT&CK mapping rather than tidiness.
// sudoers_tamper is T1548.003, Abuse Elevation Control Mechanism: Sudo and Sudo Caching, which is about GAINING elevated
// execution. Emptying or deleting a sudoers file grants nothing; it takes access away and removes whatever was written there.
// Reporting that under T1548.003 would put a destruction event on a coverage page under the technique for escalation, which is
// wrong in the direction that matters to anyone reading the mapping.
//
// Two things it detects, one outcome. `: > /etc/sudoers` empties the file through open(2) with O_TRUNC and `rm` unlinks it;
// either way the policy that was there is gone. Until #934 neither produced any telemetry at all: the truncation because
// open(O_TRUNC) is a different kernel path from the CREATE/WRITE the client watched, and the deletion because UNLINK was not
// subscribed. Measured on macOS 26.3, three separate O_TRUNC paths each took a 37-byte file to zero and emitted nothing.
//
// It matches only the names sudo will actually parse, for the same reason sudoers_tamper does (#933): sudoers(5) skips files
// in /etc/sudoers.d whose names contain a `.` or end in `~`. That narrowing is load-bearing here rather than merely tidy,
// because visudo UNLINKS its own `<name>.tmp` on every run, so a rule matching any child would report each legitimate edit as
// a policy deletion.
type SudoersDestroyed struct {
	// Exclusions is the per-host false-positive resolver, matched against the DESTROYING process's path. A configuration
	// manager that rewrites a fragment by removing and recreating it is the shape an operator will want to exclude.
	Exclusions api.ExclusionResolver
}

func (r *SudoersDestroyed) ID() string { return "sudoers_destroyed" }

// AlgorithmName is unset: the rule's logic is the detection block in its pack file, not a Go evaluator.

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding.
func (r *SudoersDestroyed) DisplayName() string { return "Sudoers policy destroyed" }

// Techniques maps this to removal rather than to escalation.
//
// T1070.004 (Indicator Removal: File Deletion) is the primary: an attacker who added a sudoers fragment and then removes it is
// deleting the evidence of their own grant. T1531 (Account Access Removal) is the other half and is not speculative padding:
// emptying /etc/sudoers revokes every administrator's elevated access at once, which is a denial an operator has to recognise
// as an attack rather than as a misconfiguration.
func (r *SudoersDestroyed) Techniques() []string { return []string{"T1070.004", "T1531"} }

// Doc surfaces the operator-facing description in /api/rules and the generated docs/detection-rules.md.
func (r *SudoersDestroyed) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags a program that empties or deletes a sudoers file that sudo would have loaded.",
		Description: "Detects destruction of sudo policy: a file sudo parses is truncated to nothing, or removed. " +
			"Either takes away access that was granted, and either can be an attacker removing the evidence of a " +
			"grant they added earlier.\n\n" +
			"Emptying is detected however it is done. `truncate(2)` and a shell's `: > file` redirect are different " +
			"kernel operations reaching the same outcome, and the redirect is the common one; before this rule " +
			"existed it produced no telemetry at all.\n\n" +
			"Only files sudo would actually load are considered: sudoers(5) skips names in /etc/sudoers.d that " +
			"contain a `.` or end in `~`, and destroying a file sudo ignores destroys no policy. That also keeps " +
			"`visudo` quiet, since it removes its own temporary file on every run.",
		Severity: api.SeverityHigh,
		// file_delete first, and this ordering is REQUIRED rather than a preference. The exporter takes the Sigma
		// logsource from the FIRST event type, and the loader refuses a rule whose detection block sits under a category
		// it supplies no fields for. Only file_delete has a genuine Sigma equivalent, so leading with file_truncate
		// declares a category nothing resolves and the pack fails to load: "logsource category file_truncate has no
		// event type we supply fields for", which is how this was found.
		//
		// It is also the better answer for an external engine, which at least receives the deletions rather than a
		// category it has never heard of.
		EventTypes: []string{"file_delete", "file_truncate"},
		FalsePositives: []string{
			"A configuration manager that rewrites a fragment by deleting and recreating it rather than writing in place. " +
				"Add a path-glob exclusion for its absolute path.",
			"An administrator retiring a sudoers fragment by hand. This is a real administrative action and the rule " +
				"cannot distinguish it from an attacker doing the same thing; the writer's identity is what separates them.",
		},
		Limitations: []string{
			"Destruction of /etc/sudoers.d itself, rather than of a file within it, is not detected: the watched set is the " +
				"files, not the directory.",
			"A file sudo already ignores (a name containing a `.` or ending in `~`) is deliberately not reported, so an " +
				"attacker removing their own `.tmp` staging file leaves no finding from this rule.",
		},
	}
}

// SupportedExclusionMatchTypes lists the match types this rule consults: the destroying process's path glob.
func (r *SudoersDestroyed) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{api.ExclusionMatchPathGlob}
}

// sudoersDestroyedDetection is the rule's logic, compiled from the detection block in its pack file.
var sudoersDestroyedDetection = sync.OnceValue(func() *sigma.Rule { return detectionFor("sudoers_destroyed") })

// Evaluate runs the rule with a scope of its own, which is the un-shared behaviour a direct caller gets.
func (r *SudoersDestroyed) Evaluate(
	ctx context.Context, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// EvaluateScoped implements api.ScopedRule.
func (r *SudoersDestroyed) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return evalEachScopedEvent(ctx, scope, events, s, r.evalEvent)
}

func (r *SudoersDestroyed) evalEvent(
	ctx context.Context, scope *api.BatchScope, evt api.Event, s api.GraphReader,
) (*api.Finding, error) {
	if evt.EventType != "file_truncate" && evt.EventType != "file_delete" {
		return nil, nil
	}
	// The same byte prefilter sudoers_tamper uses, and for the same reason: it costs nothing and keeps an event for some other
	// path out of the shared memo. See sudoersBytes for why the raw payload carries unescaped slashes by the time it gets here.
	if !bytes.Contains(evt.Payload, sudoersBytes) {
		return nil, nil
	}
	view := sigmaEvent(ctx, scope, evt, s)
	if view == nil {
		return nil, nil
	}
	se := view.Event
	matched := sudoersDestroyedDetection().Matches(se)
	if resolveErr := se.ResolveErr(); resolveErr != nil {
		return nil, resolveErr
	}
	if !matched {
		return nil, nil
	}

	proc, err := view.Subject()
	if err != nil {
		return nil, err
	}
	if proc == nil {
		return nil, nil
	}
	if r.excluded(proc.Path, evt.HostID) {
		return nil, nil
	}

	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       r.DisplayName(),
		Description: sudoersDestroyedDescription(evt.EventType, proc.Path, firstField(se, "TargetFilename")),
		ProcessID:   proc.ID,
		EventIDs:    []string{evt.EventID},
	}, nil
}

// sudoersDestroyedDescription says which destruction happened, because the two are not interchangeable to an analyst: a
// truncated file still exists and still parses, as an empty policy, while a deleted one is gone and a later `sudo` will report
// it missing. Only the matched element is named; the acting process's path is not attacker-controlled content in the sense the
// converted-rule requirement withholds, it is the subject the finding is attributed to.
func sudoersDestroyedDescription(eventType, writerPath, target string) string {
	verb := "emptied"
	if eventType == "file_delete" {
		verb = "deleted"
	}
	return fmt.Sprintf("%s %s %s, destroying sudo policy (MITRE T1070.004)", writerPath, verb, target)
}

func (r *SudoersDestroyed) excluded(writerPath, hostID string) bool {
	return r.Exclusions != nil && r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, writerPath, hostID)
}
