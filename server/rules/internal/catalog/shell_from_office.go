package catalog

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

// ShellFromOffice fires when a shell (/bin/sh, /bin/bash, /bin/zsh, etc.) is spawned
// whose parent process is one of the Microsoft Office apps. VBA/Word-macro payloads
// frequently shell out to bootstrap a second-stage; modern macOS keeps the Office
// binaries in /Applications/Microsoft {Word,Excel,PowerPoint,Outlook}.app/.
//
// MITRE ATT&CK: T1566.001 (Phishing: Spearphishing Attachment) + T1059 (Shell)
type ShellFromOffice struct{}

func (r *ShellFromOffice) ID() string { return "shell_from_office" }

// SupportedExclusionMatchTypes returns nil: this rule consults no exclusions, so the admin UI offers none for it (issue #520).
func (r *ShellFromOffice) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return nil }

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *ShellFromOffice) DisplayName() string { return "Shell spawned by Microsoft Office" }

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1566.001 (Phishing → Spearphishing Attachment) + T1059.004 (Command and
// Scripting Interpreter → Unix Shell). The chain "Office app → shell" is a textbook post-phish execution step.
func (r *ShellFromOffice) Techniques() []string { return []string{"T1566.001", "T1059.004"} }

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *ShellFromOffice) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags any /bin/sh, /bin/bash, /bin/zsh (etc.) whose parent is Word, Excel, PowerPoint, or Outlook.",
		Description: "Detects the textbook post-phishing execution step: a macro-laden Office document opens, the macro " +
			"shells out, and the second stage takes off from there. The match is on the parent process being one of " +
			"the four standard macOS Office binaries (full path, not substring) and the child being a known shell.\n\n" +
			"Office apps almost never need to shell out in normal use; when they do, it's an admin-side automation " +
			"that's worth surfacing anyway.",
		Severity:   api.SeverityHigh,
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

// shellFromOfficeDetection is the rule's logic, compiled from the detection block in its pack file.
var shellFromOfficeDetection = sync.OnceValue(func() *sigma.Rule { return detectionFor("shell_from_office") })

// Evaluate runs the rule with a scope of its own, which is the un-shared behaviour a direct caller gets. The engine calls
// EvaluateScoped instead, so the batch's Sigma-backed rules share one decode and one parent lookup per event.
func (r *ShellFromOffice) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// EvaluateScoped implements api.ScopedRule.
func (r *ShellFromOffice) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return evalEachScopedEvent(ctx, scope, events, s, r.evalEvent)
}

// evalEvent returns a finding for a single event, or nil when the event doesn't match. Splitting this out of Evaluate keeps the
// per-event short-circuits (non-exec, bad JSON, non-shell path, non-Office parent) from stacking cognitive complexity on the caller.
func (r *ShellFromOffice) evalEvent(
	ctx context.Context, scope *api.BatchScope, evt api.Event, s api.GraphReader,
) (*api.Finding, error) {
	if evt.EventType != "exec" {
		return nil, nil
	}
	// The adapter resolves the parent from the graph and supplies it as ParentImage, lazily and through a memo shared with the
	// batch's other rules, so the graph is read once per event however many rules read the field. An unresolved parent leaves the
	// field absent, so the detection declines: the same answer the Go matcher gave, and for the same reason. The processor marks
	// the batch processed after Evaluate returns, so a missing parent is accepted rather than retried.
	view, err := sigmaEvent(ctx, scope, evt, s)
	if err != nil || view == nil {
		return nil, nil
	}
	se := view.Event
	matched := shellFromOfficeDetection().Matches(se)
	if err := se.ResolveErr(); err != nil {
		return nil, err
	}
	if !matched {
		return nil, nil
	}
	// The parent the detection matched on, read back from the same field, so the alert names the Office app that spawned the shell.
	parentPath := firstField(se, "ParentImage")

	proc, err := view.Subject()
	if err != nil {
		return nil, err
	}
	if proc == nil {
		return nil, nil
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("%s → %s", prettyOfficeParent(parentPath), firstField(se, "Image")),
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
