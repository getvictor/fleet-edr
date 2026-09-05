package catalog

import (
	"context"
	"fmt"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
	"strings"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

// DyldInsert fires when a process is launched with DYLD_INSERT_LIBRARIES or
// DYLD_LIBRARY_PATH in its environment. Those env vars tell dyld to load arbitrary
// dylibs, a classic macOS code-injection technique.
//
// Known limitation: the ESF extension does not capture the environment, so this rule catches ONE shape, an explicit
// `env VAR=x target` invocation, and nothing else.
//
// It used to claim a second, the shell form `VAR=x /bin/true`, and issue #791 measured that claim as false. ESF serialises
// `es_exec_arg` only, so a shell's assignments never appear in the argument vector: that command reaches the server as
// `argv == ["/bin/true"]`, with the assignment nowhere in the event. Across 670,185 real exec events from a dev host, argv[0]
// was an assignment ZERO times, and the reason is structural rather than a small sample. The rule was therefore advertising
// coverage it could not have, which is worse than a documented gap because nobody goes looking for it.
//
// Inherited environment variables remain invisible for the same reason, and capturing the DYLD_* subset is tracked as #862.
// That would add a field rather than put assignments into argv, so the shell form stays out of reach here even then.
//
// MITRE ATT&CK: T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking)
type DyldInsert struct{}

func (r *DyldInsert) ID() string { return "dyld_insert" }

// SupportedExclusionMatchTypes returns nil: this rule consults no exclusions, so the admin UI offers none for it (issue #520).
func (r *DyldInsert) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return nil }

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *DyldInsert) DisplayName() string { return "DYLD injection on exec" }

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1574.006 (Hijack Execution Flow → Dynamic Linker Hijacking).
// Sub-technique chosen deliberately: the rule catches DYLD_* env-var abuse specifically, not the broader "Hijack Execution Flow"
// parent.
func (r *DyldInsert) Techniques() []string { return []string{"T1574.006"} }

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *DyldInsert) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags an env(1) invocation that sets DYLD_INSERT_LIBRARIES or DYLD_LIBRARY_PATH for the command it runs.",
		Description: "Detects the classic macOS code-injection primitive: launching a process with " +
			"`DYLD_INSERT_LIBRARIES=…` or `DYLD_LIBRARY_PATH=…` set so dyld loads attacker-supplied dylibs into " +
			"the new process before main(). The rule fires on an `env VAR=value /path/to/bin` invocation only, matching the " +
			"assignments env itself applies rather than any argument containing the text, so substring noise (curl POST data, " +
			"echo, etc.) does not false-positive.\n\n" +
			"The matching dylib path is redacted in alert text (a sensitive payload location) but kept in the raw " +
			"event payload for responders.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"exec"},
		FalsePositives: []string{
			"Local development of code that itself uses DYLD_INSERT_LIBRARIES (rare; usually scoped to non-managed dev hosts).",
			"Apple-signed binaries are immune to DYLD_INSERT_LIBRARIES under SIP, but the rule still fires on the launch: investigate why an admin script is setting these vars at all.",
		},
		Limitations: []string{
			"Only an `env(1)` invocation is detected. A shell assignment such as `DYLD_INSERT_LIBRARIES=… /bin/ls` is NOT detected and never was, despite earlier wording here: the sensor records a process's arguments, and a shell applies those variables without putting them there, so the assignment is absent from the event entirely (issue #791). Capturing the environment is tracked as issue #862.",
			"DYLD_FRAMEWORK_PATH and DYLD_FALLBACK_* are intentionally NOT matched: higher-FP, lower-signal. Add them to the detection block in the rule's pack file if a pilot surfaces real abuse; the Go prefix list only names the matched variable in the alert.",
		},
	}
}

// Dangerous env prefixes. DYLD_FRAMEWORK_PATH + DYLD_FALLBACK_* also exist but are higher-false-positive (SIP disables them for Apple
// binaries anyway); we leave them out for MVP and revisit if pilot customers surface real evasion.
// dyldPrefixes names the variable a finding reports. It no longer decides whether the rule fires: the detection block does, and
// this list exists only so the alert can say WHICH assignment matched, since the evaluator reports only that one did (issue #796).
// TestLiveSymbolsStillAgreeWithTheShippedDetections keeps the two in step.
var dyldPrefixes = []string{
	"DYLD_INSERT_LIBRARIES=",
	"DYLD_LIBRARY_PATH=",
}

// dyldDetection is the rule's logic, compiled from the detection block in its pack file.
var dyldDetection = sync.OnceValue(func() *sigma.Rule { return detectionFor("dyld_insert") })

// Evaluate runs the rule with a scope of its own, which is the un-shared behaviour a direct caller gets. The engine calls
// EvaluateScoped instead, so the batch's Sigma-backed rules share one decode per event.
func (r *DyldInsert) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// EvaluateScoped implements api.ScopedRule.
func (r *DyldInsert) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	var findings []api.Finding
	var miss pendingMiss
	for _, evt := range events {
		if evt.EventType != "exec" {
			continue
		}
		view := sigmaEvent(ctx, scope, evt, s)
		if view == nil {
			continue
		}
		se := view.Event
		if !dyldDetection().Matches(se) {
			continue
		}
		// The variable the detection matched on, named in the alert WITHOUT its value: the injected dylib path is attacker-chosen
		// content and the finding is read by people, so the rule has always redacted it.
		matched := redactedDyldAssignment(se)

		proc, err := view.Subject()
		if fatal := miss.absorb(err); fatal != nil {
			return nil, fatal
		}
		if proc == nil {
			continue
		}

		findings = append(findings, api.Finding{
			HostID:      evt.HostID,
			RuleID:      r.ID(),
			Severity:    api.SeverityHigh,
			Title:       r.DisplayName(),
			Description: fmt.Sprintf("%s launched with %s", firstField(se, "Image"), matched),
			ProcessID:   proc.ID,
			EventIDs:    []string{evt.EventID},
		})
	}
	return findings, miss.err
}

// redactedDyldAssignment names the DYLD variable the detection matched, with its value withheld. The finding is operator-facing and
// the value is a path the attacker chose, so only the key is reported.
func redactedDyldAssignment(se *sigmabind.Event) string {
	values, ok := se.Field("EnvAssignments")
	if !ok {
		return ""
	}
	for _, assignment := range values {
		for _, prefix := range dyldPrefixes {
			if strings.HasPrefix(assignment, prefix) {
				return prefix + "<redacted>"
			}
		}
	}
	return ""
}
