package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
)

// DyldInsert fires when a process is launched with DYLD_INSERT_LIBRARIES or
// DYLD_LIBRARY_PATH in its environment. Those env vars tell dyld to load arbitrary
// dylibs, a classic macOS code-injection technique.
//
// Known limitation: the ESF extension does not (yet) capture the full env map, so this
// rule only catches the "explicit prefix" cases: either the env vars appear in argv
// (shell style `VAR=x /bin/true`) or the caller invoked `env VAR=x target`. Inherited
// env vars are invisible until the extension learns to serialise them; that extension
// change is tracked alongside the data-lifecycle work in the best-practices checklist.
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
		Summary: "Flags exec where DYLD_INSERT_LIBRARIES or DYLD_LIBRARY_PATH is set in argv (shell-style or via env(1)).",
		Description: "Detects the classic macOS code-injection primitive: launching a process with " +
			"`DYLD_INSERT_LIBRARIES=…` or `DYLD_LIBRARY_PATH=…` set so dyld loads attacker-supplied dylibs into " +
			"the new process before main(). The rule fires on the leading argv slot only (the `VAR=value /path/to/bin` " +
			"shell form, or the `env VAR=value /path/to/bin` invocation), so substring noise (curl POST data, echo, etc.) does " +
			"not false-positive.\n\n" +
			"The matching dylib path is redacted in alert text (a sensitive payload location) but kept in the raw " +
			"event payload for responders.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"exec"},
		FalsePositives: []string{
			"Local development of code that itself uses DYLD_INSERT_LIBRARIES (rare; usually scoped to non-managed dev hosts).",
			"Apple-signed binaries are immune to DYLD_INSERT_LIBRARIES under SIP, but the rule still fires on the launch: investigate why an admin script is setting these vars at all.",
		},
		Limitations: []string{
			"Inherited environment variables (set by a parent shell, not on the exec line) are invisible: ESF does not yet hand the agent the full env map. Tracked as future work.",
			"DYLD_FRAMEWORK_PATH and DYLD_FALLBACK_* are intentionally NOT matched: higher-FP, lower-signal. Extend dyldPrefixes if a pilot surfaces real abuse.",
		},
	}
}

// Dangerous env prefixes. DYLD_FRAMEWORK_PATH + DYLD_FALLBACK_* also exist but are higher-false-positive (SIP disables them for Apple
// binaries anyway); we leave them out for MVP and revisit if pilot customers surface real evasion.
var dyldPrefixes = []string{
	"DYLD_INSERT_LIBRARIES=",
	"DYLD_LIBRARY_PATH=",
}

// dyldDetection is the rule's logic, compiled from the detection block in its pack file.
var dyldDetection = sync.OnceValue(func() *sigma.Rule { return detectionFor("dyld_insert") })

type dyldPayload struct {
	PID  int      `json:"pid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func (r *DyldInsert) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	var findings []api.Finding
	var miss pendingMiss
	for _, evt := range events {
		if evt.EventType != "exec" {
			continue
		}
		var p dyldPayload
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			continue
		}
		se, err := sigmabind.NewEvent(evt)
		if err != nil {
			continue
		}
		if !dyldDetection().Matches(se) {
			continue
		}
		// The variable the detection matched on, named in the alert WITHOUT its value: the injected dylib path is attacker-chosen
		// content and the finding is read by people, so the rule has always redacted it.
		matched := redactedDyldAssignment(se)

		proc, err := resolveSubjectProcess(ctx, s, evt, p.PID)
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
			Description: fmt.Sprintf("%s launched with %s", p.Path, matched),
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
