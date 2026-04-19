package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/store"
)

// DyldInsert fires when a process is launched with DYLD_INSERT_LIBRARIES or
// DYLD_LIBRARY_PATH in its environment. Those env vars tell dyld to load arbitrary
// dylibs, a classic macOS code-injection technique.
//
// Phase 2 MVP: the ESF extension does not (yet) capture the full env map, so this rule
// only catches the "explicit prefix" cases — either the env vars appear in argv (shell
// style `VAR=x /bin/true`) or the caller invoked `env VAR=x target`. Inherited env vars
// are invisible to us until the extension learns to serialise them; that extension change
// is tracked in Phase 4 (Data lifecycle + observability).
//
// MITRE ATT&CK: T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking)
type DyldInsert struct{}

func (r *DyldInsert) ID() string { return "dyld_insert" }

// Dangerous env prefixes. DYLD_FRAMEWORK_PATH + DYLD_FALLBACK_* also exist but are
// higher-false-positive (SIP disables them for Apple binaries anyway); we leave them
// out for MVP and revisit if pilot customers surface real evasion.
var dyldPrefixes = []string{
	"DYLD_INSERT_LIBRARIES=",
	"DYLD_LIBRARY_PATH=",
}

type dyldPayload struct {
	PID  int      `json:"pid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func (r *DyldInsert) Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, evt := range events {
		if evt.EventType != "exec" {
			continue
		}
		var p dyldPayload
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			continue
		}
		matched := matchDyldArg(p.Args)
		if matched == "" {
			continue
		}

		proc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
		if err != nil {
			return nil, fmt.Errorf("get process pid %d: %w", p.PID, err)
		}
		if proc == nil {
			continue
		}

		findings = append(findings, detection.Finding{
			HostID:      evt.HostID,
			RuleID:      r.ID(),
			Severity:    detection.SeverityHigh,
			Title:       "DYLD injection env var set on exec",
			Description: fmt.Sprintf("%s launched with %s", p.Path, matched),
			ProcessID:   proc.ID,
			EventIDs:    []string{evt.EventID},
		})
	}
	return findings, nil
}

// matchDyldArg returns the first argv entry that starts with a dangerous DYLD env prefix,
// or "" if none. We strip the value side so logs / alerts don't accidentally echo a
// potentially-sensitive dylib path; the full path is still in the raw event payload for
// responders who need it.
func matchDyldArg(args []string) string {
	for _, a := range args {
		for _, prefix := range dyldPrefixes {
			if strings.HasPrefix(a, prefix) {
				return prefix + "<redacted>"
			}
		}
	}
	return ""
}
