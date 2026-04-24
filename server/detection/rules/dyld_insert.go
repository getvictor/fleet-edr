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

// Techniques: T1574.006 (Hijack Execution Flow → Dynamic Linker Hijacking).
// Sub-technique chosen deliberately: the rule catches DYLD_* env-var abuse
// specifically, not the broader "Hijack Execution Flow" parent.
func (r *DyldInsert) Techniques() []string { return []string{"T1574.006"} }

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
		matched := matchDyldArg(p.Path, p.Args)
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

// matchDyldArg returns the matching DYLD env prefix when the exec is launching with one
// of the dangerous env vars in a leading assignment position, or "" otherwise. We strip
// the value side so logs / alerts don't accidentally echo a potentially-sensitive dylib
// path; the full argv is still in the raw event payload for responders who need it.
//
// Why leading-only: `echo DYLD_INSERT_LIBRARIES=/tmp/x` or `curl --data
// DYLD_INSERT_LIBRARIES=...` would false-positive if we scanned every argv slot. The
// dangerous shape is the shell-style "VAR=value /path/to/binary" prefix (argv[0] onwards)
// or the `env VAR=value binary` invocation. We capture both without firing on arbitrary
// data that happens to contain the substring.
func matchDyldArg(path string, args []string) string {
	// The canonical env invocations are "env", "/usr/bin/env", and shim paths ending in
	// "/env". For anything else, only argv[0] is a legitimate VAR=VALUE slot (the shell's
	// `VAR=value cmd` form).
	isEnv := path == "/usr/bin/env" || strings.HasSuffix(path, "/env")

	for i, a := range args {
		// Stop once we've walked past the leading env-assignment window. For `env`-style
		// invocations that's every leading KEY=VALUE until the first non-assignment arg;
		// for everything else it's argv[0] only.
		if !isEnv && i > 0 {
			break
		}
		if isEnv && i > 0 && !strings.Contains(a, "=") {
			break
		}
		for _, prefix := range dyldPrefixes {
			if strings.HasPrefix(a, prefix) {
				return prefix + "<redacted>"
			}
		}
	}
	return ""
}
