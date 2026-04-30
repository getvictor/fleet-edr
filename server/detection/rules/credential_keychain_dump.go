package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/store"
)

// CredentialKeychainDump fires when a process invokes `/usr/bin/security
// dump-keychain` — the canonical macOS command for exporting Keychain
// entries, including saved passwords and private keys. It is almost
// never legitimate in a managed fleet: admin scripts don't dump the
// Keychain, and the command is a well-known red-team staple.
//
// Detection targets exec events only — no process-tree lookups, no
// network correlation. A shell wrapper (`sh -c "security dump-keychain"`)
// still surfaces because ESF emits a NOTIFY_EXEC for each execve(), so
// the security binary shows up as its own exec event regardless of the
// parent.
//
// The rule does NOT attempt to match variants that touch the Keychain
// without going through /usr/bin/security (raw SQLite reads of
// login.keychain-db, SecItemCopyMatching API calls). Those are caught by
// the file-integrity-monitoring work tracked in the best-practices
// checklist (Phase 8+).
type CredentialKeychainDump struct{}

func (r *CredentialKeychainDump) ID() string { return "credential_keychain_dump" }

// Techniques returns the MITRE ATT&CK IDs this rule covers — T1555.001
// (Credentials from Password Stores → Keychain). Apple's own docs list
// `security dump-keychain` as the tool for enumerating Keychain items,
// and MITRE explicitly cites it on the technique page.
func (r *CredentialKeychainDump) Techniques() []string { return []string{"T1555.001"} }

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *CredentialKeychainDump) Doc() detection.Documentation {
	return detection.Documentation{
		Title:   "Keychain dump (security dump-keychain)",
		Summary: "Flags exec of /usr/bin/security dump-keychain — the canonical macOS Keychain export command.",
		Description: "Fires when a process invokes `/usr/bin/security` with the `dump-keychain` subcommand. " +
			"That command exports Keychain entries (saved passwords, private keys) and is the macOS-native equivalent " +
			"of credential-dumping tooling on Windows. Admin scripts virtually never invoke it; offensive playbooks do.\n\n" +
			"Match shape is exact-path + exact-subcommand to keep the rule high-precision. A shell wrapper " +
			"(`sh -c \"security dump-keychain\"`) still surfaces because ESF emits a NOTIFY_EXEC for each execve(), " +
			"so the security binary always shows up as its own exec event regardless of parent.",
		Severity:   detection.SeverityHigh,
		EventTypes: []string{"exec"},
		FalsePositives: []string{
			"An IT admin running a one-off keychain audit. Rare in managed fleets; confirm with the user before treating as benign.",
		},
		Limitations: []string{
			"Does not cover Keychain reads via the Security framework (SecItemCopyMatching, etc.) or raw SQLite scrapes of login.keychain-db. Those paths are tracked for a future file-integrity rule.",
			"Does not cover adjacent enumerative subcommands (find-internet-password -w, find-generic-password -w) — left out for precision; add them to dumpKeychainArgTokens if a pilot fleet surfaces real abuse.",
		},
	}
}

// securityBinaryPaths is the set of `security` binary locations we'll
// flag. Canonical-only by design: /usr/bin/security is where the tool
// lives on every shipping macOS SKU; SIP guarantees it. If a pilot
// customer surfaces a legitimate alternate path (symlink farm on a
// locked-down dev VM, for example), extend the map here rather than
// loosening the match.
var securityBinaryPaths = map[string]bool{
	"/usr/bin/security": true,
}

// dumpKeychainArgTokens is the subcommand set we flag. `dump-keychain`
// is the observed hit; `find-internet-password -w`, `find-generic-
// password -w`, and `unlock-keychain <path>` are adjacent tools that
// also exfiltrate credentials but we leave them out to keep the rule
// high-precision. Add them when a pilot customer asks.
var dumpKeychainArgTokens = map[string]bool{
	"dump-keychain": true,
}

type keychainDumpPayload struct {
	PID  int      `json:"pid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func (r *CredentialKeychainDump) Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, evt := range events {
		if evt.EventType != "exec" {
			continue
		}
		var p keychainDumpPayload
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			continue
		}
		if !securityBinaryPaths[p.Path] {
			continue
		}
		sub, ok := findDumpKeychainArg(p.Args)
		if !ok {
			continue
		}

		proc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
		if err != nil {
			return nil, fmt.Errorf("get process pid %d: %w", p.PID, err)
		}
		if proc == nil {
			// Defensive: the exec event landed but the process row
			// isn't materialised (e.g. a race where ingestion
			// delivered the exec before the builder's ProcessBatch
			// ran). Skip this event — we have no process_id to
			// link the finding to, and the engine won't re-feed
			// this batch. In practice the processor loop always
			// materialises before detection runs, so this branch
			// is a defensive guard, not a dropped-alert path.
			continue
		}

		findings = append(findings, detection.Finding{
			HostID:      evt.HostID,
			RuleID:      r.ID(),
			Severity:    detection.SeverityHigh,
			Title:       "Keychain credential dump attempted",
			Description: fmt.Sprintf("%s invoked with %q — reads all Keychain entries (Keychain credential access, MITRE T1555.001)", p.Path, sub),
			ProcessID:   proc.ID,
			EventIDs:    []string{evt.EventID},
		})
	}
	return findings, nil
}

// findDumpKeychainArg returns the matched subcommand (e.g.
// "dump-keychain") and true when argv invokes a flagged subcommand as
// the security tool's actual subcommand — i.e. the first non-flag token
// after argv[0]. argv[0] is the binary itself and is skipped; flag
// tokens (leading `-`) are skipped so `security -v dump-keychain` still
// matches. A subcommand like `help` that merely mentions the string
// `dump-keychain` in its arguments (`security help dump-keychain`)
// does NOT match, because `help` is the first non-flag token.
func findDumpKeychainArg(argv []string) (string, bool) {
	for i, a := range argv {
		if i == 0 {
			// argv[0] is the invocation name, not a subcommand.
			continue
		}
		if strings.HasPrefix(a, "-") {
			// Flag, not a subcommand.
			continue
		}
		if dumpKeychainArgTokens[a] {
			return a, true
		}
		// First non-flag token after argv[0] is the subcommand the
		// security tool will act on; if it's not one we flag, don't
		// keep scanning for a later match (avoids matching a path
		// arg that happens to contain "dump-keychain").
		return "", false
	}
	return "", false
}
