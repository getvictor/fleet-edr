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

// securityBinaryPaths is the set of `security` binary locations we'll
// flag. /usr/bin/security is canonical; the others appear on SIP-
// disabled or symlinked installs we've seen in QA.
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
			// Defensive: ES emitted an exec without a matching
			// materialised row (e.g. exec-without-fork not yet
			// processed). Skip — we'll catch the next emission.
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
// "dump-keychain") and true if any argv token matches, or empty+false.
// Scans ALL argv tokens rather than just argv[1] because shell wrappers
// often prepend flags: `security -v dump-keychain`.
func findDumpKeychainArg(argv []string) (string, bool) {
	for _, a := range argv {
		// Trim any leading `--`/`-` for flag-style invocations; the
		// security tool accepts subcommands bare but some scripts
		// prefix them.
		token := strings.TrimLeft(a, "-")
		if dumpKeychainArgTokens[token] {
			return token, true
		}
	}
	return "", false
}
