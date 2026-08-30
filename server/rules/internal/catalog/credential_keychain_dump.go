package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
)

// CredentialKeychainDump fires when a process invokes `/usr/bin/security
// dump-keychain`, the canonical macOS command for exporting Keychain
// entries, including saved passwords and private keys. It is almost
// never legitimate in a managed fleet: admin scripts don't dump the
// Keychain, and the command is a well-known red-team staple.
//
// Detection targets exec events only: no process-tree lookups, no
// network correlation. A shell wrapper (`sh -c "security dump-keychain"`)
// still surfaces because ESF emits a NOTIFY_EXEC for each execve(), so
// the security binary shows up as its own exec event regardless of the
// parent.
//
// The rule does NOT attempt to match variants that touch the Keychain
// without going through /usr/bin/security (raw SQLite reads of
// login.keychain-db, SecItemCopyMatching API calls). Those are caught by
// the file-integrity-monitoring work tracked in the best-practices
// checklist as a future addition.
type CredentialKeychainDump struct{}

func (r *CredentialKeychainDump) ID() string { return "credential_keychain_dump" }

// SupportedExclusionMatchTypes returns nil: this rule consults no exclusions, so the admin UI offers none for it (issue #520).
func (r *CredentialKeychainDump) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return nil }

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *CredentialKeychainDump) DisplayName() string { return "Keychain credential dump" }

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1555.001 (Credentials from Password Stores → Keychain). Apple's own docs
// list `security dump-keychain` as the tool for enumerating Keychain items, and MITRE explicitly cites it on the technique page.
func (r *CredentialKeychainDump) Techniques() []string { return []string{"T1555.001"} }

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *CredentialKeychainDump) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags exec of /usr/bin/security dump-keychain: the canonical macOS Keychain export command.",
		Description: "Fires when a process invokes `/usr/bin/security` with the `dump-keychain` subcommand. " +
			"That command exports Keychain entries (saved passwords, private keys) and is the macOS-native equivalent " +
			"of credential-dumping tooling on Windows. Admin scripts virtually never invoke it; offensive playbooks do.\n\n" +
			"Match shape is exact-path + exact-subcommand to keep the rule high-precision. A shell wrapper " +
			"(`sh -c \"security dump-keychain\"`) still surfaces because ESF emits a NOTIFY_EXEC for each execve(), " +
			"so the security binary always shows up as its own exec event regardless of parent.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"exec"},
		FalsePositives: []string{
			"An IT admin running a one-off keychain audit. Rare in managed fleets; confirm with the user before treating as benign.",
		},
		Limitations: []string{
			"Does not cover Keychain reads via the Security framework (SecItemCopyMatching, etc.) or raw SQLite scrapes of login.keychain-db. Those paths are tracked for a future file-integrity rule.",
			"Does not cover adjacent enumerative subcommands (find-internet-password -w, find-generic-password -w); left out for precision; add them to the detection block in the rule's pack file if a pilot fleet surfaces real abuse.",
		},
	}
}

// keychainDetection is the rule's logic, compiled from the detection block in its pack file. Memoised because the compile happens
// once at start-up, where a malformed block fails loudly, rather than per event.
var keychainDetection = sync.OnceValue(func() *sigma.Rule { return detectionFor("credential_keychain_dump") })

type keychainDumpPayload struct {
	PID  int      `json:"pid"`
	Path string   `json:"path"`
	Args []string `json:"args"`
}

func (r *CredentialKeychainDump) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	var findings []api.Finding
	var miss pendingMiss
	for _, evt := range events {
		if evt.EventType != "exec" {
			continue
		}
		// Built per rule rather than per event, because the engine hands each rule the raw batch and offers no way to share an
		// adapter. Measured at 1.3us and 776 bytes per exec event, which is nothing for one converted rule and is not nothing
		// once the catalog is mostly Sigma; issue #794 moves the decode into the engine.
		se, err := sigmabind.NewEvent(evt)
		if err != nil {
			// A payload that does not decode is a malformed event rather than an uninteresting one, but one bad event must not
			// discard the findings the rest of the batch produced.
			continue
		}
		if !keychainDetection().Matches(se) {
			continue
		}
		var p keychainDumpPayload
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			continue
		}
		// The subcommand the detection matched on, read back from the same computed field, so the alert names what fired.
		sub := ""
		if values, ok := se.Field("Subcommand"); ok && len(values) > 0 {
			sub = values[0]
		}

		proc, err := resolveSubjectProcess(ctx, s, evt, p.PID)
		if fatal := miss.absorb(err); fatal != nil {
			return nil, fatal
		}
		if proc == nil {
			// The exec's own row never materialized within the grace window (a young miss raises the retryable
			// ErrProcessNotYetMaterialized instead), so there is no process_id to link the finding to.
			continue
		}

		findings = append(findings, api.Finding{
			HostID:      evt.HostID,
			RuleID:      r.ID(),
			Severity:    api.SeverityHigh,
			Title:       r.DisplayName(),
			Description: fmt.Sprintf("%s invoked with %q: reads all Keychain entries (Keychain credential access, MITRE T1555.001)", p.Path, sub),
			ProcessID:   proc.ID,
			EventIDs:    []string{evt.EventID},
		})
	}
	return findings, miss.err
}
