package catalog

import (
	"context"
	"fmt"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
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

// Evaluate runs the rule with a scope of its own, which is the un-shared behaviour a direct caller gets. The engine calls
// EvaluateScoped instead, so the batch's Sigma-backed rules share one decode per event.
func (r *CredentialKeychainDump) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// EvaluateScoped implements api.ScopedRule.
func (r *CredentialKeychainDump) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	var findings []api.Finding
	var miss pendingMiss
	for _, evt := range events {
		if evt.EventType != "exec" {
			continue
		}
		// Decoded once for the whole batch and shared with every other Sigma-backed rule in it, which is what issue #794 was
		// about: this used to cost a decode per rule, and again a second decode per rule to read the pid back out.
		//
		// A payload that does not decode is a malformed event rather than an uninteresting one, but one bad event must not
		// discard the findings the rest of the batch produced, so it is skipped.
		view := sigmaEvent(ctx, scope, evt, s)
		if view == nil {
			continue
		}
		se := view.Event
		if !keychainDetection().Matches(se) {
			continue
		}
		// The subcommand the detection matched on, read back from the same computed field, so the alert names what fired.
		sub := ""
		if values, ok := se.Field("Subcommand"); ok && len(values) > 0 {
			sub = values[0]
		}

		proc, err := view.Subject()
		if fatal := miss.absorb(err); fatal != nil {
			return nil, fatal
		}
		if proc == nil {
			// The exec's own row never materialized within the grace window (a young miss raises the retryable
			// ErrProcessNotYetMaterialized instead), so there is no process_id to link the finding to.
			continue
		}

		findings = append(findings, api.Finding{
			HostID:   evt.HostID,
			RuleID:   r.ID(),
			Severity: api.SeverityHigh,
			Title:    r.DisplayName(),
			Description: fmt.Sprintf("%s invoked with %q: reads all Keychain entries (Keychain credential access, MITRE T1555.001)",
				firstField(se, "Image"), sub),
			ProcessID: proc.ID,
			EventIDs:  []string{evt.EventID},
		})
	}
	return findings, miss.err
}
