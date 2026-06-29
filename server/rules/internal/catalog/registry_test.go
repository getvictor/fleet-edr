package catalog

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// spec:server-detection-rules-engine/registered-rule-catalog/the-engine-reports-its-rule-catalog
//
// TestAll_RegisterEveryShippedRule pins down the registration order + size of the registry, so a new rule cannot land without
// explicitly being added here. The slice this returns is the single source of truth used by the production server's main.go and the
// docs generator (tools/gen-rule-docs); a silent drift between the two would mean operators see a different surface than the ATT&CK
// coverage promises. The spec scenario "the engine reports its rule catalog" is satisfied by this test because it asserts the exact
// ID list the spec enumerates. Note the spec lists the 9 catalog rules (suspicious_exec, shell_from_office, ..., dns_c2_beacon); the
// registry also includes application_control_block which is operator-policy-driven, not part of the spec-named catalog set.
func TestAll_RegisterEveryShippedRule(t *testing.T) {
	t.Parallel()
	got := New(nil)
	wantIDs := []string{
		"suspicious_exec",
		"persistence_launchagent",
		"dyld_insert",
		"shell_from_office",
		"osascript_network_exec",
		"credential_keychain_dump",
		"privilege_launchd_plist_write",
		"sudoers_tamper",
		"application_control_block",
		"dns_c2_beacon",
	}
	require.Len(t, got, len(wantIDs))
	for i, want := range wantIDs {
		assert.Equal(t, want, got[i].ID(), "rule at index %d", i)
	}
}

// spec:server-admin-surface/per-rule-documentation-endpoint/rule-with-config-knobs
//
// For every shipped rule that declares operator-tunable config knobs, the doc.Config entries MUST each
// carry env_var, type, default, and description. ConfigKnob.Default (server/rules/api/types.go) can
// legitimately be the empty string for "feature off until configured", so the loop below asserts only
// that env_var, type, and description are non-empty plus that the Default field is reachable. A regression
// that removed the Default field from the JSON shape would break compilation here rather than landing as
// silent contract drift in the operator UI.
//
// TestAll_DocStructIsPopulated walks every shipped rule's Doc() and locks in the operator-facing invariants. Drives coverage of each
// rule's Doc() body from the rules package itself so SonarCloud's Go coverage profile attributes the lines correctly (cross-package
// coverage isn't aggregated under the project's current `-coverprofile` setup). Same checks as the gate in tools/gen-rule-docs,
// repeated here so a future tool can be deleted without losing the contract.
func TestAll_DocStructIsPopulated(t *testing.T) {
	t.Parallel()
	allowedSeverities := map[string]struct{}{
		api.SeverityLow:      {},
		api.SeverityMedium:   {},
		api.SeverityHigh:     {},
		api.SeverityCritical: {},
	}
	for _, r := range New(nil) {
		t.Run(r.ID(), func(t *testing.T) {
			t.Parallel()
			d := r.Doc()
			assert.NotEmpty(t, d.Title, "Title must be set for %s", r.ID())
			assert.NotEmpty(t, d.Summary, "Summary must be set for %s", r.ID())
			assert.NotEmpty(t, d.Description, "Description must be set for %s", r.ID())
			assert.Contains(t, allowedSeverities, d.Severity,
				"%s declares severity %q; expected one of the SeverityLow|Medium|High|Critical constants",
				r.ID(), d.Severity)
			assert.NotEmpty(t, d.EventTypes, "EventTypes must list at least one type for %s", r.ID())
			for _, c := range d.Config {
				assert.NotEmpty(t, c.EnvVar, "%s config knob missing EnvVar", r.ID())
				assert.NotEmpty(t, c.Type, "%s config knob %s missing Type", r.ID(), c.EnvVar)
				assert.NotEmpty(t, c.Description, "%s config knob %s missing Description", r.ID(), c.EnvVar)
				// Default is allowed to be the empty string (feature off until configured); the field
				// must exist on the struct so the JSON shape advertises the knob's default to operators.
				// _ = is a compile-time reference, not a runtime assertion.
				_ = c.Default
			}
		})
	}
}

// spec:server-detection-rules-engine/canonical-rule-naming/a-rule-names-itself-the-same-way-everywhere
//
// TestAll_CanonicalDisplayName is the structural guard against the three-names-for-one-detection drift issue #519 fixed. It pins the
// single-source-of-truth invariant for every shipped rule: Doc().Title (docs, /api/rules, UI) MUST equal DisplayName(), so the doc
// surface can never silently diverge from the canonical name again. It also enforces that the canonical name is a clean human-readable
// label, not the old "<name> (parenthetical implementation detail)" form whose detail belongs in Summary. The finding-title half of the
// invariant (Finding.Title == DisplayName) is enforced for fixture-replayed rules by server/detection/testkit Replay and by each
// rule's positive-detection test; application_control_block is the one exemption (per-block computed title + app_control:<n> RuleID).
func TestAll_CanonicalDisplayName(t *testing.T) {
	t.Parallel()
	for _, r := range New(nil) {
		t.Run(r.ID(), func(t *testing.T) {
			t.Parallel()
			name := r.DisplayName()
			assert.NotEmpty(t, name, "DisplayName must be set for %s", r.ID())
			assert.Equal(t, name, r.Doc().Title,
				"%s: Doc().Title must equal DisplayName() so the docs and the alert name the rule one way", r.ID())
			assert.NotContains(t, name, "(",
				"%s DisplayName %q carries a parenthetical; the implementation detail belongs in Summary, the title stays a clean name",
				r.ID(), name)
			assert.Equal(t, strings.TrimSpace(name), name, "%s DisplayName must not carry leading/trailing whitespace", r.ID())
		})
	}
}

// TestAll_ThreadsExclusionResolver confirms that the four exclusion-aware rules actually thread the supplied resolver onto their
// Exclusions field. Without this, a refactor of New could silently drop the wiring and every fleet would suddenly see the alerts they
// thought they'd silenced. The other rules don't consult exclusions, so they have no Exclusions field to check.
func TestAll_ThreadsExclusionResolver(t *testing.T) {
	t.Parallel()
	res := &fakeExclusions{}
	byID := map[string]api.Rule{}
	for _, r := range New(res) {
		byID[r.ID()] = r
	}
	assert.Same(t, res, byID["suspicious_exec"].(*SuspiciousExec).Exclusions)
	assert.Same(t, res, byID["persistence_launchagent"].(*PersistenceLaunchAgent).Exclusions)
	assert.Same(t, res, byID["privilege_launchd_plist_write"].(*PrivilegeLaunchdPlistWrite).Exclusions)
	assert.Same(t, res, byID["sudoers_tamper"].(*SudoersTamper).Exclusions)
}
