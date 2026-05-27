package catalog

import (
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
// ID list the spec enumerates. Note the spec lists the 8 catalog rules (suspicious_exec, shell_from_office, ...); the registry also
// includes application_control_block which is operator-policy-driven, not part of the spec-named catalog set.
func TestAll_RegisterEveryShippedRule(t *testing.T) {
	t.Parallel()
	got := New(api.RegistryOptions{})
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
	for _, r := range New(api.RegistryOptions{}) {
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

// spec:server-detection-rules-engine/operator-toggling-of-individual-rules/an-operator-disables-a-noisy-rule-for-their-environment
//
// TestAll_DisabledRuleIDsFiltered pins the boot-time disable contract from #238 at the catalog boundary: a rule_id listed in
// DisabledRuleIDs is gone from the returned slice, so neither the engine (via service.New(rules, ...)) nor the operator-facing
// catalog (via Engine.Catalog()) sees it. The spec scenario "MUST NOT evaluate against any batch and MUST NOT produce alerts
// until it is re-enabled" follows by construction: a rule the engine never receives cannot fire.
func TestAll_DisabledRuleIDsFiltered(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		disable   []string
		wantGone  []string
		wantStill []string
	}{
		{
			name:     "single rule disabled is filtered",
			disable:  []string{"suspicious_exec"},
			wantGone: []string{"suspicious_exec"},
			wantStill: []string{
				"persistence_launchagent", "dyld_insert", "shell_from_office",
				"osascript_network_exec", "credential_keychain_dump",
				"privilege_launchd_plist_write", "sudoers_tamper", "application_control_block",
			},
		},
		{
			name:      "multiple rules disabled are all filtered",
			disable:   []string{"suspicious_exec", "sudoers_tamper"},
			wantGone:  []string{"suspicious_exec", "sudoers_tamper"},
			wantStill: []string{"dyld_insert", "shell_from_office"},
		},
		{
			name: "all rules disabled returns empty slice",
			disable: []string{
				"suspicious_exec", "persistence_launchagent", "dyld_insert", "shell_from_office",
				"osascript_network_exec", "credential_keychain_dump",
				"privilege_launchd_plist_write", "sudoers_tamper", "application_control_block",
			},
			wantGone:  []string{"suspicious_exec", "application_control_block"},
			wantStill: nil,
		},
		{
			name:      "unknown id in disable list leaves the catalog untouched",
			disable:   []string{"not-a-real-rule"},
			wantGone:  nil,
			wantStill: []string{"suspicious_exec", "application_control_block"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := New(api.RegistryOptions{DisabledRuleIDs: tc.disable})
			gotIDs := make(map[string]struct{}, len(got))
			for _, r := range got {
				gotIDs[r.ID()] = struct{}{}
			}
			for _, id := range tc.wantGone {
				_, present := gotIDs[id]
				assert.False(t, present, "rule %s must be filtered when listed in DisabledRuleIDs", id)
			}
			for _, id := range tc.wantStill {
				_, present := gotIDs[id]
				assert.True(t, present, "rule %s must remain when not in DisabledRuleIDs", id)
			}
		})
	}
}

// TestUnknownDisabledIDs covers the diagnostic helper bootstrap.New uses to warn at boot when EDR_DISABLED_RULES references a
// rule that doesn't exist. Per #238 design notes, a stale operator config (typo or rule has been removed) MUST warn but NOT
// fail the boot; that policy lives in bootstrap.New, and this test pins the inputs/outputs the warn loop relies on.
func TestUnknownDisabledIDs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty list returns nil", nil, nil},
		{"all known ids returns nil", []string{"suspicious_exec", "sudoers_tamper"}, nil},
		{"single unknown id returned", []string{"not-a-real-rule"}, []string{"not-a-real-rule"}},
		{
			"mix of known + unknown returns only unknown",
			[]string{"suspicious_exec", "typo-rule", "another-typo"},
			[]string{"typo-rule", "another-typo"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := UnknownDisabledIDs(api.RegistryOptions{DisabledRuleIDs: tc.in})
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestAll_AppliesAllowlists confirms that the four configurable rules actually thread the supplied allowlists through onto the rule
// struct. Without this, a refactor of `All` could silently drop the maps and every fleet would suddenly see the alerts they thought
// they'd silenced. We only check the rules that have a configurable allowlist; the others have empty Doc().Config.
func TestAll_AppliesAllowlists(t *testing.T) {
	t.Parallel()
	susParents := map[string]struct{}{"/usr/libexec/sshd-session": {}}
	plists := map[string]struct{}{"/Library/LaunchAgents/com.example.foo.plist": {}}
	teamIDs := map[string]struct{}{"8VBZ3948LU": {}}
	writers := map[string]struct{}{"/usr/local/bin/ansible": {}}
	rs := New(api.RegistryOptions{
		SuspiciousExecParentAllowlist: susParents,
		LaunchAgentAllowlist:          plists,
		LaunchDaemonTeamIDAllowlist:   teamIDs,
		SudoersWriterAllowlist:        writers,
	})
	byID := map[string]api.Rule{}
	for _, r := range rs {
		byID[r.ID()] = r
	}
	assert.Equal(t, susParents, byID["suspicious_exec"].(*SuspiciousExec).AllowedNonShellParents)
	assert.Equal(t, plists, byID["persistence_launchagent"].(*PersistenceLaunchAgent).AllowedPlists)
	assert.Equal(t, teamIDs, byID["privilege_launchd_plist_write"].(*PrivilegeLaunchdPlistWrite).AllowedTeamIDs)
	assert.Equal(t, writers, byID["sudoers_tamper"].(*SudoersTamper).AllowedWriters)
}
