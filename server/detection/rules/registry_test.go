package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection"
)

// TestAll_RegisterEveryShippedRule pins down the registration order + size of
// the registry, so a new rule cannot land without explicitly being added here.
// The slice this returns is the single source of truth used by the production
// server's main.go and the docs generator (tools/gen-rule-docs); a silent
// drift between the two would mean operators see a different surface than
// the ATT&CK coverage promises.
func TestAll_RegisterEveryShippedRule(t *testing.T) {
	got := All(RegistryOptions{})
	wantIDs := []string{
		"suspicious_exec",
		"persistence_launchagent",
		"dyld_insert",
		"shell_from_office",
		"osascript_network_exec",
		"credential_keychain_dump",
		"privilege_launchd_plist_write",
		"sudoers_tamper",
	}
	require.Len(t, got, len(wantIDs))
	for i, want := range wantIDs {
		assert.Equal(t, want, got[i].ID(), "rule at index %d", i)
	}
}

// TestAll_DocStructIsPopulated walks every shipped rule's Doc() and locks in
// the operator-facing invariants. Drives coverage of each rule's Doc() body
// from the rules package itself so SonarCloud's Go coverage profile attributes
// the lines correctly (cross-package coverage isn't aggregated under the
// project's current `-coverprofile` setup). Same checks as the gate in
// tools/gen-rule-docs, repeated here so a future tool can be deleted without
// losing the contract.
func TestAll_DocStructIsPopulated(t *testing.T) {
	allowedSeverities := map[string]struct{}{
		detection.SeverityLow:      {},
		detection.SeverityMedium:   {},
		detection.SeverityHigh:     {},
		detection.SeverityCritical: {},
	}
	for _, r := range All(RegistryOptions{}) {
		t.Run(r.ID(), func(t *testing.T) {
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
			}
		})
	}
}

// TestAll_AppliesAllowlists confirms that the four configurable rules actually
// thread the supplied allowlists through onto the rule struct. Without this,
// a refactor of `All` could silently drop the maps and every fleet would
// suddenly see the alerts they thought they'd silenced. We only check the
// rules that have a configurable allowlist; the others have empty Doc().Config.
func TestAll_AppliesAllowlists(t *testing.T) {
	susParents := map[string]struct{}{"/usr/libexec/sshd-session": {}}
	plists := map[string]struct{}{"/Library/LaunchAgents/com.example.foo.plist": {}}
	teamIDs := map[string]struct{}{"8VBZ3948LU": {}}
	writers := map[string]struct{}{"/usr/local/bin/ansible": {}}
	rs := All(RegistryOptions{
		SuspiciousExecParentAllowlist: susParents,
		LaunchAgentAllowlist:          plists,
		LaunchDaemonTeamIDAllowlist:   teamIDs,
		SudoersWriterAllowlist:        writers,
	})
	byID := map[string]detection.Rule{}
	for _, r := range rs {
		byID[r.ID()] = r
	}
	assert.Equal(t, susParents, byID["suspicious_exec"].(*SuspiciousExec).AllowedNonShellParents)
	assert.Equal(t, plists, byID["persistence_launchagent"].(*PersistenceLaunchAgent).AllowedPlists)
	assert.Equal(t, teamIDs, byID["privilege_launchd_plist_write"].(*PrivilegeLaunchdPlistWrite).AllowedTeamIDs)
	assert.Equal(t, writers, byID["sudoers_tamper"].(*SudoersTamper).AllowedWriters)
}
