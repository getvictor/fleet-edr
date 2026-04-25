package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/detection/testharness"
)

// TestPrivilegeLaunchdPlistWrite_Fixtures runs every fixture case under
// fixtures/privilege_launchd_plist_write/ as its own sub-test. Add a new
// case by dropping a *.json file in that directory — no Go edits needed.
func TestPrivilegeLaunchdPlistWrite_Fixtures(t *testing.T) {
	r := &PrivilegeLaunchdPlistWrite{
		AllowedTeamIDs: map[string]struct{}{
			// Synthetic team ID used by the allowlist fixture.
			"FIXTURE-ALLOW": {},
		},
	}
	testharness.Replay(t, r, "fixtures/privilege_launchd_plist_write")
}

// TestPrivilegeLaunchdPlistWrite_TechniquesMapping pins the MITRE ATT&CK
// mapping the rule reports.
func TestPrivilegeLaunchdPlistWrite_TechniquesMapping(t *testing.T) {
	r := &PrivilegeLaunchdPlistWrite{}
	assert.Equal(t, []string{"T1543.004"}, r.Techniques())
}
