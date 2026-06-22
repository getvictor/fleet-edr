package api_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/rules/api"
)

func TestMatchExclusionValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		matchType api.ExclusionMatchType
		entry     string
		candidate string
		want      bool
	}{
		{"path glob crosses separators", api.ExclusionMatchPathGlob, "*/claude/versions/*", "/Users/d/claude/versions/2/claude", true},
		{"path glob literal exact", api.ExclusionMatchPathGlob, "/usr/libexec/sshd-session", "/usr/libexec/sshd-session", true},
		{"parent path glob non-match", api.ExclusionMatchParentPathGlob, "*/lefthook_*", "/usr/bin/python3", false},
		{"team id exact", api.ExclusionMatchTeamID, "EQHXZ8M8AV", "EQHXZ8M8AV", true},
		{"team id mismatch", api.ExclusionMatchTeamID, "EQHXZ8M8AV", "OTHER", false},
		{"command substring", api.ExclusionMatchCommandSubstring, "--allow-net", "node --allow-net app.js", true},
		{"command substring empty entry never matches", api.ExclusionMatchCommandSubstring, "", "anything", false},
		{"domain exact", api.ExclusionMatchDomain, "example.com", "example.com", true},
		{"domain is case-insensitive", api.ExclusionMatchDomain, "example.com", "Example.COM", true},
		{"domain ignores trailing dot", api.ExclusionMatchDomain, "example.com", "example.com.", true},
		{"domain matches subdomain", api.ExclusionMatchDomain, "example.com", "api.example.com", true},
		{"domain does not match suffix-only", api.ExclusionMatchDomain, "example.com", "notexample.com", false},
		{"cdhash exact", api.ExclusionMatchCDHash, "abc123", "abc123", true},
		{"unknown match type never matches", api.ExclusionMatchType("bogus"), "x", "x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, api.MatchExclusionValue(tc.matchType, tc.entry, tc.candidate))
		})
	}
}

func TestDetectionRuleModeAndMatchTypeValidators(t *testing.T) {
	t.Parallel()
	assert.True(t, api.IsValidDetectionRuleMode(api.DetectionRuleModeMonitor))
	assert.False(t, api.IsValidDetectionRuleMode("paused"))
	assert.True(t, api.IsValidExclusionMatchType(api.ExclusionMatchTeamID))
	assert.False(t, api.IsValidExclusionMatchType("ip"))
}
